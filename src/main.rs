//! `lan-scan` — discover and identify services on the local network.
//!
//! Passive fingerprints only: TCP connect, read a bounded response, never
//! send credentials. Subnets are clamped to /24s.

mod find;
mod probe;
mod rules;

use probe::{probe, Finding, Plan, DEFAULT_PORTS};
use rules::Rule;
use std::env;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const USAGE: &str = "\
lan-scan — discover and identify services on the local network

USAGE:
    lan-scan [OPTIONS]
    lan-scan rules list|dir|install FILE [--name NAME]|remove NAME

OPTIONS:
    --subnet=192.168.1     probe this /24 (repeatable); default: local /24s
    --include=IP           also probe this address, outside any /24 (repeatable,
                           comma-separated; e.g. a USB gadget address)
    --ports=22,80,...      ports to fingerprint; default: 22,80,443,445,5001,8080
                           plus the ports of active rules
    --rules=FILE           add a rule file (repeatable); `-` reads stdin.
                           Explicit --rules replaces the installed rules.d
    --profile=NAME         activate only rules tagged NAME (`all` = every rule;
                           untagged rules always run)
    --no-rules             ignore installed rules; do a plain generic scan
    --filter=KIND          only print findings whose kind contains KIND
    --timeout=MS           connect+read timeout per probe (default 1500)
    --workers=N            parallel probes (default 128)
    --json                 emit the findings as a JSON array
    --jsonl                emit one JSON object per line (same schema)
    --version              print the version
    --help                 print this text

KINDS (generic, without rules):
    ssh        TCP answered with an SSH- banner (gate line kept as evidence)
    http       HTTP server (status · Server · title)
    dangbei-tv HTTP/5001 serving Dangbei Market's remote-push page
    https      TCP/443 open (not inspected)
    smb        TCP/445 open
    tcp        other port answered

RULES:
    Files in ~/.config/lan-scan/rules.d/*.conf (schema 1) declare a device
    kind, its ports/hosts and the passive evidence that must match, e.g.

        schema = 1
        kind   = lab-device
        ports  = 22
        match  = ssh.gate == unlocked
        match  = ssh.banner ~ dropbear

    Rules are data only: no commands, no credentials. `rules install` copies a
    validated file into rules.d, `rules remove` deletes it by name, and
    `rules list` shows what is installed. A matching rule replaces the generic
    kind in the output; `confidence` is its declared value (or `definitive`
    when matchers exist, `candidate` for port-open rules).

EXAMPLES:
    lan-scan
    lan-scan --filter dangbei
    lan-scan --subnet=192.168.1 --ports=5001,22 --json
    lan-scan --profile=lab --include=192.0.2.9
    lan-scan --rules=tv.conf --jsonl
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("lan-scan: {err}");
            eprintln!("try `lan-scan --help`");
            ExitCode::from(2)
        }
    }
}

struct Config {
    subnets: Vec<String>,
    includes: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    ports_explicit: bool,
    filter: String,
    timeout: Duration,
    workers: usize,
    json: bool,
    jsonl: bool,
    no_rules: bool,
    rule_files: Vec<String>,
    profiles: Vec<String>,
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    if args.first().map(String::as_str) == Some("rules") {
        return run_rules(&args[1..]);
    }

    let mut cfg = Config {
        subnets: Vec::new(),
        includes: Vec::new(),
        ports: DEFAULT_PORTS.to_vec(),
        ports_explicit: false,
        filter: String::new(),
        timeout: Duration::from_millis(1500),
        workers: 128,
        json: false,
        jsonl: false,
        no_rules: false,
        rule_files: Vec::new(),
        profiles: Vec::new(),
    };

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let (name, inline_value) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let mut take_value = |name: &str| -> Result<String, String> {
            match inline_value.clone() {
                Some(v) => Ok(v),
                None => it
                    .next()
                    .ok_or_else(|| format!("{name} needs a value"))
                    .cloned(),
            }
        };
        match name.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "--version" | "-V" => {
                println!("lan-scan {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "--subnet" => cfg.subnets.push(take_value("--subnet")?),
            "--include" => {
                for piece in take_value("--include")?.split(',') {
                    let ip: Ipv4Addr = piece
                        .trim()
                        .parse()
                        .map_err(|_| format!("bad include address {piece:?}"))?;
                    cfg.includes.push(ip);
                }
            }
            "--ports" => {
                let raw = take_value("--ports")?;
                let mut ports = Vec::new();
                for piece in raw.split(',') {
                    let port: u16 = piece
                        .trim()
                        .parse()
                        .map_err(|_| format!("bad port {piece:?}"))?;
                    if port == 0 {
                        return Err(format!("bad port {piece:?}"));
                    }
                    ports.push(port);
                }
                if ports.is_empty() {
                    return Err("--ports needs at least one port".into());
                }
                ports.sort_unstable();
                ports.dedup();
                cfg.ports = ports;
                cfg.ports_explicit = true;
            }
            "--rules" => cfg.rule_files.push(take_value("--rules")?),
            "--profile" => {
                cfg.profiles.extend(
                    take_value("--profile")?
                        .split(',')
                        .map(|p| p.trim().to_owned()),
                );
            }
            "--no-rules" => cfg.no_rules = true,
            "--filter" => cfg.filter = take_value("--filter")?.to_lowercase(),
            "--timeout" => {
                let ms: u64 = take_value("--timeout")?
                    .parse()
                    .map_err(|_| "--timeout needs milliseconds".to_string())?;
                if ms == 0 {
                    return Err("--timeout must be > 0".into());
                }
                cfg.timeout = Duration::from_millis(ms);
            }
            "--workers" => {
                let n: usize = take_value("--workers")?
                    .parse()
                    .map_err(|_| "--workers needs a number".to_string())?;
                if n == 0 {
                    return Err("--workers must be > 0".into());
                }
                cfg.workers = n;
            }
            "--json" => cfg.json = true,
            "--jsonl" => cfg.jsonl = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    if cfg.json && cfg.jsonl {
        return Err("--json and --jsonl are mutually exclusive".into());
    }

    let loaded = load_rules(&cfg)?;
    let active = rules::active(&loaded, &cfg.profiles);

    if !cfg.ports_explicit {
        for rule in &active {
            cfg.ports.extend(rule.ports.iter().copied());
        }
        cfg.ports.sort_unstable();
        cfg.ports.dedup();
    }

    let mut prefixes = find::effective_prefixes(&cfg.subnets);
    prefixes.sort();
    prefixes.dedup();

    let mut hosts: Vec<Ipv4Addr> = cfg.includes.clone();
    for prefix in &prefixes {
        hosts.extend(find::hosts_in(*prefix));
    }
    for rule in &active {
        hosts.extend(rule.hosts.iter().copied());
    }
    hosts.sort_unstable();
    hosts.dedup();

    if hosts.is_empty() {
        return Err("no local IPv4 network found; pass --subnet or --include".into());
    }

    let plans = port_plans(&cfg.ports, &active);
    let mut tasks: Vec<(Ipv4Addr, u16, Plan)> = Vec::new();
    for ip in hosts {
        for (port, plan) in &plans {
            tasks.push((ip, *port, *plan));
        }
    }

    let findings = scan(&tasks, cfg.workers, cfg.timeout);
    let findings = apply_rules(findings, &active);
    let findings = filter_findings(findings, &cfg.filter);

    if cfg.json {
        print!("{}", to_json(&findings));
    } else if cfg.jsonl {
        print!("{}", to_jsonl(&findings));
    } else if findings.is_empty() {
        eprintln!("lan-scan: nothing found on the local network(s)");
        return Ok(ExitCode::from(1));
    } else {
        for f in &findings {
            println!("{:<15} {:<5} {:<12} {}", f.ip, f.port, f.kind, f.detail);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Rules from `--rules` files, or the installed rules.d, unless `--no-rules`.
fn load_rules(cfg: &Config) -> Result<Vec<Rule>, String> {
    if cfg.no_rules {
        return Ok(Vec::new());
    }
    if !cfg.rule_files.is_empty() {
        let mut out = Vec::new();
        for file in &cfg.rule_files {
            if file == "-" {
                out.push(rules::load_stdin()?);
            } else {
                out.push(rules::load_file(Path::new(file))?);
            }
        }
        return Ok(out);
    }
    match rules::dir() {
        Some(directory) => rules::load_dir(&directory),
        None => Ok(Vec::new()),
    }
}

/// The protocols worth trying on each port: the port's own default plus any
/// matcher an active rule asks for.
fn port_plans(ports: &[u16], active: &[&Rule]) -> Vec<(u16, Plan)> {
    ports
        .iter()
        .map(|&port| {
            let mut plan = Plan::default_for(port);
            for rule in active {
                if !rule.covers_port(port) {
                    continue;
                }
                for matcher in &rule.matchers {
                    if matcher.field.needs_ssh() {
                        plan.ssh = true;
                    } else {
                        plan.http = true;
                    }
                }
            }
            (port, plan)
        })
        .collect()
}

/// Fan the probe list out over worker threads, collect findings, sort by
/// address then port.
fn scan(tasks: &[(Ipv4Addr, u16, Plan)], workers: usize, timeout: Duration) -> Vec<Finding> {
    let next = AtomicUsize::new(0);
    let found: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let n = workers.min(tasks.len()).max(1);

    std::thread::scope(|scope| {
        for _ in 0..n {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= tasks.len() {
                    break;
                }
                let (ip, port, plan) = tasks[index];
                if let Some(finding) = probe(ip, port, plan, timeout, timeout) {
                    found.lock().unwrap().push(finding);
                }
            });
        }
    });

    let mut findings = found.into_inner().unwrap_or_default();
    sort_findings(&mut findings);
    findings
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.rule.cmp(&b.rule))
    });
}

/// Replace the generic kind with a rule's kind wherever a rule matches. One
/// finding may satisfy several rules; each gets its own labelled entry.
fn apply_rules(findings: Vec<Finding>, active: &[&Rule]) -> Vec<Finding> {
    let mut out = Vec::new();
    for finding in findings {
        let mut claimed = false;
        for rule in active {
            if !rule.matches(finding.port, &finding.evidence) {
                continue;
            }
            claimed = true;
            let mut labelled = finding.clone();
            labelled.kind = rule.kind.clone();
            labelled.rule = Some(rule.source.clone());
            labelled.label = (!rule.label.is_empty()).then(|| rule.label.clone());
            labelled.confidence = Some(rule.confidence.clone());
            out.push(labelled);
        }
        if !claimed {
            out.push(finding);
        }
    }
    sort_findings(&mut out);
    out
}

fn filter_findings(findings: Vec<Finding>, filter: &str) -> Vec<Finding> {
    if filter.is_empty() {
        return findings;
    }
    findings
        .into_iter()
        .filter(|f| f.kind.to_lowercase().contains(filter))
        .collect()
}

/// Hand-rolled JSON (keeps the dependency list at just if-addrs).
fn to_json(findings: &[Finding]) -> String {
    let mut out = String::from("[\n");
    for f in findings {
        out.push_str("  ");
        out.push_str(&finding_json(f));
        out.push_str(",\n");
    }
    if !findings.is_empty() {
        out.truncate(out.len() - 2); // drop trailing ",\n"
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

/// One object per line, same schema as [`to_json`].
fn to_jsonl(findings: &[Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        out.push_str(&finding_json(f));
        out.push('\n');
    }
    out
}

fn finding_json(f: &Finding) -> String {
    let mut out = format!(
        "{{\"schema\": {}, \"ip\": {}, \"port\": {}, \"kind\": {}, \"detail\": {}",
        rules::SCHEMA,
        json_string(&f.ip.to_string()),
        f.port,
        json_string(&f.kind),
        json_string(&f.detail)
    );
    if let Some(rule) = &f.rule {
        out.push_str(&format!(", \"rule\": {}", json_string(rule)));
    }
    if let Some(label) = &f.label {
        out.push_str(&format!(", \"label\": {}", json_string(label)));
    }
    if let Some(confidence) = &f.confidence {
        out.push_str(&format!(", \"confidence\": {}", json_string(confidence)));
    }
    let evidence = evidence_json(&f.evidence);
    if !evidence.is_empty() {
        out.push_str(&format!(", \"evidence\": {evidence}"));
    }
    out.push('}');
    out
}

/// Evidence is what a human would want to read: banners and HTTP headers.
/// The response body is deliberately not included (matching only).
fn evidence_json(evidence: &probe::Evidence) -> String {
    let mut fields: Vec<String> = Vec::new();
    for (key, value) in [
        ("gate", evidence.gate.as_deref()),
        ("banner", evidence.banner.as_deref()),
        ("status", evidence.status.as_deref()),
        ("server", evidence.server.as_deref()),
        ("title", evidence.title.as_deref()),
    ] {
        if let Some(value) = value {
            fields.push(format!("\"{key}\": {}", json_string(value)));
        }
    }
    if fields.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", fields.join(", "))
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// rules management
// ---------------------------------------------------------------------------

fn run_rules(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let directory =
                rules::dir().ok_or_else(|| "cannot determine the config directory".to_owned())?;
            let installed = rules::load_dir(&directory)?;
            if installed.is_empty() {
                println!("no rules installed in {}", directory.display());
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "{:<16} {:<16} {:<8} {:<12} label",
                "name", "kind", "ports", "profiles"
            );
            for rule in &installed {
                let ports = if rule.ports.is_empty() {
                    "any".to_owned()
                } else {
                    rule.ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let profiles = if rule.profiles.is_empty() {
                    "any".to_owned()
                } else {
                    rule.profiles.join(",")
                };
                println!(
                    "{:<16} {:<16} {:<8} {:<12} {}",
                    rule.source, rule.kind, ports, profiles, rule.label
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Some("dir") => {
            let directory =
                rules::dir().ok_or_else(|| "cannot determine the config directory".to_owned())?;
            println!("{}", directory.display());
            Ok(ExitCode::SUCCESS)
        }
        Some("install") => {
            let mut file: Option<&str> = None;
            let mut name: Option<&str> = None;
            let mut it = args[1..].iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--name" => {
                        name = Some(
                            it.next()
                                .ok_or_else(|| "--name needs a value".to_owned())?
                                .as_str(),
                        )
                    }
                    other => {
                        if file.is_some() {
                            return Err(format!("unexpected argument {other:?}"));
                        }
                        file = Some(other);
                    }
                }
            }
            let file = file.ok_or_else(|| "rules install needs a FILE".to_owned())?;
            let installed = rules::install(Path::new(file), name)?;
            println!("installed {}", installed.display());
            Ok(ExitCode::SUCCESS)
        }
        Some("remove") => {
            let name = args
                .get(1)
                .ok_or_else(|| "rules remove needs a NAME".to_owned())?;
            if args.len() > 2 {
                return Err(format!("unexpected argument {:?}", args[2]));
            }
            let removed = rules::remove(name)?;
            println!("removed {}", removed.display());
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!(
            "unknown rules command {other:?} (known: list, dir, install, remove)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe::Evidence;

    fn finding(kind: &str, port: u16, evidence: Evidence) -> Finding {
        Finding {
            ip: Ipv4Addr::new(192, 0, 2, 9),
            port,
            kind: kind.to_owned(),
            detail: evidence.detail(),
            evidence,
            rule: None,
            label: None,
            confidence: None,
        }
    }

    #[test]
    fn rule_evidence_forces_the_ssh_probe_on_any_port() {
        let rule = rules::parse(
            "schema = 1\nkind = tv\nports = 2222\nmatch = ssh.banner ~ SimpleSSHD\n",
            "tv",
        )
        .unwrap();
        let active = vec![&rule];
        let plans = port_plans(&[22, 2222, 5555], &active);
        assert!(plans.iter().any(|(port, plan)| *port == 22 && plan.ssh));
        // 2222 is not an SSH port by default; the rule makes it one.
        assert!(plans.iter().any(|(port, plan)| *port == 2222 && plan.ssh));
        // A plain port keeps its default plan.
        assert!(plans
            .iter()
            .any(|(port, plan)| *port == 5555 && !plan.ssh && !plan.http));
    }

    #[test]
    fn matching_rules_relabel_the_finding() {
        let rule = rules::parse(
            "schema = 1\nkind = lab-device\nlabel = Lab device\nports = 22\nmatch = ssh.gate == unlocked\nmatch = ssh.banner ~ dropbear\nconfidence = definitive\n",
            "lab-device",
        )
        .unwrap();
        let active = vec![&rule];
        let findings = vec![finding(
            "ssh",
            22,
            Evidence {
                gate: Some("unlocked".to_owned()),
                banner: Some("SSH-2.0-dropbear_2024.81".to_owned()),
                ..Evidence::default()
            },
        )];
        let out = apply_rules(findings, &active);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "lab-device");
        assert_eq!(out[0].rule.as_deref(), Some("lab-device"));
        assert_eq!(out[0].label.as_deref(), Some("Lab device"));
        assert_eq!(out[0].confidence.as_deref(), Some("definitive"));
    }

    #[test]
    fn a_locked_gate_keeps_the_generic_kind() {
        let rule = rules::parse(
            "schema = 1\nkind = lab-device\nports = 22\nmatch = ssh.gate == unlocked\n",
            "lab-device",
        )
        .unwrap();
        let active = vec![&rule];
        let findings = vec![finding(
            "ssh",
            22,
            Evidence {
                gate: Some("locked".to_owned()),
                banner: Some("SSH-2.0-dropbear_2024.81".to_owned()),
                ..Evidence::default()
            },
        )];
        let out = apply_rules(findings, &active);
        assert_eq!(out[0].kind, "ssh");
        assert!(out[0].rule.is_none());
    }

    #[test]
    fn jsonl_is_one_object_per_line_with_evidence() {
        let findings = vec![finding(
            "ssh",
            22,
            Evidence {
                gate: Some("unlocked".to_owned()),
                banner: Some("SSH-2.0-dropbear_2024.81".to_owned()),
                ..Evidence::default()
            },
        )];
        let out = to_jsonl(&findings);
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("\"ip\": \"192.0.2.9\""), "{out}");
        assert!(
            out.contains("\"evidence\": {\"gate\": \"unlocked\""),
            "{out}"
        );
    }

    #[test]
    fn json_escapes_peer_text() {
        let value = "he said \"hi\"\\\n";
        assert_eq!(json_string(value), "\"he said \\\"hi\\\"\\\\\\n\"");
    }
}
