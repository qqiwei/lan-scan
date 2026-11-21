//! Declarative device fingerprints.
//!
//! A rule is data, never code: one file describes one device class (a `kind`)
//! by the ports it listens on and the passive evidence a probe must show.
//! Rules are read from `~/.config/lan-scan/rules.d/*.conf` (or explicit
//! `--rules` files) and can be installed by the tools that know the device.
//!
//! Format (one rule per file, `key = value`, `#` starts a comment):
//!
//! ```text
//! schema     = 1
//! kind       = lab-device
//! label      = Example lab device
//! profile    = lab
//! ports      = 22
//! hosts      = 192.0.2.9
//! match      = ssh.gate == unlocked
//! match      = ssh.banner ~ dropbear
//! confidence = definitive
//! ```
//!
//! `match` fields are `ssh.gate`, `ssh.banner`, `http.status`, `http.server`,
//! `http.title`, `http.body`; operators are `==` (exact) and `~` (contains,
//! case-insensitive). Every matcher must pass, and every port in `ports` is
//! probed (`ports` may be omitted = any port).

use crate::probe::Evidence;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    SshGate,
    SshBanner,
    HttpStatus,
    HttpServer,
    HttpTitle,
    HttpBody,
}

impl Field {
    fn parse(value: &str) -> Option<Field> {
        match value {
            "ssh.gate" => Some(Field::SshGate),
            "ssh.banner" => Some(Field::SshBanner),
            "http.status" => Some(Field::HttpStatus),
            "http.server" => Some(Field::HttpServer),
            "http.title" => Some(Field::HttpTitle),
            "http.body" => Some(Field::HttpBody),
            _ => None,
        }
    }

    pub fn needs_ssh(self) -> bool {
        matches!(self, Field::SshGate | Field::SshBanner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    pub field: Field,
    pub op: Op,
    pub value: String,
}

impl Matcher {
    fn holds(&self, evidence: &Evidence) -> bool {
        let actual = match self.field {
            Field::SshGate => evidence.gate.as_deref().unwrap_or_default(),
            Field::SshBanner => evidence.banner.as_deref().unwrap_or_default(),
            Field::HttpStatus => evidence.status.as_deref().unwrap_or_default(),
            Field::HttpServer => evidence.server.as_deref().unwrap_or_default(),
            Field::HttpTitle => evidence.title.as_deref().unwrap_or_default(),
            Field::HttpBody => evidence.body.as_deref().unwrap_or_default(),
        };
        match self.op {
            Op::Eq => actual.eq_ignore_ascii_case(&self.value),
            Op::Contains => actual.to_lowercase().contains(&self.value.to_lowercase()),
        }
    }
}

/// One device class. The fields are data only — nothing here is ever
/// executed, and no rule may carry credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Rule file stem (what `rules list` shows).
    pub source: String,
    pub kind: String,
    pub label: String,
    /// Profile tags; empty = active for every run.
    pub profiles: Vec<String>,
    /// Ports to probe; empty = any port already being probed.
    pub ports: Vec<u16>,
    /// Extra addresses this device lives on (e.g. the USB gadget).
    pub hosts: Vec<Ipv4Addr>,
    pub matchers: Vec<Matcher>,
    /// Declared strength, or derived: matchers present = `definitive`,
    /// ports open only = `candidate`.
    pub confidence: String,
}

impl Rule {
    /// Does this rule claim `port`? Ports are matched exactly; no ports means
    /// the rule follows whatever the scan already probes.
    pub fn covers_port(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }

    /// All declared evidence must be present. A rule without matchers matches
    /// any answered port in its port set.
    pub fn matches(&self, port: u16, evidence: &Evidence) -> bool {
        self.covers_port(port) && self.matchers.iter().all(|m| m.holds(evidence))
    }
}

/// Parse one rule file. Errors are prefixed with `file:line`.
pub fn parse(text: &str, source: &str) -> Result<Rule, String> {
    let mut kind: Option<String> = None;
    let mut label: Option<String> = None;
    let mut confidence: Option<String> = None;
    let mut profiles = Vec::new();
    let mut ports = Vec::new();
    let mut hosts = Vec::new();
    let mut matchers = Vec::new();
    let mut schema_seen = false;

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let text = raw.split('#').next().unwrap_or_default().trim();
        if text.is_empty() {
            continue;
        }
        let Some((key, value)) = text.split_once('=') else {
            return Err(format!(
                "{source}:{line}: expected `key = value`, got {raw:?}"
            ));
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() && key != "match" {
            return Err(format!("{source}:{line}: {key} needs a value"));
        }
        match key.as_str() {
            "schema" => {
                let parsed: u32 = value
                    .parse()
                    .map_err(|_| format!("{source}:{line}: schema must be a number"))?;
                if parsed != SCHEMA {
                    return Err(format!(
                        "{source}:{line}: unsupported schema {parsed} (lan-scan understands {SCHEMA})"
                    ));
                }
                schema_seen = true;
            }
            "kind" => {
                if kind.is_some() {
                    return Err(format!("{source}:{line}: kind is set twice"));
                }
                if value.contains(char::is_whitespace) {
                    return Err(format!("{source}:{line}: kind must not contain whitespace"));
                }
                kind = Some(value.to_owned());
            }
            "label" => label = Some(value.to_owned()),
            "profile" => profiles.extend(comma(value)),
            "ports" => {
                for piece in comma(value) {
                    let port: u16 = piece
                        .parse()
                        .map_err(|_| format!("{source}:{line}: bad port {piece:?}"))?;
                    if port == 0 {
                        return Err(format!("{source}:{line}: bad port {piece:?}"));
                    }
                    ports.push(port);
                }
            }
            "hosts" => {
                for piece in comma(value) {
                    let host: Ipv4Addr = piece
                        .parse()
                        .map_err(|_| format!("{source}:{line}: bad host {piece:?}"))?;
                    hosts.push(host);
                }
            }
            "match" => matchers.push(parse_matcher(value, source, line)?),
            "confidence" => confidence = Some(value.to_owned()),
            other => {
                return Err(format!(
                    "{source}:{line}: unknown key {other:?} (known: schema, kind, label, profile, ports, hosts, match, confidence)"
                ));
            }
        }
    }

    if !schema_seen {
        return Err(format!("{source}: missing `schema = {SCHEMA}`"));
    }
    let Some(kind) = kind else {
        return Err(format!("{source}: missing `kind`"));
    };
    if ports.is_empty() && matchers.is_empty() {
        return Err(format!(
            "{source}: a rule needs at least one of `ports` or `match`"
        ));
    }
    ports.sort_unstable();
    ports.dedup();
    profiles.sort();
    profiles.dedup();
    hosts.sort_unstable();
    hosts.dedup();
    let confidence = confidence.unwrap_or_else(|| {
        if matchers.is_empty() {
            "candidate".to_owned()
        } else {
            "definitive".to_owned()
        }
    });

    Ok(Rule {
        source: source.to_owned(),
        kind,
        label: label.unwrap_or_default(),
        profiles,
        ports,
        hosts,
        matchers,
        confidence,
    })
}

fn comma(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_matcher(value: &str, source: &str, line: usize) -> Result<Matcher, String> {
    let Some((field, rest)) = value.split_once(char::is_whitespace) else {
        return Err(format!(
            "{source}:{line}: match needs `field ==|~ value`, e.g. `match = ssh.gate == unlocked`"
        ));
    };
    let Some(field) = Field::parse(field.trim()) else {
        return Err(format!(
            "{source}:{line}: unknown match field {:?} (known: ssh.gate, ssh.banner, http.status, http.server, http.title, http.body)",
            field.trim()
        ));
    };
    let rest = rest.trim_start();
    let (op, value) = if let Some(rest) = rest.strip_prefix("==") {
        (Op::Eq, rest)
    } else if let Some(rest) = rest.strip_prefix('~') {
        (Op::Contains, rest)
    } else {
        return Err(format!(
            "{source}:{line}: match needs `==` or `~` after the field"
        ));
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{source}:{line}: match needs a value"));
    }
    Ok(Matcher {
        field,
        op,
        value: value.to_owned(),
    })
}

/// Read one file; the rule source is the file stem.
pub fn load_file(path: &Path) -> Result<Rule, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let source = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("rule")
        .to_owned();
    parse(&text, &source)
}

/// Read a rule from stdin (`--rules -`).
pub fn load_stdin() -> Result<Rule, String> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|err| format!("read rules from stdin: {err}"))?;
    parse(&text, "stdin")
}

/// `~/.config/lan-scan/rules.d` (or `$XDG_CONFIG_HOME/lan-scan/rules.d`).
pub fn dir() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        if !base.is_empty() {
            return Some(PathBuf::from(base).join("lan-scan").join("rules.d"));
        }
    }
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("lan-scan")
            .join("rules.d")
    })
}

/// Every `*.conf` under the rules directory, sorted by name. A missing
/// directory is not an error: rules are optional.
pub fn load_dir(directory: &Path) -> Result<Vec<Rule>, String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("read {}: {err}", directory.display())),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("conf"))
        .collect();
    paths.sort();
    paths.iter().map(|path| load_file(path)).collect()
}

/// Install a rule file into the rules directory (idempotent: a file with the
/// same name is replaced). Returns the installed path.
pub fn install(file: &Path, name: Option<&str>) -> Result<PathBuf, String> {
    let rule = load_file(file)?;
    let stem = match name {
        Some(name) => {
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains(char::is_whitespace)
            {
                return Err(format!("bad rule name {name:?}"));
            }
            trimmed.trim_end_matches(".conf").to_owned()
        }
        None => rule.source.clone(),
    };
    let directory = dir().ok_or_else(|| "cannot determine the config directory".to_owned())?;
    fs::create_dir_all(&directory)
        .map_err(|err| format!("create {}: {err}", directory.display()))?;
    let target = directory.join(format!("{stem}.conf"));
    let text = fs::read_to_string(file).map_err(|err| format!("read {}: {err}", file.display()))?;
    // Write next to the target and rename, so a concurrent scan never reads a
    // half-written rule.
    let tmp = directory.join(format!(".{stem}.conf.tmp"));
    fs::write(&tmp, text).map_err(|err| format!("write {}: {err}", tmp.display()))?;
    fs::rename(&tmp, &target).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        format!("install {}: {err}", target.display())
    })?;
    Ok(target)
}

/// Remove an installed rule by name (`lab-device` or `lab-device.conf`).
pub fn remove(name: &str) -> Result<PathBuf, String> {
    let directory = dir().ok_or_else(|| "cannot determine the config directory".to_owned())?;
    let name = name.trim();
    if name.is_empty() || name.contains('/') {
        return Err(format!("bad rule name {name:?}"));
    }
    let stem = name.trim_end_matches(".conf");
    let path = directory.join(format!("{stem}.conf"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("no installed rule named {stem:?}"))
        }
        Err(err) => Err(format!("remove {}: {err}", path.display())),
    }
}

/// Which rules a `--profile` selection activates. Rules without a profile tag
/// always run; `all` (or no selection) runs everything.
pub fn active<'a>(rules: &'a [Rule], profiles: &[String]) -> Vec<&'a Rule> {
    if profiles.is_empty() || profiles.iter().any(|p| p == "all") {
        return rules.iter().collect();
    }
    rules
        .iter()
        .filter(|rule| {
            rule.profiles.is_empty()
                || rule
                    .profiles
                    .iter()
                    .any(|tag| profiles.iter().any(|picked| picked == tag))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAB: &str = "\
schema     = 1
kind       = lab-device
label      = Example lab device
profile    = lab
ports      = 22
hosts      = 192.0.2.9
match      = ssh.gate == unlocked
match      = ssh.banner ~ dropbear
confidence = definitive
";

    fn evidence(gate: Option<&str>, banner: Option<&str>) -> Evidence {
        Evidence {
            gate: gate.map(str::to_owned),
            banner: banner.map(str::to_owned),
            ..Evidence::default()
        }
    }

    #[test]
    fn parses_a_full_rule() {
        let rule = parse(LAB, "lab-device").unwrap();
        assert_eq!(rule.kind, "lab-device");
        assert_eq!(rule.label, "Example lab device");
        assert_eq!(rule.profiles, ["lab"]);
        assert_eq!(rule.ports, [22]);
        assert_eq!(rule.hosts, [Ipv4Addr::new(192, 0, 2, 9)]);
        assert_eq!(rule.confidence, "definitive");
        assert_eq!(rule.matchers.len(), 2);
    }

    #[test]
    fn a_port_only_rule_is_a_candidate() {
        let rule = parse("schema = 1\nkind = tv\nports = 5555,2222\n", "tv").unwrap();
        assert_eq!(rule.confidence, "candidate");
        assert!(rule.matchers.is_empty());
        assert_eq!(rule.ports, [2222, 5555]);
    }

    #[test]
    fn ssh_matchers_are_and_all_must_hold() {
        let rule = parse(LAB, "lab-device").unwrap();
        let ev = evidence(Some("unlocked"), Some("SSH-2.0-dropbear_2024.81"));
        assert!(rule.matches(22, &ev));
        assert!(!rule.matches(22, &evidence(Some("locked"), ev.banner.as_deref())));
        assert!(!rule.matches(22, &evidence(Some("unlocked"), Some("SSH-2.0-OpenSSH_9.9"))));
        // The rule only covers port 22.
        assert!(!rule.matches(2222, &ev));
    }

    #[test]
    fn contains_is_case_insensitive() {
        let rule = parse(
            "schema = 1\nkind = dangbei\nports = 5001\nmatch = http.body ~ 当贝\n",
            "dangbei",
        )
        .unwrap();
        let ev = Evidence {
            body: Some("<title>当贝市场</title>".to_owned()),
            ..Evidence::default()
        };
        assert!(rule.matches(5001, &ev));
    }

    #[test]
    fn a_matcher_on_absent_evidence_never_matches() {
        let rule = parse("schema = 1\nkind = x\nmatch = ssh.gate == unlocked\n", "x").unwrap();
        assert!(!rule.matches(22, &Evidence::default()));
    }

    #[test]
    fn profiles_select_rules_but_untagged_ones_always_run() {
        let tagged = parse("schema = 1\nkind = lab\nprofile = lab\nports = 22\n", "lab").unwrap();
        let plain = parse("schema = 1\nkind = tv\nports = 5555\n", "tv").unwrap();
        let all = vec![tagged, plain];
        assert_eq!(active(&all, &[]).len(), 2);
        assert_eq!(active(&all, &["all".to_owned()]).len(), 2);
        assert_eq!(active(&all, &["tv".to_owned()]).len(), 1);
        assert_eq!(active(&all, &["tv".to_owned()])[0].kind, "tv");
    }

    #[test]
    fn rejects_unknown_and_incomplete_rules() {
        let err = parse("schema = 1\nkind = x\nports = 22\nhook = rm -rf /\n", "bad").unwrap_err();
        assert!(err.contains("unknown key"), "{err}");

        let err = parse("kind = x\nports = 22\n", "bad").unwrap_err();
        assert!(err.contains("schema"), "{err}");

        let err = parse("schema = 1\nports = 22\n", "bad").unwrap_err();
        assert!(err.contains("kind"), "{err}");

        let err = parse("schema = 1\nkind = x\n", "bad").unwrap_err();
        assert!(err.contains("ports"), "{err}");

        let err = parse("schema = 1\nkind = x\nmatch = ssh.gate = unlocked\n", "bad").unwrap_err();
        assert!(err.contains("=="), "{err}");

        let err = parse("schema = 1\nkind = x\nmatch = dns.name == x\n", "bad").unwrap_err();
        assert!(err.contains("unknown match field"), "{err}");

        let err = parse(
            "schema = 1\nkind = x\nports = 22\nhosts = 10.0.0.0/24\n",
            "bad",
        )
        .unwrap_err();
        assert!(err.contains("bad host"), "{err}");
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let rule = parse(
            "# a TV candidate\n\nschema = 1   # data only\nkind = tv\nports = 5555, 2222\n",
            "tv",
        )
        .unwrap();
        assert_eq!(rule.ports, [2222, 5555]);
    }
}
