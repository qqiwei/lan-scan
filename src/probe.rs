//! Port fingerprints. Each probe takes an open TCP stream and collects
//! passive evidence (banners, HTTP headers) that both the human-readable
//! `kind` and the declarative rules use.
//!
//! Rules are deliberately small and passive: we connect, read a bounded
//! amount, and never send credentials.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Default ports probed when `--ports` is not given.
pub const DEFAULT_PORTS: &[u16] = &[22, 80, 443, 445, 5001, 8080];

/// What a probe actually saw. Every field is optional; a field is only filled
/// when the peer volunteered it (or answered the one minimal HTTP GET).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The line a host may print before its `SSH-` banner (some devices print
    /// a secure-boot gate or other status text here).
    pub gate: Option<String>,
    /// e.g. `SSH-2.0-dropbear_2024.81`
    pub banner: Option<String>,
    pub status: Option<String>,
    pub server: Option<String>,
    pub title: Option<String>,
    /// Response body, kept for rule matching only (never printed).
    pub body: Option<String>,
}

impl Evidence {
    /// One-line summary for the text table and the JSON `detail` field.
    pub fn detail(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(gate) = &self.gate {
            parts.push(gate.clone());
        }
        if let Some(banner) = &self.banner {
            parts.push(banner.clone());
        }
        if let Some(status) = &self.status {
            parts.push(format!("HTTP {status}"));
        }
        if let Some(server) = &self.server {
            parts.push(server.clone());
        }
        if let Some(title) = &self.title {
            parts.push(title.clone());
        }
        parts.join(" · ")
    }
}

/// One identified service.
#[derive(Debug, Clone)]
pub struct Finding {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub kind: String,
    pub detail: String,
    pub evidence: Evidence,
    /// Rule source (file stem) when a rule claimed this finding.
    pub rule: Option<String>,
    /// Rule label / confidence, when a rule claimed it.
    pub label: Option<String>,
    pub confidence: Option<String>,
}

/// Which protocols to try on a port. Both can be true: connect once, read
/// first (SSH speaks first), then send the one HTTP request if nothing was
/// said. Defaults follow the port; rules can force either probe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plan {
    pub ssh: bool,
    pub http: bool,
}

impl Plan {
    /// The protocol implied by the port alone (the behaviour of older
    /// versions).
    pub fn default_for(port: u16) -> Plan {
        Plan {
            ssh: port == 22,
            http: matches!(port, 80 | 5001 | 8080),
        }
    }
}

/// Probe `ip:port`, collecting evidence and naming the most specific kind.
pub fn probe(
    ip: Ipv4Addr,
    port: u16,
    plan: Plan,
    connect: Duration,
    read: Duration,
) -> Option<Finding> {
    let addr = SocketAddr::new(ip.into(), port);
    let mut stream = TcpStream::connect_timeout(&addr, connect).ok()?;
    let _ = stream.set_read_timeout(Some(read));
    let _ = stream.set_write_timeout(Some(read));

    let mut evidence = Evidence::default();

    if plan.ssh {
        // SSH servers speak first, so read before sending anything.
        read_ssh(&mut stream, &mut evidence);
    }
    if plan.http && evidence.status.is_none() && evidence.banner.is_none() {
        // One minimal GET; the body is kept for fingerprint matching only.
        if let Some(info) = http_info(&mut stream, ip, port) {
            if !info.status.is_empty() {
                evidence.status = Some(info.status);
            }
            if !info.server.is_empty() {
                evidence.server = Some(info.server);
            }
            if !info.title.is_empty() {
                evidence.title = Some(info.title);
            }
            evidence.body = Some(info.body);
        }
    }

    let answered_http = evidence.status.is_some() || evidence.body.is_some();
    let kind = if evidence.banner.is_some() {
        "ssh".to_owned()
    } else if port == 5001 && answered_http && is_dangbei(&evidence) {
        "dangbei-tv".to_owned()
    } else if answered_http {
        "http".to_owned()
    } else if port == 443 {
        "https".to_owned()
    } else if port == 445 {
        "smb".to_owned()
    } else {
        "tcp".to_owned()
    };

    // 443 is labelled without a TLS handshake; keep the human hint.
    let detail = if port == 443 && evidence.detail().is_empty() {
        "tls (not inspected)".to_owned()
    } else {
        evidence.detail()
    };

    Some(Finding {
        ip,
        port,
        kind,
        detail,
        evidence,
        rule: None,
        label: None,
        confidence: None,
    })
}

/// Read up to three lines, keeping the pre-banner line and the `SSH-` line.
/// Port 22 alone is not enough to call a host SSH: a banner must arrive.
fn read_ssh(stream: &mut TcpStream, evidence: &mut Evidence) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    for _ in 0..3 {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let text = line.trim();
                if text.starts_with("SSH-") {
                    evidence.banner = Some(text.to_owned());
                    break;
                }
                if !text.is_empty() && evidence.gate.is_none() {
                    evidence.gate = Some(text.to_owned());
                }
            }
            Err(_) => break,
        }
    }
}

/// What a minimal HTTP GET revealed.
struct HttpInfo {
    status: String,
    server: String,
    title: String,
    body: String,
}

fn is_dangbei(evidence: &Evidence) -> bool {
    let hay = format!(
        "{} {} {}",
        evidence.title.as_deref().unwrap_or_default(),
        evidence.server.as_deref().unwrap_or_default(),
        evidence.body.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    hay.contains("当贝") || hay.contains("dangbei") || hay.contains("远程推送")
}

/// Minimal HTTP probe: GET / over HTTP/1.0, parse status, `Server:`,
/// `<title>` and keep the body (bounded) for fingerprints.
fn http_info(stream: &mut TcpStream, ip: Ipv4Addr, port: u16) -> Option<HttpInfo> {
    let request = format!("GET / HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: lan-scan\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;

    let mut buf = vec![0u8; 16384];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            break;
        }
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    if total == 0 {
        return None;
    }

    let text = String::from_utf8_lossy(&buf[..total]);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => (text.as_ref(), ""),
    };

    let status = head
        .lines()
        .next()
        .unwrap_or_default()
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_string();

    let server = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| {
            line.trim_start_matches(|c| c != ':')
                .trim_start_matches(": ")
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    let title = extract_title(body).unwrap_or_default();

    Some(HttpInfo {
        status,
        server,
        title,
        body: body.to_string(),
    })
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let content_start = lower[start..].find('>')? + start + 1;
    let content_end = lower[content_start..].find("</title>")? + content_start;
    Some(body[content_start..content_end].trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn extracts_title() {
        let html = "<html><head><TITLE>hello world</TITLE></head></html>";
        assert_eq!(extract_title(html).as_deref(), Some("hello world"));
        assert_eq!(extract_title("<html></html>"), None);
    }

    #[test]
    fn keeps_the_gate_line_before_the_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(b"unlocked\nSSH-2.0-dropbear_2024.81\r\n")
                .unwrap();
        });

        let finding = probe(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            Plan {
                ssh: true,
                http: false,
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("the fake server answers");

        assert_eq!(finding.kind, "ssh");
        assert_eq!(finding.evidence.gate.as_deref(), Some("unlocked"));
        assert_eq!(
            finding.evidence.banner.as_deref(),
            Some("SSH-2.0-dropbear_2024.81")
        );
        assert_eq!(finding.detail, "unlocked · SSH-2.0-dropbear_2024.81");
        server.join().unwrap();
    }

    #[test]
    fn an_answer_without_a_banner_is_still_a_tcp_finding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"hello\n").unwrap();
        });

        let finding = probe(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            Plan {
                ssh: true,
                http: false,
            },
            Duration::from_secs(2),
            Duration::from_millis(500),
        )
        .expect("the port answered");

        assert_eq!(finding.kind, "tcp");
        assert_eq!(finding.evidence.gate.as_deref(), Some("hello"));
        server.join().unwrap();
    }

    #[test]
    fn detail_orders_http_fields() {
        let ev = Evidence {
            status: Some("200".to_owned()),
            server: Some("BaseHTTP/0.6".to_owned()),
            title: Some("当贝市场".to_owned()),
            ..Evidence::default()
        };
        assert_eq!(ev.detail(), "HTTP 200 · BaseHTTP/0.6 · 当贝市场");
    }
}
