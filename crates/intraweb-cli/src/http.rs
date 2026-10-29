//! A very small HTTP/1.0 client.
//!
//! Everything a node says to another node goes over the peer's own HTTP port:
//! pages, mail, and file downloads. That is one socket dialled straight at the
//! peer, which is all the "direct point to point" requirement ever meant, and
//! it comes with ranged, resumable downloads already solved.
//!
//! A client crate would cost more than the few dozen lines below and drag a TLS
//! stack into a binary that has no use for one.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default ceiling on a response we buffer in memory. Streaming downloads use
/// [`stream_to_file`] instead and never hold the body at all.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| key.to_ascii_lowercase() == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Format a host for a `Host:` header or a URL, bracketing IPv6.
pub fn host_for(addr: IpAddr) -> String {
    match addr {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

pub async fn get(addr: IpAddr, port: u16, path: &str, timeout: Duration) -> Result<Response> {
    request(addr, port, "GET", path, &[], None, timeout).await
}

pub async fn post_json(
    addr: IpAddr,
    port: u16,
    path: &str,
    body: &str,
    timeout: Duration,
) -> Result<Response> {
    let headers = [("Content-Type".to_string(), "application/json".to_string())];
    request(addr, port, "POST", path, &headers, Some(body), timeout).await
}

/// One request/response exchange, with the connection closed by the peer.
pub async fn request(
    addr: IpAddr,
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
    timeout: Duration,
) -> Result<Response> {
    let exchange = async {
        let mut stream = TcpStream::connect((addr, port)).await?;
        write_request(&mut stream, addr, port, method, path, extra_headers, body).await?;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while buf.len() < MAX_RESPONSE_BYTES {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
        }
        anyhow::Ok(buf)
    };

    let started = std::time::Instant::now();
    let raw = match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(raw)) => raw,
        Ok(Err(err)) => {
            crate::traffic::record_failure();
            return Err(err);
        }
        Err(_) => {
            crate::traffic::record_failure();
            anyhow::bail!("{} did not answer in time", host_for(addr));
        }
    };
    // The head is a few hundred bytes; counting the body we sent and the
    // whole reply is close enough and costs nothing to work out.
    let sent = body.map_or(0, str::len) as u64;
    crate::traffic::record(
        crate::traffic::Direction::Out,
        sent,
        raw.len() as u64,
        started.elapsed(),
    );

    parse_response(&raw)
}

async fn write_request(
    stream: &mut TcpStream,
    addr: IpAddr,
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<()> {
    // HTTP/1.0 so the peer closes the connection and we can read to EOF without
    // implementing chunked transfer decoding.
    let mut head = format!(
        "{method} {path} HTTP/1.0\r\n\
         Host: {}:{port}\r\n\
         User-Agent: intraweb\r\n\
         Connection: close\r\n",
        host_for(addr),
    );
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Download to a file, resuming from whatever is already there.
///
/// Nothing is held in memory beyond one buffer, so the size of the file does
/// not decide whether the transfer succeeds.
pub async fn stream_to_file(
    addr: IpAddr,
    port: u16,
    path: &str,
    destination: &std::path::Path,
    timeout: Duration,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt as _;

    let already = tokio::fs::metadata(destination)
        .await
        .map(|m| m.len())
        .unwrap_or(0);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((addr, port)))
        .await
        .map_err(|_| anyhow::anyhow!("{} did not answer in time", host_for(addr)))??;

    // Asking for the remainder is what makes an interrupted transfer resumable.
    let range = (already > 0).then(|| ("Range".to_string(), format!("bytes={already}-")));
    write_request(&mut stream, addr, port, "GET", path, range.as_slice(), None).await?;

    // Read just the head, then stream the rest to disk.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            bail!("the peer closed the connection before sending a response");
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            bail!("the peer sent an absurdly large response head");
        }
    }
    let head = parse_response(&head)?;

    let resuming = head.status == 206;
    if !head.is_success() {
        bail!("the peer answered HTTP {}", head.status);
    }
    if already > 0 && !resuming {
        // Ranges were ignored, so this is a whole file again -- start over
        // rather than appending it onto the partial one.
        tokio::fs::remove_file(destination).await.ok();
    }

    let expected = head
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|len| len + if resuming { already } else { 0 });

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(resuming)
        .truncate(!resuming)
        .open(destination)
        .await
        .with_context(|| format!("could not write {}", destination.display()))?;

    let mut written = if resuming { already } else { 0 };
    let started = std::time::Instant::now();
    let starting_from = written;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        file.write_all(&chunk[..read]).await?;
        written += read as u64;
        on_progress(written, expected);
    }
    file.flush().await?;
    // Only what crossed the wire this time; a resumed transfer's earlier part
    // was measured when it happened.
    crate::traffic::record(
        crate::traffic::Direction::Out,
        0,
        written - starting_from,
        started.elapsed(),
    );
    Ok(written)
}

/// Split an HTTP response into status, headers, and body.
pub fn parse_response(raw: &[u8]) -> Result<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));

    let mut lines = head.lines();
    let status_line = lines.next().context("the peer sent an empty response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .with_context(|| format!("could not read a status from {status_line:?}"))?;

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    Ok(Response {
        status,
        headers,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn reads_status_headers_and_body() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
        let response = parse_response(raw).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.is_success());
        assert_eq!(response.body, "hello");
        assert_eq!(response.header("content-type"), Some("text/html"));
    }

    #[test]
    fn header_lookup_ignores_case() {
        let raw = b"HTTP/1.0 206 Partial Content\r\nCONTENT-LENGTH: 12\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.header("Content-Length"), Some("12"));
    }

    #[test]
    fn a_failure_status_is_not_success() {
        let response = parse_response(b"HTTP/1.0 404 Not Found\r\n\r\n").unwrap();
        assert_eq!(response.status, 404);
        assert!(!response.is_success());
    }

    #[test]
    fn junk_is_refused_rather_than_guessed_at() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"not http at all\r\n\r\n").is_err());
    }

    #[test]
    fn ipv6_hosts_are_bracketed() {
        assert_eq!(host_for(IpAddr::V6(Ipv6Addr::LOCALHOST)), "[::1]");
        assert_eq!(host_for(IpAddr::V4(Ipv4Addr::LOCALHOST)), "127.0.0.1");
    }
}
