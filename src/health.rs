//! HTTP health endpoints for Kubernetes probes.
//!
//! - `GET /healthz` → liveness: 200 as long as the process serves requests.
//! - `GET /readyz` → readiness: 200 once the node cache and the initial CSR
//!   list have succeeded, 503 before that.
//!
//! Deliberately dependency-free (raw HTTP/1.1 over tokio TCP): the probe
//! surface stays tiny. No credential is ever returned here (AGENTS.md §6).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Shared flag flipped to `true` once the controller is ready to work.
pub type ReadyFlag = Arc<AtomicBool>;

pub fn new_ready_flag() -> ReadyFlag {
    Arc::new(AtomicBool::new(false))
}

/// Bind `addr` and serve health endpoints until process exit.
pub async fn serve(addr: &str, ready: ReadyFlag) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr, "health server listening");
    serve_on(listener, ready).await
}

/// Accept loop on an already-bound listener.
pub async fn serve_on(listener: TcpListener, ready: ReadyFlag) -> io::Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        let ready = ready.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(socket, ready).await {
                tracing::debug!(error = %err, %peer, "health request failed");
            }
        });
    }
}

/// Map a request path to an HTTP response, given the readiness flag.
fn response_for(path: &str, ready: bool) -> (&'static str, &'static str) {
    match path {
        "/healthz" => ("200 OK", "ok\n"),
        "/readyz" if ready => ("200 OK", "ready\n"),
        "/readyz" => ("503 Service Unavailable", "not ready\n"),
        _ => ("404 Not Found", "not found\n"),
    }
}

async fn handle<S>(mut stream: S, ready: ReadyFlag) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read until the end of the headers; kube probes send a single small GET.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "health read timeout",
            ));
        }
        let n = tokio::time::timeout(remaining, stream.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 4096 {
            break;
        }
    }
    let request = String::from_utf8_lossy(&buf);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = response_for(path, ready.load(Ordering::SeqCst));
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpStream;

    #[test]
    fn healthz_is_always_ok() {
        assert_eq!(response_for("/healthz", false), ("200 OK", "ok\n"));
        assert_eq!(response_for("/healthz", true), ("200 OK", "ok\n"));
    }

    #[test]
    fn readyz_reflects_ready_flag() {
        assert_eq!(response_for("/readyz", false).0, "503 Service Unavailable");
        assert_eq!(response_for("/readyz", true), ("200 OK", "ready\n"));
    }

    #[test]
    fn unknown_path_is_404() {
        assert_eq!(response_for("/nope", true).0, "404 Not Found");
    }

    #[tokio::test]
    async fn serves_http_response_on_duplex_stream() {
        let ready = new_ready_flag();
        ready.store(true, Ordering::SeqCst);
        let (mut client, server) = duplex(4096);
        let server_ready = ready.clone();
        let server_task = tokio::spawn(async move { handle(server, server_ready).await });
        client
            .write_all(b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server_task.await.unwrap().unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ready\n"));
    }

    #[tokio::test]
    async fn serves_over_tcp_and_follows_ready_flag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ready = new_ready_flag();
        let server_ready = ready.clone();
        tokio::spawn(async move { serve_on(listener, server_ready).await });

        async fn get(path: &str, addr: std::net::SocketAddr) -> String {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            String::from_utf8(buf).unwrap()
        }

        // Not ready yet: readiness must be 503, liveness still 200.
        assert!(get("/readyz", addr).await.starts_with("HTTP/1.1 503"));
        assert!(get("/healthz", addr).await.starts_with("HTTP/1.1 200"));
        // Flip the flag: readiness becomes 200.
        ready.store(true, Ordering::SeqCst);
        assert!(get("/readyz", addr).await.starts_with("HTTP/1.1 200"));
    }
}
