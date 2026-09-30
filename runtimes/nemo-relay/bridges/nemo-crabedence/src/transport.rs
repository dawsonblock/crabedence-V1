// SPDX-License-Identifier: Apache-2.0

//! Length-prefixed JSON transport for the Crabedence execution socket.
//!
//! One request, one response, per connection: a 4-byte big-endian length
//! prefix followed by a UTF-8 JSON body, with a 4 MiB bound in either
//! direction. The framing and the failure classification mirror the canonical
//! Go client (`internal/execution/client.go`) and the NEMO TypeScript client
//! (`nemo/adapters/crabedence/adapter.ts`) so all three planners agree about
//! what a transport failure means.
//!
//! # The dispatch boundary
//!
//! Every failure is classified relative to the moment the request frame is
//! fully transmitted:
//!
//! - [`TransportErrorKind::PreDispatch`] — the connection failed, the request
//!   could not be encoded, or the frame was not fully written. The service
//!   parses only complete frames, so the invocation did not happen and a retry
//!   is safe.
//! - [`TransportErrorKind::PostDispatch`] — the frame was fully transmitted but
//!   no definitive response arrived (timeout, connection loss, truncated
//!   frame). The side effect may have occurred; the outcome is `UNKNOWN` and
//!   must be reconciled, never retried blindly.
//! - [`TransportErrorKind::Protocol`] — the service responded, but the response
//!   violated the ABI (oversized frame, invalid JSON, unknown status, trailing
//!   bytes). The request was transmitted, so the outcome is exactly as
//!   ambiguous as `PostDispatch`.
//!
//! Callers must never convert an ambiguous failure into a definitive `FAILED`
//! outcome.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Maximum message size accepted in either direction (4 MiB).
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Default bound on the wait for a response after the request is transmitted.
///
/// A client-side bound only: an expired wait means the outcome is `UNKNOWN`,
/// never that the invocation failed. The service's provider budget is
/// intentionally longer, so a caller that can afford to wait should raise this.
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default bound on writing the request frame.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Classifies a transport failure relative to the request write boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// The request provably never reached the service. Safe to retry.
    PreDispatch,
    /// The request frame was fully transmitted but no definitive response was
    /// received. The outcome is `UNKNOWN`.
    PostDispatch,
    /// The service responded, but the response violated the ABI. The request
    /// was transmitted, so the outcome is as ambiguous as `PostDispatch`.
    Protocol,
}

impl TransportErrorKind {
    /// Reports whether this failure leaves the outcome ambiguous.
    ///
    /// A caller that sees `true` must treat the execution as `UNKNOWN` —
    /// reconcile before retrying — never as `FAILED`.
    pub const fn is_ambiguous(self) -> bool {
        !matches!(self, Self::PreDispatch)
    }
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreDispatch => formatter.write_str("PRE_DISPATCH"),
            Self::PostDispatch => formatter.write_str("POST_DISPATCH"),
            Self::Protocol => formatter.write_str("PROTOCOL"),
        }
    }
}

/// A client-side transport failure carrying its dispatch classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    /// Builds a classified transport failure.
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The dispatch classification.
    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    /// The human-readable detail.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for TransportError {}

/// Resolves the canonical default execution-socket path.
///
/// This mirrors `execution.DefaultSocketPath` in the Go service and
/// `defaultCrabedenceSocketPath` in the NEMO TypeScript client, so a
/// default-started service and a default-configured bridge meet without flags:
/// `$XDG_RUNTIME_DIR/crabedence/execution.sock` when the runtime directory is
/// set, else `/tmp/crabedence-$USER/execution.sock` (falling back to the
/// numeric uid when `USER` is unset).
pub fn default_socket_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR")
        && !runtime_dir.is_empty()
    {
        return Path::new(&runtime_dir)
            .join("crabedence")
            .join("execution.sock");
    }
    let user = std::env::var("USER").unwrap_or_else(|_| {
        // SAFETY: getuid takes no arguments, cannot fail, and touches no
        // memory; it is the same call the Go service makes.
        let uid = unsafe { libc::getuid() };
        format!("uid-{uid}")
    });
    Path::new("/tmp")
        .join(format!("crabedence-{user}"))
        .join("execution.sock")
}

/// The canonical client for the execution service's length-prefixed JSON ABI.
#[derive(Debug, Clone)]
pub struct ExecutionSocketClient {
    socket_path: PathBuf,
    response_timeout: Duration,
    write_timeout: Duration,
}

impl ExecutionSocketClient {
    /// Returns a client for the execution service at `socket_path`.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            response_timeout: DEFAULT_RESPONSE_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Overrides the response and write bounds.
    ///
    /// Zero durations are replaced by the defaults, matching the Go client's
    /// option handling.
    pub fn with_timeouts(mut self, response: Duration, write: Duration) -> Self {
        if !response.is_zero() {
            self.response_timeout = response;
        }
        if !write.is_zero() {
            self.write_timeout = write;
        }
        self
    }

    /// The socket path this client targets.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Transmits one request and returns the parsed response.
    ///
    /// A failure is returned as a [`TransportError`]: `PreDispatch` failures
    /// are safe to retry, while `PostDispatch` and `Protocol` failures mean the
    /// outcome is `UNKNOWN` and must be reconciled, not reported as `FAILED`.
    ///
    /// The request is validated against the strict invocation ABI before it is
    /// written, so the bridge never emits a request the kernel would refuse.
    pub fn invoke(&self, request: &serde_json::Value) -> Result<serde_json::Value, TransportError> {
        let frame = self.encode_request_frame(request)?;

        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            TransportError::new(
                TransportErrorKind::PreDispatch,
                format!(
                    "connect to execution service at {}: {error} (is 'crabbox serve-exec' running?)",
                    self.socket_path.display()
                ),
            )
        })?;
        let _ = stream.set_write_timeout(Some(self.write_timeout));
        let _ = stream.set_read_timeout(Some(self.response_timeout));

        // The write boundary is the dispatch boundary: track exactly how much
        // of the frame the kernel accepted.
        let mut written = 0;
        while written < frame.len() {
            match stream.write(&frame[written..]) {
                Ok(0) => {
                    return Err(TransportError::new(
                        TransportErrorKind::PreDispatch,
                        format!(
                            "write request frame ({written} of {} bytes): unexpected end of stream",
                            frame.len()
                        ),
                    ));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    // Rust's `Write` never reports partial success together
                    // with an error (unlike Go's `net.Conn`), so a write error
                    // here always means the frame was not fully transmitted —
                    // and the service parses only complete frames.
                    return Err(TransportError::new(
                        TransportErrorKind::PreDispatch,
                        format!(
                            "write request frame ({written} of {} bytes): {error}",
                            frame.len()
                        ),
                    ));
                }
            }
        }

        // From here the request has been transmitted. Every failure is an
        // UNKNOWN outcome until a definitive response arrives.
        self.read_response_frame(&mut stream)
    }

    /// Marshals, validates, and length-prefixes one request.
    fn encode_request_frame(&self, request: &serde_json::Value) -> Result<Vec<u8>, TransportError> {
        let payload = serde_json::to_vec(request).map_err(|error| {
            TransportError::new(
                TransportErrorKind::PreDispatch,
                format!("marshal request: {error}"),
            )
        })?;
        crate::abi::validate_invocation_request(&payload).map_err(|error| {
            TransportError::new(
                TransportErrorKind::PreDispatch,
                format!("invocation ABI violation: {error}"),
            )
        })?;
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(TransportError::new(
                TransportErrorKind::PreDispatch,
                format!(
                    "request exceeds the {MAX_MESSAGE_BYTES}-byte frame bound: {} bytes",
                    payload.len()
                ),
            ));
        }
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Reads one length-prefixed response frame. Every failure here is
    /// post-transmission.
    fn read_response_frame(
        &self,
        stream: &mut UnixStream,
    ) -> Result<serde_json::Value, TransportError> {
        let mut length_bytes = [0u8; 4];
        if let Err(error) = read_exact_classified(stream, &mut length_bytes, self.response_timeout)
        {
            return Err(TransportError::new(
                TransportErrorKind::PostDispatch,
                format!("no response received: {error}"),
            ));
        }
        let response_length = u32::from_be_bytes(length_bytes) as usize;
        if response_length > MAX_MESSAGE_BYTES {
            return Err(TransportError::new(
                TransportErrorKind::Protocol,
                format!(
                    "response frame length {response_length} exceeds the {MAX_MESSAGE_BYTES}-byte bound"
                ),
            ));
        }
        let mut payload = vec![0u8; response_length];
        if let Err(error) = read_exact_classified(stream, &mut payload, self.response_timeout) {
            return Err(TransportError::new(
                TransportErrorKind::PostDispatch,
                format!("response frame truncated: {error}"),
            ));
        }
        if let Some(trailing) = read_trailing_bytes(stream) {
            return Err(TransportError::new(
                TransportErrorKind::Protocol,
                format!("unexpected trailing data after frame ({trailing} bytes)"),
            ));
        }
        let response: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
            TransportError::new(
                TransportErrorKind::Protocol,
                format!("parse response frame: {error}"),
            )
        })?;
        let status = response.get("status").and_then(serde_json::Value::as_str);
        if !matches!(
            status,
            Some("SUCCEEDED" | "FAILED" | "DENIED" | "UNKNOWN" | "IN_FLIGHT")
        ) {
            return Err(TransportError::new(
                TransportErrorKind::Protocol,
                format!("invalid response status {}", status.unwrap_or("<absent>")),
            ));
        }
        Ok(response)
    }
}

/// Reads exactly `buffer.len()` bytes, mapping a short read to a readable
/// message.
fn read_exact_classified(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    timeout: Duration,
) -> Result<(), String> {
    stream
        .read_exact(buffer)
        .map_err(|error| match error.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => format!("timed out after {timeout:?}"),
            _ => error.to_string(),
        })
}

/// Reports whether bytes follow a complete frame.
///
/// The service sends exactly one frame per connection and closes it, so
/// once a full frame has arrived the only lawful continuation is
/// end-of-stream. The probe therefore waits under the socket's read
/// timeout: a healthy peer signals EOF immediately after its frame,
/// while a non-blocking check could miss trailing bytes that had not
/// yet arrived and pass a protocol violation off as a clean response.
/// A peer that never closes still bounds the wait the same way an
/// unanswered request does; only bytes actually received are reported.
fn read_trailing_bytes(stream: &UnixStream) -> Option<usize> {
    let mut probe = [0u8; 64];
    let mut stream_ref = stream;
    match stream_ref.read(&mut probe) {
        Ok(0) => None,
        Ok(count) => Some(count),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn temp_socket_path(label: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "nemo-crabedence-test-{label}-{}-{unique}.sock",
            std::process::id()
        ))
    }

    fn valid_request() -> serde_json::Value {
        serde_json::json!({
            "capability": "system.echo",
            "arguments": {},
            "authority": { "principal": "alice@example.com" }
        })
    }

    #[test]
    fn round_trips_one_frame() {
        let path = temp_socket_path("round-trip");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            let request: serde_json::Value = serde_json::from_slice(&payload).expect("json");
            assert_eq!(request["capability"], "system.echo");
            let response = br#"{"status":"SUCCEEDED","result":{"ok":true}}"#;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("write length");
            stream.write_all(response).expect("write body");
        });

        let client = ExecutionSocketClient::new(&path);
        let response = client.invoke(&valid_request()).expect("invoke");
        assert_eq!(response["status"], "SUCCEEDED");
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_socket_is_pre_dispatch() {
        let client = ExecutionSocketClient::new(temp_socket_path("absent"));
        let error = client.invoke(&valid_request()).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::PreDispatch);
        assert!(!error.kind().is_ambiguous());
    }

    #[test]
    fn closed_socket_before_response_is_post_dispatch() {
        let path = temp_socket_path("closed");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            // Close without answering: the request was transmitted.
        });

        let client = ExecutionSocketClient::new(&path);
        let error = client.invoke(&valid_request()).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::PostDispatch);
        assert!(error.kind().is_ambiguous());
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalid_json_response_is_protocol() {
        let path = temp_socket_path("bad-json");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            let response = b"not json";
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("write length");
            stream.write_all(response).expect("write body");
        });

        let client = ExecutionSocketClient::new(&path);
        let error = client.invoke(&valid_request()).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::Protocol);
        assert!(error.kind().is_ambiguous());
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_status_is_protocol() {
        let path = temp_socket_path("bad-status");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            let response = br#"{"status":"MAYBE"}"#;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("write length");
            stream.write_all(response).expect("write body");
        });

        let client = ExecutionSocketClient::new(&path);
        let error = client.invoke(&valid_request()).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::Protocol);
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trailing_data_is_protocol() {
        let path = temp_socket_path("trailing");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).expect("length");
            let length = u32::from_be_bytes(length_bytes) as usize;
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).expect("payload");
            let response = br#"{"status":"SUCCEEDED"}"#;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("write length");
            stream.write_all(response).expect("write body");
            stream.write_all(b"{}").expect("write trailing");
        });

        let client = ExecutionSocketClient::new(&path);
        let error = client.invoke(&valid_request()).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::Protocol);
        server.join().expect("server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_to_send_an_abi_violating_request() {
        let client = ExecutionSocketClient::new(temp_socket_path("abi"));
        let request = serde_json::json!({
            "capability": "system.echo",
            "arguments": {},
            "authority": { "principal": "alice" },
            "execution_route": "LOCAL"
        });
        let error = client.invoke(&request).unwrap_err();
        assert_eq!(error.kind(), TransportErrorKind::PreDispatch);
        assert!(error.message().contains("unknown field"), "{error}");
    }

    #[test]
    fn default_socket_path_follows_the_runtime_directory() {
        // The resolution rule is exercised through the same environment the
        // service reads; this asserts the shape rather than a fixed path.
        let path = default_socket_path();
        assert!(path.ends_with("execution.sock"), "{}", path.display());
    }
}
