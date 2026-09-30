use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::consts::*;
use crate::error::{Error, Result};
use native_tls::{TlsConnector, TlsStream};

pub struct SocketHandler {
    socket: Option<TlsStream<TcpStream>>,
    heartbeat_interval: Duration,
    heartbeat_ack_timeout: Duration,
    read_poll_interval: Duration,
    on_message: Option<Arc<dyn Fn(u8, Vec<u8>) -> Result<()> + Send + Sync>>,
    buffer: Vec<u8>,
    state: u8,
    message_tag: u8,
    message_size: usize,
    last_heartbeat: Instant,
    heartbeat_ack_deadline: Option<Instant>,
    debug: bool,
}

impl SocketHandler {
    pub fn new() -> Self {
        Self {
            socket: None,
            heartbeat_interval: Duration::from_secs(120),
            heartbeat_ack_timeout: Duration::from_secs(30),
            read_poll_interval: Duration::from_secs(1),
            on_message: None,
            buffer: Vec::new(),
            state: MCS_VERSION_TAG_AND_SIZE,
            message_tag: 0,
            message_size: 0,
            last_heartbeat: Instant::now(),
            heartbeat_ack_deadline: None,
            debug: false,
        }
    }

    pub fn connect(&mut self) -> Result<()> {
        let connector = TlsConnector::new()
            .map_err(|e| Error::Other(format!("Failed to create TLS connector: {}", e)))?;

        let stream = TcpStream::connect(FCM_SOCKET_ADDRESS).map_err(|e| {
            Error::Other(format!(
                "Failed to connect to {}: {}",
                FCM_SOCKET_ADDRESS, e
            ))
        })?;

        stream
            .set_nodelay(true)
            .map_err(|e| Error::Other(format!("Failed to set TCP_NODELAY: {}", e)))?;

        let tls_stream = connector
            .connect("mtalk.google.com", stream)
            .map_err(|e| Error::Other(format!("Failed to establish TLS connection: {}", e)))?;

        tls_stream
            .get_ref()
            .set_read_timeout(Some(self.read_poll_interval))
            .map_err(|e| Error::Other(format!("Failed to set socket read timeout: {}", e)))?;

        tls_stream
            .get_ref()
            .set_write_timeout(Some(self.heartbeat_ack_timeout))
            .map_err(|e| Error::Other(format!("Failed to set socket write timeout: {}", e)))?;

        self.socket = Some(tls_stream);
        self.init();
        eprintln!("[FCM] connected");

        Ok(())
    }

    pub fn start_socket_handler(&mut self) -> Result<()> {
        loop {
            while self.process_state_step()? {}
            self.check_heartbeat_timeout()?;
            self.maybe_send_periodic_heartbeat()?;
            self.read_from_socket()?;
        }
    }

    fn read_from_socket(&mut self) -> Result<()> {
        let mut buffer = [0u8; 32 * 1024];

        let result = {
            let socket = self.socket_mut()?;
            socket.read(&mut buffer)
        };

        match result {
            Ok(0) => {
                eprintln!("[FCM] socket_closed");
                Err(Error::Other("Connection closed by peer".to_string()))
            }
            Ok(bytes_read) => {
                self.buffer.extend_from_slice(&buffer[..bytes_read]);
                Ok(())
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                // Normal poll wake-up. This lets heartbeat/watchdog logic run even when
                // the MCS connection is completely idle or silently blackholed.
                Ok(())
            }
            Err(e) => {
                eprintln!("[FCM] socket_error: {e}");
                Err(Error::Other(format!("Failed to read from socket: {}", e)))
            }
        }
    }

    fn process_state_step(&mut self) -> Result<bool> {
        match self.state {
            MCS_VERSION_TAG_AND_SIZE => {
                if self.buffer.len() < VERSION_PACKET_LEN {
                    return Ok(false);
                }
                let version = self.buffer.remove(0);
                if version < KMCS_VERSION && version != 38 {
                    return Err(Error::Other(format!("Invalid version: {}", version)));
                }
                self.state = MCS_TAG_AND_SIZE;
                Ok(true)
            }
            MCS_TAG_AND_SIZE => {
                if self.buffer.len() < TAG_PACKET_LEN {
                    return Ok(false);
                }
                self.message_tag = self.buffer.remove(0);
                self.state = MCS_SIZE;
                Ok(true)
            }
            MCS_SIZE => match Self::try_read_varint(&self.buffer)? {
                Some((size, consumed)) => {
                    self.buffer.drain(0..consumed);
                    self.message_size = size;
                    if self.message_size == 0 {
                        self.dispatch_message(Vec::new())?;
                        self.state = MCS_TAG_AND_SIZE;
                    } else {
                        self.state = MCS_PROTO_BYTES;
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
            MCS_PROTO_BYTES => {
                if self.buffer.len() < self.message_size {
                    return Ok(false);
                }
                let payload: Vec<u8> = self.buffer.drain(0..self.message_size).collect();
                self.dispatch_message(payload)?;
                self.state = MCS_TAG_AND_SIZE;
                Ok(true)
            }
            _ => Err(Error::Other(format!(
                "Socket handler reached unexpected state ({})",
                self.state
            ))),
        }
    }

    fn dispatch_message(&mut self, payload: Vec<u8>) -> Result<()> {
        match self.message_tag {
            K_HEARTBEAT_PING_TAG => {
                self.debug_log("heartbeat_ping_received");
                self.send_heartbeat_ack()?;
            }
            K_HEARTBEAT_ACK_TAG => {
                self.debug_log("heartbeat_ack");
                self.heartbeat_ack_deadline = None;
            }
            _ => {}
        }

        if let Some(ref callback) = self.on_message {
            callback(self.message_tag, payload)?;
        }

        self.message_tag = 0;
        self.message_size = 0;
        Ok(())
    }

    fn maybe_send_periodic_heartbeat(&mut self) -> Result<()> {
        if self.heartbeat_interval.is_zero() {
            return Ok(());
        }

        // Do not send another client ping while the previous one is awaiting ACK.
        if self.heartbeat_ack_deadline.is_some() {
            return Ok(());
        }

        if self.last_heartbeat.elapsed() >= self.heartbeat_interval {
            self.send_heartbeat_ping()?;
        }

        Ok(())
    }

    fn check_heartbeat_timeout(&mut self) -> Result<()> {
        let Some(deadline) = self.heartbeat_ack_deadline else {
            return Ok(());
        };

        if Instant::now() < deadline {
            return Ok(());
        }

        eprintln!("[FCM] heartbeat_timeout");
        self.close();
        Err(Error::Other("Heartbeat ACK timeout".to_string()))
    }

    fn socket_mut(&mut self) -> Result<&mut TlsStream<TcpStream>> {
        self.socket
            .as_mut()
            .ok_or_else(|| Error::Other("Socket not connected".to_string()))
    }

    fn try_read_varint(data: &[u8]) -> Result<Option<(usize, usize)>> {
        let mut result = 0usize;
        let mut shift = 0usize;

        for (idx, &byte) in data.iter().enumerate().take(SIZE_PACKET_LEN_MAX) {
            result |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                return Ok(Some((result, idx + 1)));
            }

            shift += 7;
        }

        if data.len() >= SIZE_PACKET_LEN_MAX {
            return Err(Error::Other("Invalid varint encoding".to_string()));
        }

        Ok(None)
    }

    fn send_heartbeat_ping(&mut self) -> Result<()> {
        {
            let socket = self.socket_mut()?;
            socket.write_all(&[K_HEARTBEAT_PING_TAG, 0]).map_err(|e| {
                eprintln!("[FCM] socket_error: {e}");
                Error::Other(format!("Failed to send heartbeat ping: {}", e))
            })?;
            socket.flush().map_err(|e| {
                eprintln!("[FCM] socket_error: {e}");
                Error::Other(format!("Failed to flush heartbeat ping: {}", e))
            })?;
        }

        let now = Instant::now();
        self.last_heartbeat = now;
        self.heartbeat_ack_deadline = Some(now + self.heartbeat_ack_timeout);
        self.debug_log("heartbeat_ping");
        Ok(())
    }

    fn send_heartbeat_ack(&mut self) -> Result<()> {
        let socket = self.socket_mut()?;
        socket.write_all(&[K_HEARTBEAT_ACK_TAG, 0]).map_err(|e| {
            eprintln!("[FCM] socket_error: {e}");
            Error::Other(format!("Failed to send heartbeat ACK: {}", e))
        })?;
        socket.flush().map_err(|e| {
            eprintln!("[FCM] socket_error: {e}");
            Error::Other(format!("Failed to flush heartbeat ACK: {}", e))
        })?;
        self.debug_log("heartbeat_ack_sent");
        Ok(())
    }

    pub fn send_login_handshake(&mut self, login_request: &[u8]) -> Result<()> {
        let socket = self.socket_mut()?;
        socket
            .write_all(login_request)
            .map_err(|e| Error::Other(format!("Failed to send login handshake: {}", e)))?;
        socket
            .flush()
            .map_err(|e| Error::Other(format!("Failed to flush socket: {}", e)))?;
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.shutdown();
        }
        self.init();
    }

    pub fn set_on_message<F>(&mut self, callback: F)
    where
        F: Fn(u8, Vec<u8>) -> Result<()> + Send + Sync + 'static,
    {
        self.on_message = Some(Arc::new(callback));
    }

    pub fn set_heartbeat_interval(&mut self, interval: Duration) {
        self.heartbeat_interval = interval;
    }

    pub fn set_heartbeat_ack_timeout(&mut self, timeout: Duration) {
        self.heartbeat_ack_timeout = timeout;
    }

    pub fn set_debug(&mut self, enabled: bool) {
        self.debug = enabled;
    }

    fn debug_log(&self, message: &str) {
        if self.debug {
            eprintln!("[FCM][DEBUG] {message}");
        }
    }

    fn init(&mut self) {
        self.buffer.clear();
        self.state = MCS_VERSION_TAG_AND_SIZE;
        self.message_tag = 0;
        self.message_size = 0;
        self.last_heartbeat = Instant::now();
        self.heartbeat_ack_deadline = None;
    }
}

impl Drop for SocketHandler {
    fn drop(&mut self) {
        self.close();
    }
}
