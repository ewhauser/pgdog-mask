//! A Postgres frontend that speaks the wire protocol message by message, so
//! tests can send what drivers send (pipelines, `Execute` without `Describe`,
//! result formats per column, statements split over requests) and see every
//! byte the server sends back.
use std::time::Duration;

use postgres_protocol::authentication::{md5_hash, sasl};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// Longest wait for a server message: a missing response fails the test
/// instead of hanging it.
const TIMEOUT: Duration = Duration::from_secs(10);

pub const TEXT: i16 = 0;
pub const BINARY: i16 = 1;

/// A server message.
#[derive(Debug, Clone)]
pub struct Msg {
    pub code: u8,
    pub body: Vec<u8>,
}

impl Msg {
    /// Fields of a `DataRow`; `None` is NULL.
    pub fn fields(&self) -> Vec<Option<Vec<u8>>> {
        assert_eq!(self.code, b'D', "{self:?}");
        let count = i16::from_be_bytes([self.body[0], self.body[1]]);
        let mut offset = 2;
        (0..count)
            .map(|_| {
                let len = i32::from_be_bytes(self.body[offset..offset + 4].try_into().unwrap());
                offset += 4;
                (len >= 0).then(|| {
                    let field = self.body[offset..offset + len as usize].to_vec();
                    offset += len as usize;
                    field
                })
            })
            .collect()
    }

    /// Fields of an `ErrorResponse` or `NoticeResponse`, by type.
    pub fn error_fields(&self) -> Vec<(u8, String)> {
        assert!(matches!(self.code, b'E' | b'N'), "{self:?}");
        self.body
            .split(|&b| b == 0)
            .filter(|field| !field.is_empty())
            .map(|field| (field[0], String::from_utf8_lossy(&field[1..]).into_owned()))
            .collect()
    }

    /// SQLSTATE of an `ErrorResponse` or `NoticeResponse`.
    pub fn sqlstate(&self) -> String {
        self.error_fields()
            .into_iter()
            .find(|(field, _)| *field == b'C')
            .map(|(_, code)| code)
            .unwrap_or_default()
    }
}

/// What a request got back.
#[derive(Debug, Default)]
pub struct Response {
    pub messages: Vec<Msg>,
}

impl Response {
    /// Every `DataRow`.
    pub fn rows(&self) -> Vec<Vec<Option<Vec<u8>>>> {
        self.messages
            .iter()
            .filter(|msg| msg.code == b'D')
            .map(Msg::fields)
            .collect()
    }

    /// SQLSTATEs of every `ErrorResponse`.
    pub fn errors(&self) -> Vec<String> {
        self.messages
            .iter()
            .filter(|msg| msg.code == b'E')
            .map(Msg::sqlstate)
            .collect()
    }
}

/// One frontend connection.
pub struct Wire {
    stream: TcpStream,
    /// Bytes received and not yet split into messages.
    buf: Vec<u8>,
    /// Every byte the server sent, including startup.
    transcript: Vec<u8>,
    /// Messages to send with the next `send`.
    out: Vec<u8>,
    /// `ReadyForQuery`s the buffered messages will get: one per `Query` and `Sync`.
    ready: usize,
    /// `DataRow` and `CopyData` messages received.
    pub data: usize,
}

fn cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

impl Wire {
    /// Connect and authenticate (trust, cleartext, MD5 or SCRAM).
    pub async fn connect(addr: &str, user: &str, password: &str, database: &str) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        stream.set_nodelay(true).unwrap();
        let mut wire = Self {
            stream,
            buf: Vec::new(),
            transcript: Vec::new(),
            out: Vec::new(),
            ready: 0,
            data: 0,
        };

        let mut body = 196608_i32.to_be_bytes().to_vec();
        for (key, value) in [("user", user), ("database", database)] {
            cstr(&mut body, key);
            cstr(&mut body, value);
        }
        body.push(0);
        wire.out
            .extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
        wire.out.extend_from_slice(&body);
        wire.send().await;

        let mut scram = None;
        loop {
            let msg = wire.recv().await;
            match msg.code {
                b'R' => {
                    let kind = i32::from_be_bytes(msg.body[..4].try_into().unwrap());
                    let data = &msg.body[4..];
                    match kind {
                        0 => (),
                        3 => {
                            let mut pw = password.as_bytes().to_vec();
                            pw.push(0);
                            wire.message(b'p', &pw);
                            wire.send().await;
                        }
                        5 => {
                            let hash = md5_hash(
                                user.as_bytes(),
                                password.as_bytes(),
                                data.try_into().unwrap(),
                            );
                            let mut pw = hash.into_bytes();
                            pw.push(0);
                            wire.message(b'p', &pw);
                            wire.send().await;
                        }
                        10 => {
                            let client = sasl::ScramSha256::new(
                                password.as_bytes(),
                                sasl::ChannelBinding::unsupported(),
                            );
                            let mut body = Vec::new();
                            cstr(&mut body, sasl::SCRAM_SHA_256);
                            body.extend_from_slice(&(client.message().len() as i32).to_be_bytes());
                            body.extend_from_slice(client.message());
                            wire.message(b'p', &body);
                            wire.send().await;
                            scram = Some(client);
                        }
                        11 => {
                            let client = scram.as_mut().expect("SASL started");
                            client.update(data).expect("SCRAM server-first");
                            let body = client.message().to_vec();
                            wire.message(b'p', &body);
                            wire.send().await;
                        }
                        12 => {
                            let client = scram.as_mut().expect("SASL started");
                            client.finish(data).expect("SCRAM server-final");
                        }
                        kind => panic!("unsupported authentication request {kind}"),
                    }
                }
                b'E' => panic!("connect as {user} failed: {:?}", msg.error_fields()),
                b'Z' => break,
                _ => (),
            }
        }
        wire
    }

    fn message(&mut self, code: u8, body: &[u8]) -> &mut Self {
        self.out.push(code);
        self.out
            .extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
        self.out.extend_from_slice(body);
        self
    }

    /// Simple query.
    pub fn query(&mut self, sql: &str) -> &mut Self {
        let mut body = Vec::new();
        cstr(&mut body, sql);
        self.ready += 1;
        self.message(b'Q', &body)
    }

    pub fn parse(&mut self, name: &str, sql: &str, types: &[u32]) -> &mut Self {
        let mut body = Vec::new();
        cstr(&mut body, name);
        cstr(&mut body, sql);
        body.extend_from_slice(&(types.len() as i16).to_be_bytes());
        for oid in types {
            body.extend_from_slice(&oid.to_be_bytes());
        }
        self.message(b'P', &body)
    }

    /// Bind text parameters, with the given result format codes.
    pub fn bind(
        &mut self,
        portal: &str,
        statement: &str,
        params: &[Option<&str>],
        result_formats: &[i16],
    ) -> &mut Self {
        let mut body = Vec::new();
        cstr(&mut body, portal);
        cstr(&mut body, statement);
        body.extend_from_slice(&0_i16.to_be_bytes());
        body.extend_from_slice(&(params.len() as i16).to_be_bytes());
        for param in params {
            match param {
                Some(value) => {
                    body.extend_from_slice(&(value.len() as i32).to_be_bytes());
                    body.extend_from_slice(value.as_bytes());
                }
                None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
            }
        }
        body.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
        for format in result_formats {
            body.extend_from_slice(&format.to_be_bytes());
        }
        self.message(b'B', &body)
    }

    pub fn describe_statement(&mut self, name: &str) -> &mut Self {
        let mut body = vec![b'S'];
        cstr(&mut body, name);
        self.message(b'D', &body)
    }

    pub fn describe_portal(&mut self, name: &str) -> &mut Self {
        let mut body = vec![b'P'];
        cstr(&mut body, name);
        self.message(b'D', &body)
    }

    /// Execute a portal; `max_rows` 0 runs it to completion.
    pub fn execute(&mut self, portal: &str, max_rows: i32) -> &mut Self {
        let mut body = Vec::new();
        cstr(&mut body, portal);
        body.extend_from_slice(&max_rows.to_be_bytes());
        self.message(b'E', &body)
    }

    pub fn close_statement(&mut self, name: &str) -> &mut Self {
        let mut body = vec![b'S'];
        cstr(&mut body, name);
        self.message(b'C', &body)
    }

    pub fn close_portal(&mut self, name: &str) -> &mut Self {
        let mut body = vec![b'P'];
        cstr(&mut body, name);
        self.message(b'C', &body)
    }

    pub fn sync(&mut self) -> &mut Self {
        self.ready += 1;
        self.message(b'S', &[])
    }

    pub fn flush(&mut self) -> &mut Self {
        self.message(b'H', &[])
    }

    /// Send the buffered messages.
    pub async fn send(&mut self) {
        let out = std::mem::take(&mut self.out);
        self.stream.write_all(&out).await.expect("send");
    }

    /// The next server message.
    pub async fn recv(&mut self) -> Msg {
        loop {
            if self.buf.len() >= 5 {
                let len = i32::from_be_bytes(self.buf[1..5].try_into().unwrap()) as usize;
                if self.buf.len() > len {
                    let rest = self.buf.split_off(len + 1);
                    let msg = std::mem::replace(&mut self.buf, rest);
                    if matches!(msg[0], b'D' | b'd') {
                        self.data += 1;
                    }
                    return Msg {
                        code: msg[0],
                        body: msg[5..].to_vec(),
                    };
                }
            }
            let mut chunk = [0; 8192];
            let n = tokio::time::timeout(TIMEOUT, self.stream.read(&mut chunk))
                .await
                .expect("timed out waiting for the server")
                .expect("read");
            assert!(n > 0, "server closed the connection");
            self.transcript.extend_from_slice(&chunk[..n]);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Messages up to and including the first one with `code`.
    pub async fn recv_until(&mut self, code: u8) -> Response {
        self.recv_until_any(&[code]).await
    }

    /// Messages up to and including the first one with one of `codes`.
    pub async fn recv_until_any(&mut self, codes: &[u8]) -> Response {
        let mut response = Response::default();
        loop {
            let msg = self.recv().await;
            let done = codes.contains(&msg.code);
            response.messages.push(msg);
            if done {
                return response;
            }
        }
    }

    /// Send the buffered messages and read up to the last `ReadyForQuery`
    /// they get.
    pub async fn run(&mut self) -> Response {
        let ready = std::mem::take(&mut self.ready);
        assert!(ready > 0, "nothing ends the request");
        self.send().await;
        let mut response = Response::default();
        for _ in 0..ready {
            response
                .messages
                .extend(self.recv_until(b'Z').await.messages);
        }
        response
    }

    /// Every byte the server sent so far.
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}
