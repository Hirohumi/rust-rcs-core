// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate cookie;
extern crate httparse;
extern crate rustls;
extern crate tokio;
extern crate tokio_stream;
extern crate url;
extern crate walkdir;

pub mod decode;
pub mod decompress;
pub mod request;
pub mod response;

use std::fmt;
use std::io;
use std::io::Read;
use std::marker::Unpin;
use std::net::IpAddr;
use std::ops::Add;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::io::AsyncBufRead;
use futures::stream::TryStreamExt;
use futures::StreamExt;

use rustls::ClientConfig;

use tokio::io::copy;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;

use tokio_util::compat::FuturesAsyncReadCompatExt;
use url::{Host, Url};
use uuid::Uuid;

use crate::dns::{DnsClient, DnsConfig};

use crate::ffi::log::platform_log;
use crate::ffi::net_ctrl::get_active_dns_servers;

use crate::internet::header;
use crate::internet::Header;
use crate::io::network::stream;
use crate::io::network::stream::ClientStream;
use crate::io::DynamicChain;
use crate::io::ProgressReportingReader;
use crate::io::Serializable;

use request::Request;
use response::{Response, ResponseOrAgain, ResponseStream};

const LOG_TAG: &str = "http_client";

const MAX_CONCURRENT_CONNECTIONS: usize = 16;

const MAX_CONCURRENT_REQUEST_IN_CONNECTIONS: usize = 16;

enum ConnectMessage {
    Request(
        bool,
        Host,
        u16,
        bool,
        oneshot::Sender<Result<HttpConnectionHandle>>,
    ),
    // DnsResolved(SocketAddr, Host, u16, bool, oneshot::Sender<HttpConnectionHandle>),
    // ConnectSuccess(ClientStream, Option<(u8, u8)>, Host, u16, bool, oneshot::Sender<HttpConnectionHandle>),
}

fn setup_idle_timeout(
    conn: &Arc<HttpConnection>,
    connections: &Arc<
        Mutex<
            Vec<(
                Arc<HttpConnection>,
                mpsc::Sender<(
                    Request,
                    mpsc::Sender<usize>,
                    oneshot::Sender<
                        Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>,
                    >,
                )>,
            )>,
        >,
    >,
    now: Instant,
) {
    let conn = Arc::clone(&conn);
    let connections = Arc::clone(&connections);

    tokio::spawn(async move {
        let deadline = now.add(Duration::from_secs(16));
        sleep_until(deadline).await;
        platform_log(
            LOG_TAG,
            format!("on idle timer for http connection {}", conn.debug_name),
        );
        let mut guard = connections.lock().unwrap();
        match *conn.state.lock().unwrap() {
            ConnectionState::Idle(scheduled) => {
                if scheduled == now {
                    let mut i = 0;
                    for (conn_, _) in &mut *guard {
                        if Arc::ptr_eq(&conn, conn_) {
                            let _ = (*guard).remove(i);
                            platform_log(
                                LOG_TAG,
                                format!("http connection {} removed", conn.debug_name),
                            );
                            break;
                        }
                        i = i + 1;
                    }
                }
            }
            ConnectionState::Working(_) => {}
        }
    });
}

pub struct HttpClient {
    // connections: Arc<Mutex<HashMap<Url, ConnectionState>>>,
    // cookie_jar: CookieJar,
    tx: mpsc::Sender<ConnectMessage>,
}

impl HttpClient {
    pub fn new(
        client_config: Arc<ClientConfig>,
        dns_client: Arc<DnsClient>,
        rt: Arc<Runtime>,
    ) -> HttpClient {
        let (tx, mut rx) = mpsc::channel::<ConnectMessage>(MAX_CONCURRENT_CONNECTIONS);

        let connections: Arc<
            Mutex<
                Vec<(
                    Arc<HttpConnection>,
                    mpsc::Sender<(
                        Request,
                        mpsc::Sender<usize>,
                        oneshot::Sender<
                            Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>,
                        >,
                    )>,
                )>,
            >,
        > = Arc::new(Mutex::new(Vec::new()));

        let mut stdout = tokio::io::stdout();

        rt.spawn(async move {
            'next: loop {
                match rx.recv().await {
                    Some(cm) => {
                        match cm {
                            ConnectMessage::Request(tls, host, port, can_pipeline, tx) => {
                                stdout
                                    .write(b"getting http connect request\r\n")
                                    .await
                                    .unwrap();

                                {
                                    let mut guard = connections.lock().unwrap();

                                    for (conn, req_tx) in &mut *guard {
                                        if conn.host == host && conn.port == port {
                                            let mut conn_guard = conn.state.lock().unwrap();
                                            match &mut *conn_guard {
                                                ConnectionState::Idle(_) if conn.can_pipeline == can_pipeline => {
                                                    *conn_guard = ConnectionState::Working(0);

                                                    match tx.send(Ok(HttpConnectionHandle {
                                                        cipher_id: conn.cipher_id,
                                                        tx: req_tx.clone(),
                                                    })) {
                                                        Ok(()) => {
                                                            continue 'next;
                                                        }

                                                        Err(_) => {
                                                            panic!("")
                                                        }
                                                    }
                                                }

                                                ConnectionState::Working(_) if conn.can_pipeline && can_pipeline => {
                                                    match tx.send(Ok(HttpConnectionHandle {
                                                        cipher_id: conn.cipher_id,
                                                        tx: req_tx.clone(),
                                                    })) {
                                                        Ok(()) => {
                                                            continue 'next;
                                                        }

                                                        Err(_) => {
                                                            panic!("")
                                                        }
                                                    }
                                                }

                                                _ => {}
                                            }
                                        }
                                    }
                                }

                                match host {
                                    Host::Domain(domain) => {
                                        let client_config = Arc::clone(&client_config);
                                        let dns_client = Arc::clone(&dns_client);
                                        let connections = Arc::clone(&connections);

                                        stdout.write(b"resolve dns for ").await.unwrap();
                                        stdout.write(domain.as_bytes()).await.unwrap();
                                        stdout.write(b"\r\n").await.unwrap();

                                        tokio::spawn(async move {
                                            let dns_servers = get_active_dns_servers();

                                            let dns_config = DnsConfig { server_addrs: dns_servers };

                                            match dns_client.resolve(dns_config, domain.clone()).await {
                                                Ok(mut stream) => {
                                                    while let Some(ip) = stream.next().await {
                                                        if let IpAddr::V6(_) = ip {
                                                            continue; // to-do: IPv6 not supported?
                                                        }
                                                        let client_config = Arc::clone(&client_config);
                                                        match Self::connect_inner(
                                                            tls,
                                                            Host::Domain(domain.clone()),
                                                            ip,
                                                            port,
                                                            client_config,
                                                            &domain,
                                                            can_pipeline,
                                                            &connections,
                                                        )
                                                        .await
                                                        {
                                                            Ok(handle) => match tx.send(Ok(handle)) {
                                                                Ok(()) => {
                                                                    return;
                                                                }

                                                                Err(_) => {
                                                                    panic!("")
                                                                }
                                                            },

                                                            Err(e) => {
                                                                platform_log(
                                                                    LOG_TAG,
                                                                    format!(
                                                                        "connect_inner failed with error {:?}",
                                                                        e
                                                                    ),
                                                                );
                                                            }
                                                        }
                                                    }

                                                    match tx.send(Err(ErrorKind::Dns)) {
                                                        Ok(()) => {
                                                            return;
                                                        }

                                                        Err(_) => {
                                                            panic!("")
                                                        }
                                                    }
                                                }

                                                Err(_) => match tx.send(Err(ErrorKind::Dns)) {
                                                    Ok(()) => {
                                                        return;
                                                    }

                                                    Err(_) => {
                                                        panic!("")
                                                    }
                                                },
                                            }
                                        });
                                    }

                                    Host::Ipv4(ip) => {
                                        let client_config = Arc::clone(&client_config);
                                        let connections = Arc::clone(&connections);

                                        tokio::spawn(async move {
                                            if let Ok(handle) = Self::connect_inner(
                                                tls,
                                                host,
                                                IpAddr::V4(ip),
                                                port,
                                                client_config,
                                                &ip.to_string(),
                                                can_pipeline,
                                                &connections,
                                            )
                                            .await
                                            {
                                                match tx.send(Ok(handle)) {
                                                    Ok(()) => {
                                                        return;
                                                    }

                                                    Err(_) => {
                                                        panic!("")
                                                    }
                                                }
                                            }
                                        });
                                    }

                                    Host::Ipv6(ip) => {
                                        let client_config = Arc::clone(&client_config);
                                        let connections = Arc::clone(&connections);

                                        tokio::spawn(async move {
                                            if let Ok(handle) = Self::connect_inner(
                                                tls,
                                                host,
                                                IpAddr::V6(ip),
                                                port,
                                                client_config,
                                                &ip.to_string(),
                                                can_pipeline,
                                                &connections,
                                            )
                                            .await
                                            {
                                                match tx.send(Ok(handle)) {
                                                    Ok(()) => {
                                                        return;
                                                    }

                                                    Err(_) => {
                                                        panic!("")
                                                    }
                                                }
                                            }
                                        });
                                    }
                                }
                            }

                        }
                    },

                    None => break,
                }
            }
        });

        HttpClient {
            // connections: Arc::new(Mutex::new(HashMap::new())),
            // cookie_jar: CookieJar::new(),
            tx,
        }
    }

    async fn connect_inner(
        tls: bool,
        host: Host,
        addr: IpAddr,
        port: u16,
        client_config: Arc<ClientConfig>,
        server_name: &str,
        can_pipeline: bool,
        connections: &Arc<
            Mutex<
                Vec<(
                    Arc<HttpConnection>,
                    mpsc::Sender<(
                        Request,
                        mpsc::Sender<usize>,
                        oneshot::Sender<
                            Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>,
                        >,
                    )>,
                )>,
            >,
        >,
    ) -> Result<HttpConnectionHandle> {
        platform_log(
            LOG_TAG,
            format!(
                "connect_inner: {}/{}:{}",
                host.to_string(),
                addr.to_string(),
                &port
            ),
        );

        if tls {
            let (stream, cipher_id) =
                Self::connect_tls(addr, port, client_config, server_name).await?;
            let now = Instant::now();
            let conn = HttpConnection::new(host, port, cipher_id, can_pipeline, now);
            let conn = Arc::new(conn);
            let conn_ = Arc::clone(&conn);
            let req_tx = setup_http_connection(connections, &conn, stream);

            let handle = HttpConnectionHandle {
                cipher_id: conn.cipher_id,
                tx: req_tx.clone(),
            };

            let mut guard = connections.lock().unwrap();

            guard.push((conn, req_tx));

            setup_idle_timeout(&conn_, &connections, now);

            return Ok(handle);
        } else {
            let stream = Self::connect_tcp(addr, port).await?;
            let now = Instant::now();
            let conn = HttpConnection::new(host, port, None, can_pipeline, now);
            let conn = Arc::new(conn);
            let req_tx = setup_http_connection(connections, &conn, stream);
            let conn_ = Arc::clone(&conn);

            let handle = HttpConnectionHandle {
                cipher_id: conn.cipher_id,
                tx: req_tx.clone(),
            };

            let mut guard = connections.lock().unwrap();

            guard.push((conn, req_tx));

            setup_idle_timeout(&conn_, &connections, now);

            return Ok(handle);
        }
    }

    async fn connect_tcp(ip: IpAddr, port: u16) -> Result<ClientStream> {
        #[cfg(all(feature = "android", target_os = "android"))]
        match ClientStream::new_android(ip, port).await {
            Ok(client_stream) => Ok(client_stream),

            Err(e) => Err(ErrorKind::Stream(e)),
        }

        #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
        match ClientStream::new_ohos(ip, port).await {
            Ok(client_stream) => Ok(client_stream),

            Err(e) => Err(ErrorKind::Stream(e)),
        }

        #[cfg(not(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        )))]
        match ClientStream::new_tokio(ip, port).await {
            Ok(client_stream) => Ok(client_stream),

            Err(e) => Err(ErrorKind::Stream(e)),
        }
    }

    async fn connect_tls(
        ip: IpAddr,
        port: u16,
        client_config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<(ClientStream, Option<(u8, u8)>)> {
        #[cfg(all(feature = "android", target_os = "android"))]
        match ClientStream::new_android_ssl(ip, port, server_name).await {
            Ok(client_stream) => match client_stream.do_handshake().await {
                Ok((client_stream, cipher_id)) => {
                    platform_log(LOG_TAG, format!("ssl do_handshake success"));
                    Ok((client_stream, cipher_id))
                }
                Err(e) => {
                    platform_log(
                        LOG_TAG,
                        format!("ssl do_handshake failed with error {:?}", e),
                    );
                    Err(ErrorKind::Stream(e))
                }
            },

            Err(e) => {
                platform_log(LOG_TAG, format!("ssl new failed with error {:?}", e));
                Err(ErrorKind::Stream(e))
            }
        }

        #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
        match ClientStream::new_ohos_ssl(client_config, ip, port, server_name).await {
            Ok(client_stream) => match client_stream.do_handshake().await {
                Ok((client_stream, cipher_id)) => {
                    platform_log(LOG_TAG, format!("ssl do_handshake success"));
                    Ok((client_stream, cipher_id))
                }
                Err(e) => {
                    platform_log(
                        LOG_TAG,
                        format!("ssl do_handshake failed with error {:?}", e),
                    );
                    Err(ErrorKind::Stream(e))
                }
            },

            Err(e) => {
                platform_log(LOG_TAG, format!("ssl new failed with error {:?}", e));
                Err(ErrorKind::Stream(e))
            }
        }

        #[cfg(not(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        )))]
        match ClientStream::new_tokio_ssl(client_config, ip, port, server_name).await {
            Ok(client_stream) => match client_stream.do_handshake().await {
                Ok((client_stream, cipher_id)) => {
                    platform_log(LOG_TAG, format!("ssl do_handshake success"));
                    Ok((client_stream, cipher_id))
                }
                Err(e) => {
                    platform_log(
                        LOG_TAG,
                        format!("ssl do_handshake failed with error {:?}", e),
                    );
                    Err(ErrorKind::Stream(e))
                }
            },

            Err(e) => {
                platform_log(LOG_TAG, format!("ssl new failed with error {:?}", e));
                Err(ErrorKind::Stream(e))
            }
        }
    }

    pub async fn connect(&self, url: &Url, can_pipeline: bool) -> Result<HttpConnectionHandle> {
        if let Some(host) = url.host() {
            let tls = if url.scheme() == "https" { true } else { false };

            let port = if let Some(port_) = url.port() {
                port_
            } else {
                if tls {
                    443
                } else {
                    80
                }
            };

            match host {
                Host::Domain(domain) => {
                    let (request_tx, request_rx) =
                        oneshot::channel::<Result<HttpConnectionHandle>>();

                    match self
                        .tx
                        .send(ConnectMessage::Request(
                            tls,
                            Host::Domain(String::from(domain)),
                            port,
                            can_pipeline,
                            request_tx,
                        ))
                        .await
                    {
                        Ok(()) => request_rx.await.unwrap(),

                        Err(_) => Err(ErrorKind::BrokenPipe),
                    }
                }

                Host::Ipv4(ip) => {
                    let (request_tx, request_rx) =
                        oneshot::channel::<Result<HttpConnectionHandle>>();

                    match self
                        .tx
                        .send(ConnectMessage::Request(
                            tls,
                            Host::Ipv4(ip),
                            port,
                            can_pipeline,
                            request_tx,
                        ))
                        .await
                    {
                        Ok(()) => request_rx.await.unwrap(),

                        Err(_) => Err(ErrorKind::BrokenPipe),
                    }
                }

                Host::Ipv6(ip) => {
                    let (request_tx, request_rx) =
                        oneshot::channel::<Result<HttpConnectionHandle>>();

                    match self
                        .tx
                        .send(ConnectMessage::Request(
                            tls,
                            Host::Ipv6(ip),
                            port,
                            can_pipeline,
                            request_tx,
                        ))
                        .await
                    {
                        Ok(()) => request_rx.await.unwrap(),

                        Err(_) => Err(ErrorKind::BrokenPipe),
                    }
                }
            }
        } else {
            Err(ErrorKind::BadFormat)
        }
    }
}

pub enum ErrorKind {
    BadFormat,
    Dns,
    Stream(stream::ErrorKind),
    BrokenPipe,
    ConnectionLost,
    ProtocolError,
}

impl Copy for ErrorKind {}

impl Clone for ErrorKind {
    fn clone(&self) -> ErrorKind {
        *self
    }
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::BadFormat => {
                write!(f, "BadFormat")
            }

            ErrorKind::Dns => {
                write!(f, "Dns")
            }

            ErrorKind::Stream(e) => {
                write!(f, "Stream {:?}", e)
            }

            ErrorKind::BrokenPipe => {
                write!(f, "BrokenPipe")
            }

            ErrorKind::ConnectionLost => {
                write!(f, "ConnectionLost")
            }

            ErrorKind::ProtocolError => {
                write!(f, "ProtocolError")
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorKind>;

enum ConnectionState {
    Idle(Instant),
    Working(usize), // Working(transaction_count)
}

pub struct HttpConnection {
    debug_name: String,
    state: Arc<Mutex<ConnectionState>>,
    can_pipeline: bool,
    host: Host,
    port: u16,
    cipher_id: Option<(u8, u8)>,
}

impl HttpConnection {
    pub fn new(
        host: Host,
        port: u16,
        cipher_id: Option<(u8, u8)>,
        can_pipeline: bool,
        now: Instant,
    ) -> HttpConnection {
        let state = Arc::new(Mutex::new(ConnectionState::Idle(now)));
        HttpConnection {
            debug_name: Uuid::new_v4().to_string(),
            state,
            can_pipeline,
            host,
            port,
            cipher_id,
        }
    }
}

fn on_transaction_complete(
    state: &Arc<Mutex<ConnectionState>>,
    conn: &Arc<HttpConnection>,
    connections: &Arc<
        Mutex<
            Vec<(
                Arc<HttpConnection>,
                mpsc::Sender<(
                    Request,
                    mpsc::Sender<usize>,
                    oneshot::Sender<
                        Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>,
                    >,
                )>,
            )>,
        >,
    >,
) {
    platform_log(
        LOG_TAG,
        format!(
            "on_transaction_complete for http connection {}",
            conn.debug_name
        ),
    );
    let mut state = state.lock().unwrap();
    match &mut *state {
        ConnectionState::Idle(_) => panic!(""),
        ConnectionState::Working(transaction_count) => {
            if *transaction_count > 0 {
                *transaction_count -= 1;
                if *transaction_count == 0 {
                    platform_log(
                        LOG_TAG,
                        format!("http connection {} going idle", conn.debug_name),
                    );

                    let now = Instant::now();
                    *state = ConnectionState::Idle(now);

                    setup_idle_timeout(&conn, &connections, now);
                }
            } else {
                panic!("")
            }
        }
    }
}

fn setup_http_connection(
    connections: &Arc<
        Mutex<
            Vec<(
                Arc<HttpConnection>,
                mpsc::Sender<(
                    Request,
                    mpsc::Sender<usize>,
                    oneshot::Sender<
                        Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>,
                    >,
                )>,
            )>,
        >,
    >,
    conn: &Arc<HttpConnection>,
    stream: ClientStream,
) -> mpsc::Sender<(
    Request,
    mpsc::Sender<usize>,
    oneshot::Sender<Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>>,
)> {
    let debug_name_1 = String::from(&conn.debug_name);
    let debug_name_2 = String::from(&conn.debug_name);

    let connections_1 = Arc::clone(connections);
    let connections_2 = Arc::clone(connections);
    let conn_1 = Arc::clone(conn);
    let conn_2 = Arc::clone(conn);

    let state_1 = Arc::clone(&conn.state);
    let state_2 = Arc::clone(&conn.state);

    let (transaction_tx, mut transaction_rx) = mpsc::channel::<(
        &'static [u8],
        oneshot::Sender<Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>>,
    )>(MAX_CONCURRENT_REQUEST_IN_CONNECTIONS);

    let (rh, mut wh) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut resp_stream = ResponseStream::new(rh);

        loop {
            match resp_stream.next().await {
                Some(r) => match r {
                    ResponseOrAgain::Response(resp) => {
                        platform_log(LOG_TAG, format!("http connection {} on resp", debug_name_1));

                        let (req_method, resp_tx) = transaction_rx.recv().await.unwrap();

                        match resp_stream.setup_body_reading(req_method, &resp) {
                            Ok(data_rx) => {
                                if data_rx.is_none() {
                                    on_transaction_complete(&state_1, &conn_1, &connections_1);
                                }

                                match resp_tx.send(Ok((resp, data_rx))) {
                                    Ok(()) => {}

                                    Err(_) => {
                                        platform_log(
                                            LOG_TAG,
                                            "body reader dropped due to pipe error",
                                        );
                                        close_transaction_rx_and_quit(
                                            transaction_rx,
                                            ErrorKind::BrokenPipe,
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }

                            Err(e) => {
                                platform_log(
                                    LOG_TAG,
                                    format!("could not setup body reader due to error: {:?}", e),
                                );
                                close_transaction_rx_and_quit(
                                    transaction_rx,
                                    ErrorKind::BrokenPipe,
                                )
                                .await;
                                break;
                            }
                        }
                    }

                    ResponseOrAgain::Again(transaction_completed) => {
                        if transaction_completed {
                            on_transaction_complete(&state_1, &conn_1, &connections_1);
                        }
                    }
                },

                None => {
                    platform_log(LOG_TAG, format!("http connection {} closed", debug_name_1));
                    close_transaction_rx_and_quit(transaction_rx, ErrorKind::BrokenPipe).await;

                    let mut guard = connections_1.lock().unwrap();
                    let mut i = 0;
                    for (conn, _) in &mut *guard {
                        if Arc::ptr_eq(conn, &conn_1) {
                            let _ = (*guard).remove(i);
                            platform_log(
                                LOG_TAG,
                                format!("http connection {} removed", debug_name_1),
                            );
                            break;
                        }
                        i = i + 1;
                    }

                    break;
                }
            }
        }
    });

    let (req_tx, mut req_rx) = mpsc::channel::<(
        Request,
        mpsc::Sender<usize>,
        oneshot::Sender<Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>>,
    )>(MAX_CONCURRENT_REQUEST_IN_CONNECTIONS);

    tokio::spawn(async move {
        'next: loop {
            match req_rx.recv().await {
                Some((request, prog_tx, resp_tx)) => {
                    platform_log(
                        LOG_TAG,
                        format!(
                            "on_transaction_received over http connection {}",
                            debug_name_2
                        ),
                    );

                    {
                        let mut guard = state_2.lock().unwrap();

                        match &mut *guard {
                            ConnectionState::Idle(_) => {
                                *guard = ConnectionState::Working(1);
                            }
                            ConnectionState::Working(transaction_count) => {
                                *transaction_count += 1;
                            }
                        }
                    }

                    let data_size = request.estimated_size();
                    let mut data = Vec::with_capacity(data_size);
                    {
                        let mut readers = Vec::new();
                        request.get_readers(&mut readers);
                        let mut chain = DynamicChain::new(readers);
                        match chain.read_to_end(&mut data) {
                            Ok(_) => {}
                            Err(_) => {} // to-do: early failure
                        }
                    }

                    platform_log(
                        LOG_TAG,
                        format!("sending request {}", String::from_utf8_lossy(&data)),
                    );

                    let mut written = 0;
                    while written < data.len() {
                        match wh.write(&data[written..]).await {
                            Ok(size) => {
                                written = written + size;
                            }

                            Err(e) => {
                                platform_log(
                                    LOG_TAG,
                                    format!("socket write failed with error: {}", e),
                                );

                                match resp_tx.send(Err(ErrorKind::BrokenPipe)) {
                                    Ok(()) => {}
                                    Err(_) => {}
                                }
                                continue 'next;
                            }
                        }
                    }

                    if let Some(body) = request.body {
                        platform_log(LOG_TAG, "sending request body");

                        loop {
                            if let Ok(reader) = body.reader() {
                                let reader =
                                    ProgressReportingReader::new(reader, move |read| match prog_tx
                                        .try_send(read) // can drop a few progress reports, it's fine
                                    {
                                        Ok(()) => {}
                                        Err(e) => {}
                                    });

                                let mut reader = reader.compat();
                                match copy(&mut reader, &mut wh).await {
                                    Ok(i) => {
                                        platform_log(
                                            LOG_TAG,
                                            format!("written {} bytes of http body", i),
                                        );

                                        match wh.flush().await {
                                            Ok(()) => {
                                                platform_log(LOG_TAG, "wh flushed");
                                            }
                                            Err(e) => {
                                                platform_log(LOG_TAG, format!("wh error: {:?}", e));
                                            }
                                        }

                                        break;
                                    }

                                    Err(e) => {
                                        platform_log(
                                            LOG_TAG,
                                            format!("socket write failed with error: {}", e),
                                        );
                                    }
                                }
                            } else {
                                platform_log(LOG_TAG, "cannot create body reader");
                            }

                            match resp_tx.send(Err(ErrorKind::BrokenPipe)) {
                                Ok(()) => {}
                                Err(_) => {
                                    platform_log(LOG_TAG, "response dropped");
                                }
                            }

                            continue 'next;
                        }
                    }

                    match transaction_tx.send((request.method, resp_tx)).await {
                        Ok(()) => {}

                        Err(mpsc::error::SendError((_, tx))) => {
                            match tx.send(Err(ErrorKind::BrokenPipe)) {
                                Ok(()) => {}
                                Err(_) => {
                                    platform_log(LOG_TAG, "transaction not processed");
                                }
                            }
                        }
                    }
                }

                None => {
                    platform_log(
                        LOG_TAG,
                        format!("no more request on http connection {}", debug_name_2),
                    );
                    match wh.shutdown().await {
                        Ok(()) => platform_log(LOG_TAG, "write handle shutdown"),
                        Err(e) => {
                            platform_log(LOG_TAG, format!("write handle shutdown failed: {}", e))
                        }
                    }
                    break;
                }
            }
        }
    });

    req_tx
}

async fn close_transaction_rx_and_quit(
    mut transaction_rx: mpsc::Receiver<(
        &'static [u8],
        oneshot::Sender<Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>>,
    )>,
    error_kind: ErrorKind,
) {
    platform_log(LOG_TAG, "close_transaction_rx_and_quit()");

    transaction_rx.close();

    while let Some((_, response_tx)) = transaction_rx.recv().await {
        match response_tx.send(Err(error_kind)) {
            Ok(()) => {}

            Err(_) => {
                platform_log(LOG_TAG, "response dropped");
            }
        }
    }

    platform_log(LOG_TAG, "transactions cleared");
}

pub struct HttpConnectionHandle {
    cipher_id: Option<(u8, u8)>,
    tx: mpsc::Sender<(
        Request,
        mpsc::Sender<usize>,
        oneshot::Sender<Result<(Response, Option<mpsc::Receiver<io::Result<Vec<u8>>>>)>>,
    )>,
}

impl HttpConnectionHandle {
    pub fn cipher_id(&self) -> Option<(u8, u8)> {
        self.cipher_id
    }

    pub async fn send<F>(
        &self,
        mut request: Request,
        io_callback: F,
    ) -> Result<(Response, Option<Box<dyn AsyncBufRead + Send + Unpin>>)>
    where
        F: Fn(usize) + Send + Sync + 'static,
    {
        let (prog_tx, mut prog_rx) = mpsc::channel(1);
        let (resp_tx, resp_rx) = oneshot::channel();

        if request.body.is_none() {
            if let None = header::search(&request.headers, b"Content-Length", true) {
                request.headers.push(Header::new("Content-Length", "0"));
            }
        }

        tokio::spawn(async move {
            while let Some(written) = prog_rx.recv().await {
                io_callback(written);
            }
        });

        match self.tx.send((request, prog_tx, resp_tx)).await {
            Ok(()) => match resp_rx.await {
                Ok(result) => {
                    let (resp, data_rx) = result?;

                    platform_log(LOG_TAG, "resp transfered");

                    if let Some(data_rx) = data_rx {
                        let stream = ReceiverStream::new(data_rx);

                        platform_log(LOG_TAG, "converting data stream into async reader");

                        let reader = stream.into_async_read();

                        Ok((resp, Some(Box::new(reader))))
                    } else {
                        Ok((resp, None))
                    }
                }

                Err(_) => Err(ErrorKind::BrokenPipe),
            },

            Err(_) => Err(ErrorKind::BrokenPipe),
        }
    }
}
