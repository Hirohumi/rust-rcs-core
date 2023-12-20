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

extern crate hickory_client;
extern crate tokio;
extern crate tokio_stream;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time;
use tokio::time::{Duration, Instant};

use tokio_stream::wrappers::ReceiverStream;

use hickory_client::client::{AsyncClient, ClientHandle as _};
use hickory_client::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::udp::UdpClientStream;

use crate::ffi::log::platform_log;
use crate::util::raw_string::StrEq;

const LOG_TAG: &str = "dns";

const REQUEST_BUFFER_SIZE: usize = 16;

pub struct DnsConfig {
    pub server_addrs: Vec<SocketAddr>,
}

impl Clone for DnsConfig {
    fn clone(&self) -> Self {
        DnsConfig {
            server_addrs: self.server_addrs.clone(),
        }
    }
}

pub enum DnsRequest {
    Default(DnsConfig, String, mpsc::Sender<IpAddr>),
    SipNaptr(DnsConfig, String, String, mpsc::Sender<(String, u16)>),
}

pub struct DnsClient {
    tx: mpsc::Sender<DnsRequest>,
    cache_a_aaaa: Arc<Mutex<HashMap<String, Vec<(Instant, IpAddr)>>>>,
    cache_naptr_srv: Arc<Mutex<HashMap<String, Vec<(Instant, String, String, u16)>>>>,
}

impl DnsClient {
    pub fn new(rt: Arc<Runtime>) -> DnsClient {
        let (tx, mut rx) = mpsc::channel::<DnsRequest>(REQUEST_BUFFER_SIZE);

        let cache_a_aaaa: Arc<Mutex<HashMap<String, Vec<(Instant, IpAddr)>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let cache_a_aaaa_ = Arc::clone(&cache_a_aaaa);

        let cache_naptr_srv: Arc<Mutex<HashMap<String, Vec<(Instant, String, String, u16)>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let cache_naptr_srv_ = Arc::clone(&cache_naptr_srv);

        rt.spawn(async move {
            let cache_a_aaaa = cache_a_aaaa_;
            let cache_naptr_srv = cache_naptr_srv_;

            'next: loop {
                match rx.recv().await {
                    Some(dr) => {
                        match dr {
                            DnsRequest::Default(config, host, tx) => {

                                platform_log(LOG_TAG, "getting dns request");

                                let now = Instant::now();
                                let mut cached = Vec::new();

                                {
                                    let guard = cache_a_aaaa.lock().unwrap();

                                    if let Some(cached_addresses) = guard.get(&host) {
                                        for (expire, ip) in cached_addresses {
                                            if expire > &now {
                                                cached.push(*ip);
                                            }
                                        }
                                    }
                                }

                                if cached.is_empty() {
                                    let cache = Arc::clone(&cache_a_aaaa);

                                    platform_log(LOG_TAG, "start dns");

                                    tokio::spawn(async move {
                                        for server_addr in config.server_addrs {
                                            let stream = UdpClientStream::<UdpSocket>::new(server_addr);

                                            let mut successful = false;

                                            if let Ok((mut client, bg)) = AsyncClient::connect(stream).await
                                            {
                                                platform_log(LOG_TAG, "dns server connected");

                                                tokio::spawn(async move {
                                                    bg.await.unwrap();
                                                });

                                                if let Ok(name) = Name::from_str(&host) {
                                                    platform_log(LOG_TAG, "start AAAA query");

                                                    match time::timeout_at(
                                                        Instant::now() + Duration::from_secs(15),
                                                        client.query(name, DNSClass::IN, RecordType::AAAA),
                                                    )
                                                    .await
                                                    {
                                                        Ok(r) => {
                                                            if let Ok(resp) = r {
                                                                for r in resp.answers() {
                                                                    if let Some(&RData::AAAA(addr)) =
                                                                        r.data()
                                                                    {
                                                                        successful = true;

                                                                        let addr = IpAddr::V6(addr.0);
                                                                        let ttl = r.ttl();

                                                                        if ttl > 0 {
                                                                            update_a_aaaa_cache(
                                                                                &cache, addr, ttl, &host,
                                                                            );
                                                                        }

                                                                        match tx.send(addr).await {
                                                                            Ok(()) => {}

                                                                            Err(_) => {
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        Err(_) => {
                                                            platform_log(LOG_TAG, "dns timeout");
                                                        }
                                                    }
                                                }

                                                if let Ok(name) = Name::from_str(&host) {
                                                    platform_log(LOG_TAG, "start A query");

                                                    match time::timeout_at(
                                                        Instant::now() + Duration::from_secs(15),
                                                        client.query(name, DNSClass::IN, RecordType::A),
                                                    )
                                                    .await
                                                    {
                                                        Ok(r) => {
                                                            if let Ok(resp) = r {
                                                                for r in resp.answers() {
                                                                    if let Some(&RData::A(addr)) = r.data()
                                                                    {
                                                                        successful = true;

                                                                        let addr = IpAddr::V4(addr.0);
                                                                        let ttl = r.ttl();

                                                                        if ttl > 0 {
                                                                            update_a_aaaa_cache(
                                                                                &cache, addr, ttl, &host,
                                                                            );
                                                                        }

                                                                        match tx.send(addr).await {
                                                                            Ok(()) => {}

                                                                            Err(_) => {
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        Err(_) => {
                                                            platform_log(LOG_TAG, "dns timeout");
                                                        }
                                                    }
                                                }
                                            }

                                            if successful {
                                                return;
                                            }
                                        }
                                    });
                                } else {
                                    for addr in cached {
                                        match tx.send(addr).await {
                                            Ok(()) => {}

                                            Err(_) => {
                                                continue 'next;
                                            }
                                        }
                                    }
                                }
                            }

                            DnsRequest::SipNaptr(config, q_name, q_service_type, tx) => {

                                platform_log(LOG_TAG, "getting dns request");

                                let now = Instant::now();
                                let mut cached = Vec::new();

                                {
                                    let guard = cache_naptr_srv.lock().unwrap();

                                    if let Some(cached_addresses) = guard.get(&q_name) {
                                        for (expire, service_type, target, port) in cached_addresses {
                                            if expire > &now && q_service_type.eq(service_type) {
                                                cached.push((String::from(target), *port));
                                            }
                                        }
                                    }
                                }

                                if cached.is_empty() {

                                    let cache = Arc::clone(&cache_naptr_srv);

                                    tokio::spawn(async move {
                                        for server_addr in config.server_addrs {
                                            let stream = UdpClientStream::<UdpSocket>::new(server_addr);

                                            let mut successful = false;

                                            if let Ok((mut client, bg)) = AsyncClient::connect(stream).await
                                            {
                                                platform_log(LOG_TAG, "dns server connected");

                                                tokio::spawn(async move {
                                                    bg.await.unwrap();
                                                });

                                                if let Ok(name) = Name::from_str(&q_name) {
                                                    platform_log(LOG_TAG, "start NAPTR query");

                                                    match time::timeout_at(
                                                        Instant::now() + Duration::from_secs(15),
                                                        client.query(name, DNSClass::IN, RecordType::NAPTR),
                                                    )
                                                    .await
                                                    {
                                                        Ok(r) => {
                                                            if let Ok(resp) = r {
                                                                for r in resp.answers() {
                                                                    if let Some(rd) =
                                                                        r.data()
                                                                    {
                                                                        if let RData::NAPTR(ptr) = rd {

                                                                            if ptr.services().equals_string(&q_service_type, false) {

                                                                                let replacement = ptr.replacement().clone();

                                                                                platform_log(LOG_TAG, format!("naptr replacement: {:?}", &replacement));

                                                                                platform_log(LOG_TAG, "start SRV query");

                                                                                match time::timeout_at(
                                                                                    Instant::now() + Duration::from_secs(15),
                                                                                    client.query(replacement, DNSClass::IN, RecordType::SRV),
                                                                                )
                                                                                .await {
                                                                                    Ok(r) => {

                                                                                        if let Ok(resp) = r {
                                                                                            for r in resp.answers() {
                                                                                                if let Some(rd) =
                                                                                                    r.data()
                                                                                                {
                                                                                                    if let RData::SRV(srv) = rd {
                                                                                                        successful = true;

                                                                                                        let target = srv.target();
                                                                                                        platform_log(LOG_TAG, format!("srv target: {:?}", target));
                                                                                                        let target = target.to_string();
                                                                                                        let target = if target.ends_with('.') {
                                                                                                            String::from(&target[0..target.len() - 1])
                                                                                                        } else {
                                                                                                            target
                                                                                                        };
                                                                                                        let port = srv.port();

                                                                                                        let ttl = r.ttl();

                                                                                                        if ttl > 0 {
                                                                                                            update_naptr_srv_cache(
                                                                                                                &cache, &target, port, ttl, &q_name, &q_service_type,
                                                                                                            );
                                                                                                        }

                                                                                                        match tx.send((target, port)).await {
                                                                                                            Ok(()) => {}

                                                                                                            Err(_) => {
                                                                                                                return;
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }

                                                                                    Err(_) => {
                                                                                        platform_log(LOG_TAG, "dns timeout");
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        Err(_) => {
                                                            platform_log(LOG_TAG, "dns timeout");
                                                        }
                                                    }
                                                }
                                            }

                                            if successful {
                                                return;
                                            }
                                        }
                                    });

                                } else {
                                    for res in cached {
                                        match tx.send(res).await {
                                            Ok(()) => {}

                                            Err(_) => {
                                                continue 'next;
                                            }
                                        }
                                    }
                                }
                            }

                        }
                    },
                    None => break,
                }
            }
        });

        DnsClient {
            tx,
            cache_a_aaaa,
            cache_naptr_srv,
        }
    }

    pub async fn resolve(
        &self,
        dns_config: DnsConfig,
        host: String,
    ) -> Result<ReceiverStream<IpAddr>> {
        let (tx, rx) = mpsc::channel::<IpAddr>(1);

        match self
            .tx
            .send(DnsRequest::Default(dns_config, host, tx))
            .await
        {
            Ok(()) => Ok(ReceiverStream::new(rx)),

            Err(_) => Err(ErrorKind::BrokenPipe),
        }
    }

    pub async fn resolve_service(
        &self,
        dns_config: DnsConfig,
        domain: String,
        service_name: String,
    ) -> Result<ReceiverStream<(String, u16)>> {
        let (tx, rx) = mpsc::channel::<(String, u16)>(1);

        match self
            .tx
            .send(DnsRequest::SipNaptr(dns_config, domain, service_name, tx))
            .await
        {
            Ok(()) => Ok(ReceiverStream::new(rx)),

            Err(_) => Err(ErrorKind::BrokenPipe),
        }
    }

    pub fn clear_cache(&self, name: String, rtype: RecordType) {
        match rtype {
            RecordType::A | RecordType::AAAA => {
                let mut guard = self.cache_a_aaaa.lock().unwrap();

                if let Some(cached_addresses) = guard.get_mut(&name) {
                    let mut i = 0;
                    while i < cached_addresses.len() {
                        let (_, ip) = cached_addresses[i];
                        match (ip, rtype) {
                            (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA) => {
                                cached_addresses.swap_remove(i);
                            }

                            _ => {
                                i = i + 1;
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }

    pub fn clear_naptr_srv_cache(&self, q_name: String, q_service_type: String) {
        let mut guard = self.cache_naptr_srv.lock().unwrap();

        if let Some(cached_addresses) = guard.get_mut(&q_name) {
            let mut i = 0;
            while i < cached_addresses.len() {
                let (_, service_type, _, _) = &cached_addresses[i];
                if q_service_type.eq(service_type) {
                    cached_addresses.swap_remove(i);
                } else {
                    i = i + 1;
                }
            }
        }
    }
}

fn update_a_aaaa_cache(
    cache: &Arc<Mutex<HashMap<String, Vec<(Instant, IpAddr)>>>>,
    addr: IpAddr,
    ttl: u32,
    host: &String,
) {
    let mut guard = cache.lock().unwrap();

    let now = Instant::now();
    let expire = now + Duration::from_secs(ttl.into());
    if let Some(ref mut cached_addresses) = guard.get_mut(host) {
        for (e, ip) in cached_addresses.iter_mut() {
            match (*ip, addr) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                    *e = expire;
                    *ip = addr;
                    return;
                }

                _ => {}
            }
        }

        cached_addresses.push((expire, addr));
    } else {
        let mut cached_addresses = Vec::new();
        cached_addresses.push((expire, addr));
        guard.insert(String::from(host), cached_addresses);
    }
}

fn update_naptr_srv_cache(
    cache: &Arc<Mutex<HashMap<String, Vec<(Instant, String, String, u16)>>>>,
    r_target: &String,
    r_port: u16,
    ttl: u32,
    q_name: &String,
    q_service_type: &String,
) {
    let mut guard = cache.lock().unwrap();

    let now = Instant::now();
    let expire = now + Duration::from_secs(ttl.into());
    if let Some(ref mut cached_addresses) = guard.get_mut(q_name) {
        for (e, service_type, target, port) in cached_addresses.iter_mut() {
            if q_service_type.eq(service_type) {
                *e = expire;
                *target = r_target.clone();
                *port = r_port;
                return;
            }
        }

        cached_addresses.push((
            expire,
            String::from(q_service_type),
            String::from(r_target),
            r_port,
        ));
    } else {
        let mut cached_addresses = Vec::new();
        cached_addresses.push((
            expire,
            String::from(q_service_type),
            String::from(r_target),
            r_port,
        ));
        guard.insert(String::from(q_name), cached_addresses);
    }
}

pub enum ErrorKind {
    BrokenPipe,
}

impl Copy for ErrorKind {}

impl Clone for ErrorKind {
    fn clone(&self) -> ErrorKind {
        *self
    }
}

pub type Result<T> = std::result::Result<T, ErrorKind>;
