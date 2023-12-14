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

extern crate base64;
extern crate chrono;
extern crate futures;
extern crate quick_xml;
extern crate ring;
extern crate tokio;
extern crate url;

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, FixedOffset};

use data_encoding::HEXUPPER;
use futures::io::{AsyncBufRead, AsyncReadExt};

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use ring::hmac;

use tokio::sync::Semaphore;
use tokio::time::{self, Duration, Instant};

use url::{Host, Url};

use crate::ffi::log::platform_log;
use crate::http::request::{Request, GET};
use crate::http::response::Response;
use crate::http::{HttpClient, HttpConnectionHandle};

use crate::internet::header::{self, Header};

use crate::internet::syntax;
use crate::security::aka::{self, AkaChallenge, AkaResponse, AsAkaAlgorithm};
use crate::security::authentication::{AuthenticationMethod, AuthenticationMethods};
use crate::security::SecurityContext;

use crate::util::rand;
use crate::util::raw_string::FromRawStr;

use super::authentication::digest::{DigestAnswerParams, DigestCredentials};

const LOG_TAG: &str = "gba";

pub struct GbaContext {
    impi: String,
    bsf_url: String,
    bsf_realm: String,

    subscription_id: i32,

    bootstrapped_context: UnsafeCell<Option<Arc<BootstrappedContext>>>,
    bootstrap_sem: Semaphore,
}

impl GbaContext {
    pub fn new(
        impi: String,
        bsf_url: String,
        bsf_realm: String,
        subscription_id: i32,
    ) -> GbaContext {
        platform_log(
            LOG_TAG,
            format!(
                "init GbaContext with url: {}, realm: {}",
                &bsf_url, &bsf_realm
            ),
        );

        GbaContext {
            impi,
            bsf_url,
            bsf_realm,

            subscription_id,

            bootstrapped_context: None.into(),
            bootstrap_sem: Semaphore::new(1),
        }
    }

    pub fn try_get_bootstrapped_context(&self) -> Option<Arc<BootstrappedContext>> {
        match self.bootstrap_sem.try_acquire() {
            Ok(_permit) => {
                let cell;
                unsafe {
                    cell = &*self.bootstrapped_context.get();
                }
                if let Some(bootstrapped_context) = cell {
                    if bootstrapped_context.expires > Instant::now() {
                        return Some(Arc::clone(&bootstrapped_context));
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    pub async fn get_bootstrapped_context(
        &self,
        http_client: &HttpClient,
    ) -> Result<Arc<BootstrappedContext>, ErrorKind> {
        platform_log(LOG_TAG, "get_bootstrapped_context");
        match time::timeout_at(
            Instant::now() + Duration::from_secs(60),
            self.bootstrap(http_client),
        )
        .await
        {
            Ok(context) => context,

            Err(_) => Err(ErrorKind::TimeOut),
        }
    }

    async fn bootstrap(
        &self,
        http_client: &HttpClient,
    ) -> Result<Arc<BootstrappedContext>, ErrorKind> {
        platform_log(LOG_TAG, "bootstrap");
        match self.bootstrap_sem.acquire().await {
            Ok(_permit) => {
                platform_log(LOG_TAG, "permit acquired");

                let cell;
                unsafe {
                    cell = &*self.bootstrapped_context.get();
                }

                if let Some(bootstrapped_context) = cell {
                    if bootstrapped_context.expires > Instant::now() {
                        return Ok(Arc::clone(&bootstrapped_context));
                    }
                }

                let bsf_url = format!("http://{}/", &self.bsf_url);

                if let Ok(url) = Url::parse(&bsf_url) {
                    match http_client.connect(&url, false).await {
                        Ok(conn) => {
                            let mut digest_answer = DigestAnswerParams {
                                realm: self.bsf_realm.as_bytes().to_vec(),
                                algorithm: None,

                                username: self.impi.as_bytes().to_vec(),
                                uri: b"".to_vec(),

                                challenge: None,

                                credentials: None,
                            };

                            if let Ok(authorization) =
                                digest_answer.make_authorization_header(None, true, true)
                            {
                                let (resp, resp_stream) =
                                    send_ub_message(&conn, &url, authorization).await?;

                                platform_log(LOG_TAG, format!("ub status {}", resp.status_code));

                                match decode_ub_resp(
                                    &mut digest_answer,
                                    resp,
                                    resp_stream,
                                    self.impi.as_bytes(),
                                    b"\"/\"",
                                    self.subscription_id,
                                )
                                .await
                                {
                                    UbResult::Res(authorization, rand, mut ck, mut ik) => {
                                        let (resp, resp_stream) =
                                            send_ub_message(&conn, &url, authorization).await?;

                                        platform_log(
                                            LOG_TAG,
                                            format!("ub status {}", resp.status_code),
                                        );

                                        match decode_ub_resp(
                                            &mut digest_answer,
                                            resp,
                                            resp_stream,
                                            self.impi.as_bytes(),
                                            b"\"/\"",
                                            self.subscription_id,
                                        )
                                        .await
                                        {
                                            UbResult::Bootstrapped(b_tid, expiry) => {
                                                ck.append(&mut ik);

                                                let bootstrapped_context = BootstrappedContext {
                                                    impi: self.impi.clone(),
                                                    rand,
                                                    ks: ck,
                                                    b_tid,
                                                    expires: expiry,
                                                    used_count: AtomicU32::new(0),
                                                };

                                                let bootstrapped_context =
                                                    Arc::new(bootstrapped_context);

                                                let cell;
                                                unsafe {
                                                    cell = &mut *self.bootstrapped_context.get();
                                                }

                                                cell.replace(Arc::clone(&bootstrapped_context));

                                                return Ok(bootstrapped_context);
                                            }

                                            _ => {}
                                        }
                                    }

                                    UbResult::Auts(authorization) => {
                                        platform_log(LOG_TAG, "on AUTS response");

                                        let (resp, resp_stream) =
                                            send_ub_message(&conn, &url, authorization).await?;

                                        platform_log(
                                            LOG_TAG,
                                            format!("ub status {}", resp.status_code),
                                        );

                                        match decode_ub_resp(
                                            &mut digest_answer,
                                            resp,
                                            resp_stream,
                                            self.impi.as_bytes(),
                                            b"\"/\"",
                                            self.subscription_id,
                                        )
                                        .await
                                        {
                                            UbResult::Res(authorization, rand, mut ck, mut ik) => {
                                                let (resp, resp_stream) =
                                                    send_ub_message(&conn, &url, authorization)
                                                        .await?;

                                                platform_log(
                                                    LOG_TAG,
                                                    format!("ub status {}", resp.status_code),
                                                );

                                                match decode_ub_resp(
                                                    &mut digest_answer,
                                                    resp,
                                                    resp_stream,
                                                    self.impi.as_bytes(),
                                                    b"\"/\"",
                                                    self.subscription_id,
                                                )
                                                .await
                                                {
                                                    UbResult::Bootstrapped(b_tid, expiry) => {
                                                        ck.append(&mut ik);

                                                        let bootstrapped_context =
                                                            BootstrappedContext {
                                                                impi: self.impi.clone(),
                                                                rand,
                                                                ks: ck,
                                                                b_tid,
                                                                expires: expiry,
                                                                used_count: AtomicU32::new(0),
                                                            };

                                                        let bootstrapped_context =
                                                            Arc::new(bootstrapped_context);

                                                        let cell;
                                                        unsafe {
                                                            cell = &mut *self
                                                                .bootstrapped_context
                                                                .get();
                                                        }

                                                        cell.replace(Arc::clone(
                                                            &bootstrapped_context,
                                                        ));

                                                        return Ok(bootstrapped_context);
                                                    }

                                                    _ => {}
                                                }
                                            }

                                            _ => {}
                                        }
                                    }

                                    _ => {}
                                }
                            }

                            Err(ErrorKind::Authentication)
                        }

                        Err(e) => {
                            platform_log(LOG_TAG, format!("http error {:?}", e));

                            Err(ErrorKind::ConnectionClosed)
                        }
                    }
                } else {
                    Err(ErrorKind::Http)
                }
            }

            Err(_) => Err(ErrorKind::Closed),
        }
    }
}

unsafe impl Send for GbaContext {}
unsafe impl Sync for GbaContext {}

async fn send_ub_message(
    connection: &HttpConnectionHandle,
    url: &Url,
    authorization: Vec<u8>,
) -> Result<(Response, Option<Box<dyn AsyncBufRead + Send + Unpin>>), ErrorKind> {
    let host = url.host_str().unwrap();

    let host = match url.host() {
        Some(Host::Domain(domain)) => String::from(domain),

        Some(Host::Ipv4(ip)) => ip.to_string(),

        Some(Host::Ipv6(ip)) => ip.to_string(),

        None => String::from(host),
    };

    let mut req = Request::new_with_default_headers(GET, &host, "/", None);

    req.headers
        .push(Header::new(b"Authorization", authorization));

    match connection.send(req, |_| {}).await {
        Ok((resp, resp_stream)) => Ok((resp, resp_stream)),

        Err(_) => Err(ErrorKind::Http),
    }
}

enum UbResult {
    Bootstrapped(String, Instant),
    Res(Vec<u8>, [u8; 16], Vec<u8>, Vec<u8>),
    Auts(Vec<u8>),
    Error(ErrorKind),
}

async fn decode_ub_resp<'a>(
    digest_answer: &'a mut DigestAnswerParams,
    resp: Response,
    resp_stream: Option<Box<dyn AsyncBufRead + Send + Unpin>>,
    impi: &'a [u8],
    uri: &'a [u8],
    subscription_id: i32,
) -> UbResult {
    platform_log(LOG_TAG, "decode_ub_resp");
    let status_code = resp.status_code;
    if status_code == 200 {
        if let Some(mut resp_stream) = resp_stream {
            let mut resp_data = Vec::new();
            if let Ok(_) = resp_stream.read_to_end(&mut resp_data).await {
                if let Ok(resp_str) = std::str::from_utf8(&resp_data) {
                    platform_log(LOG_TAG, format!("ub resp.string = {:?}", resp_str,));

                    let mut xml_reader = Reader::from_str(resp_str);
                    let mut buf = Vec::new();
                    loop {
                        match xml_reader.read_event_into(&mut buf) {
                            Ok(Event::Start(ref e)) => {
                                if e.name().as_ref() == b"BootstrappingInfo" {
                                    let mut b_tid: Option<String> = None;
                                    let mut expiry: Option<DateTime<FixedOffset>> = None;
                                    let mut level = 1;
                                    loop {
                                        match xml_reader.read_event_into(&mut buf) {
                                            Ok(Event::Start(ref e)) => {
                                                if e.name().as_ref() == b"btid" {
                                                    let mut level = 1;
                                                    loop {
                                                        match xml_reader.read_event_into(&mut buf) {
                                                            Ok(Event::Text(e)) => {
                                                                if level == 1 {
                                                                    if let Ok(t) = e.unescape() {
                                                                        b_tid.replace(
                                                                            t.into_owned(),
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Ok(Event::Start(_)) => level += 1,
                                                            Ok(Event::End(_)) => {
                                                                level -= 1;
                                                                if level == 0 {
                                                                    break;
                                                                }
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                    buf.clear();
                                                } else if e.name().as_ref() == b"lifetime" {
                                                    let mut level = 1;
                                                    loop {
                                                        match xml_reader.read_event_into(&mut buf) {
                                                            Ok(Event::Text(e)) => {
                                                                if level == 1 {
                                                                    if let Ok(t) = e.unescape() {
                                                                        if let Ok(lifetime) =
                                                                            DateTime::parse_from_rfc3339(
                                                                                &t,
                                                                            )
                                                                        {
                                                                            expiry.replace(lifetime);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Ok(Event::Start(_)) => level += 1,
                                                            Ok(Event::End(_)) => {
                                                                level -= 1;
                                                                if level == 0 {
                                                                    break;
                                                                }
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                    buf.clear();
                                                }
                                            }
                                            Ok(Event::End(ref e)) => {
                                                level -= 1;
                                                if level == 0 {
                                                    break;
                                                }
                                            }
                                            Ok(Event::Eof) => break,
                                            _ => {}
                                        }
                                    }

                                    buf.clear();

                                    if let (Some(b_tid), Some(expiry)) = (b_tid, expiry) {
                                        let expiry = SystemTime::UNIX_EPOCH
                                            + std::time::Duration::from_secs(
                                                expiry.timestamp() as u64
                                            );
                                        if let Ok(timeout) =
                                            expiry.duration_since(SystemTime::now())
                                        {
                                            let expiry = std::time::Instant::now() + timeout;
                                            let expiry = Instant::from_std(expiry);
                                            return UbResult::Bootstrapped(b_tid, expiry);
                                        }
                                    }
                                }
                            }
                            Ok(Event::Eof) => break,
                            _ => {}
                        }
                    }
                }
            }
        }
    } else if status_code == 401 {
        if let Some(www_authenticate_header) =
            header::search(&resp.headers, b"WWW-Authenticate", false)
        {
            let www_authenticate_header_value = www_authenticate_header.get_value();
            for method in AuthenticationMethods::new(www_authenticate_header_value) {
                if let AuthenticationMethod::Digest(challenge_params) = method {
                    if let Ok(algorithm) = challenge_params.algorithm.as_aka_algorithm() {
                        if let Ok(aka_challenge) =
                            AkaChallenge::from_raw_str(challenge_params.nonce)
                        {
                            digest_answer.challenge = Some(challenge_params.to_challenge());

                            // to-do: can we really do this ?
                            if digest_answer.uri.len() == 0 {
                                digest_answer.uri = b"/".to_vec();
                            }

                            if let Ok(response) =
                                aka::aka_do_challenge(&aka_challenge, subscription_id)
                            {
                                match response {
                                    AkaResponse::Successful(res, Some((ck, ik))) => {
                                        let cnonce = rand::create_raw_alpha_numeric_string(16);
                                        digest_answer.credentials = Some(DigestCredentials {
                                            password: res,
                                            client_data: Some(b"GET".to_vec()),
                                            client_nonce: Some((cnonce, 1)),
                                            entity_digest: None,
                                            extra_params: Vec::new(),
                                        });
                                        if let Ok(authorization) = digest_answer
                                            .make_authorization_header(
                                                Some(algorithm.algorithm),
                                                false,
                                                false,
                                            )
                                        {
                                            return UbResult::Res(
                                                authorization,
                                                aka_challenge.rand,
                                                ck,
                                                ik,
                                            );
                                        }
                                    }

                                    AkaResponse::SyncFailure(auts) => {
                                        let cnonce = rand::create_raw_alpha_numeric_string(16);
                                        digest_answer.credentials = Some(DigestCredentials {
                                            password: b"".to_vec(),
                                            client_data: Some(b"GET".to_vec()),
                                            client_nonce: Some((cnonce, 1)),
                                            entity_digest: None,
                                            extra_params: Vec::new(),
                                        });
                                        if let Ok(mut authorization) = digest_answer
                                            .make_authorization_header(
                                                Some(algorithm.algorithm),
                                                false,
                                                false,
                                            )
                                        {
                                            authorization.extend_from_slice(b",auts=\"");
                                            let encoded = general_purpose::STANDARD.encode(&auts);
                                            let mut encoded = Vec::from(encoded);
                                            authorization.append(&mut encoded);
                                            authorization.extend_from_slice(b"\"");
                                            return UbResult::Auts(authorization);
                                        }
                                    }

                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }

            return UbResult::Error(ErrorKind::Authentication);
        }
    }

    UbResult::Error(ErrorKind::Http)
}

pub struct BootstrappedContext {
    pub impi: String,
    pub rand: [u8; 16],
    pub ks: Vec<u8>,
    pub b_tid: String,
    pub expires: Instant,
    pub used_count: AtomicU32, // CAUTION: NC IS CURRENTLY ASSOCIATED WITH nonce USED IN BSF BOOTSTRAP UNDER ZTE 5G DEPLOYMENT
}

impl BootstrappedContext {
    pub fn get_credential(
        &self,
        fqdn: &[u8],
        cipher_id: Option<(u8, u8)>,
    ) -> Result<GbaCredential, ErrorKind> {
        let naf_id = gba_get_naf_id(fqdn, cipher_id);

        let ks_naf = gba_me_ks_naf(&self.ks, &self.rand, self.impi.as_bytes(), &naf_id)?;
        let ks_naf_hex = HEXUPPER.encode(&ks_naf);
        platform_log(LOG_TAG, format!("ks_naf_hex: {}", &ks_naf_hex));

        let encoded = general_purpose::STANDARD.encode(&ks_naf);
        let encoded = Vec::from(encoded);

        Ok(GbaCredential {
            username: self.b_tid.as_bytes().to_vec(),
            password: encoded,
        })
    }

    pub fn increase_and_get_use_count(&self) -> u32 {
        self.used_count.fetch_add(1, Ordering::SeqCst)
    }
}

fn gba_kdf(ks: &[u8], p0: &[u8], p1: &[u8], p2: &[u8], p3: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    if p0.len() < 256 && p1.len() < 256 && p2.len() < 256 && p3.len() < 65536 {
        let mut message = Vec::with_capacity(p0.len() + p1.len() + p2.len() + p3.len() + 9);

        message.push(1);

        message.extend_from_slice(p0);
        message.push(0);
        message.push(p0.len() as u8);

        message.extend_from_slice(p1);
        message.push(0);
        message.push(p1.len() as u8);

        let p2_len = (p2.len() as u16).to_be_bytes();

        message.extend_from_slice(p2);
        message.push(p2_len[0]);
        message.push(p2_len[1]);

        message.extend_from_slice(p3);

        let p3_len = (p3.len() as u16).to_be_bytes();

        message.push(p3_len[0]);
        message.push(p3_len[1]);

        let key = hmac::Key::new(hmac::HMAC_SHA256, ks);

        let signature = hmac::sign(&key, &message);

        return Ok(signature.as_ref().to_vec());
    }

    Err(ErrorKind::BadInput)
}

fn gba_me_ks_naf(ks: &[u8], rand: &[u8], impi: &[u8], naf_id: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    gba_kdf(ks, b"gba-me", rand, impi, naf_id)
}

fn gba_get_naf_id(fqdn: &[u8], cipher_id: Option<(u8, u8)>) -> Vec<u8> {
    let mut naf_id = Vec::with_capacity(fqdn.len() + 5);

    naf_id.extend_from_slice(fqdn);

    if let Some((yy, zz)) = cipher_id {
        naf_id.push(0x01);
        naf_id.push(0x00);
        naf_id.push(0x01);
        naf_id.push(yy);
        naf_id.push(zz);
    } else {
        naf_id.push(0x01);
        naf_id.push(0x00);
        naf_id.push(0x00);
        naf_id.push(0x00);
        naf_id.push(0x02);
    }

    naf_id
}

pub struct GbaCredential {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

const UA_BOOTSTRAPPING_REQUIRED_INDICATION_AKA_ME: &[u8] = b"3GPP-bootstrapping";

const UA_BOOTSTRAPPING_REQUIRED_INDICATION_AKA_UICC: &[u8] = b"3GPP-bootstrapping-uicc";

const UA_BOOTSTRAPPING_REQUIRED_INDICATION_GBA_DIGEST: &[u8] = b"3GPP-bootstrapping-digest";

pub enum GbaRealm<'a> {
    Me(&'a [u8]),
    Uicc(&'a [u8]),
    Digest(&'a [u8]),
}

pub fn get_gba_realm<'a>(realm: &'a [u8]) -> Option<GbaRealm<'a>> {
    if let Some(idx) = realm.iter().position(|c| *c == b'@') {
        match &realm[..idx] {
            UA_BOOTSTRAPPING_REQUIRED_INDICATION_AKA_ME => {
                return Some(GbaRealm::Me(&realm[idx + 1..]));
            }

            UA_BOOTSTRAPPING_REQUIRED_INDICATION_AKA_UICC => {
                return Some(GbaRealm::Uicc(&realm[idx + 1..]));
            }

            UA_BOOTSTRAPPING_REQUIRED_INDICATION_GBA_DIGEST => {
                return Some(GbaRealm::Digest(&realm[idx + 1..]));
            }

            _ => {}
        }
    }

    None
}

pub async fn try_process_401_response(
    context: &GbaContext,
    fqdn: &[u8],
    cipher_id: Option<(u8, u8)>,
    method: &[u8],
    resource_uri: &[u8],
    body_digest: Option<&[u8]>,
    www_authenticate_header: &Header,
    http_client: &HttpClient,
    security_context: &SecurityContext,
) -> Option<Result<DigestAnswerParams, ErrorKind>> {
    platform_log(LOG_TAG, "on 401");

    let www_authenticate_header_value = www_authenticate_header.get_value();
    for auth_method in AuthenticationMethods::new(www_authenticate_header_value) {
        if let AuthenticationMethod::Digest(challenge_params) = auth_method {
            if let Some(gba_realm) = get_gba_realm(challenge_params.realm) {
                platform_log(LOG_TAG, "is GBA bootstrap response");

                match gba_realm {
                    GbaRealm::Me(gba_fqdn) => {
                        if gba_fqdn == fqdn {
                            match context.get_bootstrapped_context(http_client).await {
                                Ok(bootstrapped_context) => {
                                    if let Ok(credential) =
                                        bootstrapped_context.get_credential(fqdn, cipher_id)
                                    {
                                        let challenge = challenge_params.to_challenge();

                                        let cnonce = rand::create_raw_alpha_numeric_string(16);
                                        let nc = bootstrapped_context.increase_and_get_use_count();

                                        let digest_answer = DigestAnswerParams {
                                            realm: syntax::unquote(resource_uri).to_vec(),
                                            algorithm: Some(challenge_params.algorithm.to_vec()),

                                            username: credential.username,
                                            uri: syntax::unquote(resource_uri).to_vec(),

                                            challenge: Some(challenge),

                                            credentials: Some(DigestCredentials {
                                                password: credential.password,
                                                client_data: Some(method.to_vec()),
                                                client_nonce: Some((cnonce, nc)),
                                                entity_digest: match body_digest {
                                                    Some(body_digest) => Some(body_digest.to_vec()),
                                                    None => None,
                                                },
                                                extra_params: Vec::new(),
                                            }),
                                        };

                                        return Some(Ok(digest_answer));
                                    }
                                }

                                Err(e) => {
                                    return Some(Err(e));
                                }
                            }
                        } else {
                            platform_log(LOG_TAG, format!("bootstrap indicated fqdn {:?} which is different from {:?} we requested", std::str::from_utf8(gba_fqdn), std::str::from_utf8(fqdn)));
                        }

                        return Some(Err(ErrorKind::Authentication));
                    }

                    _ => {
                        return Some(Err(ErrorKind::Authentication));
                    }
                }
            }
        }
    }

    None
}

pub enum ErrorKind {
    TimeOut,
    Closed,
    ConnectionClosed,
    Http,
    Authentication,
    BadInput,
    Hmac,
}
