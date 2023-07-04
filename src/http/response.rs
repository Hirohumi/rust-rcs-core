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

extern crate futures;
extern crate httparse;
extern crate tokio;
extern crate tokio_util;

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::Future;
use futures::AsyncReadExt;

use httparse::Response as HttpResponse;

use libc::c_void;
use tokio::io::{AsyncRead, ReadBuf, ReadHalf};
use tokio::sync::mpsc;

use tokio_util::sync::PollSender;

use crate::ffi::log::platform_log;

use crate::internet::header::Header;
use crate::internet::syntax;
use crate::internet::AsHeaderField;

use crate::io::network::stream::ClientStream;

use crate::util::raw_string::{StrEq, ToInt};

use super::decode::{
    ChunkDecodeResult, ChunkDecoder, ErrorKind, HeaderPartDecodeStatus, HeaderPartDecoder, Result,
};

use super::decompress::Decompressor;

const LOG_TAG: &str = "http_client_decode";

pub struct Response {
    pub status_code: u16,
    pub reason_phrase: Vec<u8>,
    pub headers: Vec<Header>,
}

impl Response {
    pub fn from(resp: &HttpResponse) -> Option<Response> {
        if let (Some(code), Some(reason)) = (resp.code, resp.reason) {
            platform_log(LOG_TAG, format!("{} {} HTTP/1.1", code, reason));
            let mut headers = Vec::new();

            for h in &*resp.headers {
                platform_log(
                    LOG_TAG,
                    format!("{}: {}", h.name, String::from_utf8_lossy(h.value)),
                );
                headers.push(Header::new(String::from(h.name), h.value.to_vec()));
            }

            return Some(Response {
                status_code: code,
                reason_phrase: reason.as_bytes().to_vec(),
                headers,
            });
        }

        None
    }

    pub fn get_response_transfer_method(
        &self,
        req_method: &[u8],
    ) -> Result<Option<TransferMethod>> {
        if req_method == b"HEAD"
            || self.status_code < 200
            || self.status_code == 204
            || self.status_code == 304
        {
            return Ok(None);
        }

        if req_method == b"CONNECT" && self.status_code >= 200 && self.status_code < 300 {
            return Ok(None);
        }

        let mut method = TransferMethod::Unbounded;

        for header in &self.headers {
            if header.get_name().equals_bytes(b"Content-Length", true) {
                if let Ok(i) = header.get_value().to_int() {
                    match method {
                        TransferMethod::Sized(_) | TransferMethod::Chunked(_) => {
                            return Err(ErrorKind::Parse);
                        }
                        TransferMethod::Unbounded => {
                            method = TransferMethod::Sized(SizedTransferEncoding::Plain(i));
                        }
                    }
                }
            } else if header.get_name().equals_bytes(b"Transfer-Encoding", true) {
                let header_field = header.get_value().as_header_field();
                let mut iter = header_field.value.split(|c| *c == b',');
                while let Some(value) = iter.next() {
                    let value = syntax::trim(value);
                    if value.equals_bytes(b"chunked", true) {
                        match &mut method {
                            TransferMethod::Sized(encoding) => match encoding {
                                SizedTransferEncoding::Plain(_) => {
                                    return Err(ErrorKind::Parse);
                                }

                                SizedTransferEncoding::Encoded(ref mut encodings) => {
                                    let mut v = Vec::new();
                                    v.append(encodings);
                                    method = TransferMethod::Chunked(
                                        ChunkedTransferEncoding::Encoded(v),
                                    );
                                }
                            },

                            TransferMethod::Chunked(_) => {
                                return Err(ErrorKind::Parse);
                            }

                            TransferMethod::Unbounded => {
                                method = TransferMethod::Chunked(ChunkedTransferEncoding::Plain);
                            }
                        }
                    } else if value.equals_bytes(b"br", true)
                        || value.equals_bytes(b"compress", true)
                        || value.equals_bytes(b"deflate", true)
                        || value.equals_bytes(b"gzip", true)
                    {
                        match &mut method {
                            TransferMethod::Sized(encoding) => match encoding {
                                SizedTransferEncoding::Plain(_) => {
                                    return Err(ErrorKind::Parse);
                                }

                                SizedTransferEncoding::Encoded(ref mut encodings) => {
                                    if value.equals_bytes(b"compress", true) {
                                        encodings.push(Encoding::Compress);
                                    } else if value.equals_bytes(b"deflate", true) {
                                        encodings.push(Encoding::Deflate);
                                    } else if value.equals_bytes(b"gzip", true) {
                                        encodings.push(Encoding::Gzip);
                                    } else {
                                        panic!("Impossible Condition");
                                    }
                                }
                            },

                            TransferMethod::Chunked(_) => {
                                return Err(ErrorKind::Parse);
                            }

                            TransferMethod::Unbounded => {
                                let mut v = Vec::new();
                                if value.equals_bytes(b"compress", true) {
                                    v.push(Encoding::Compress);
                                } else if value.equals_bytes(b"deflate", true) {
                                    v.push(Encoding::Deflate);
                                } else if value.equals_bytes(b"gzip", true) {
                                    v.push(Encoding::Gzip);
                                } else {
                                    panic!("Impossible Condition");
                                }
                                method = TransferMethod::Sized(SizedTransferEncoding::Encoded(v));
                            }
                        }
                    }
                }
            }
        }

        Ok(Some(method))
    }
}

pub enum Encoding {
    Brotli,
    Compress,
    Deflate,
    Gzip,
}

impl Copy for Encoding {}

impl Clone for Encoding {
    fn clone(&self) -> Encoding {
        *self
    }
}

impl fmt::Debug for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Encoding::Brotli => {
                write!(f, "Brotli")
            }

            Encoding::Compress => {
                write!(f, "Compress")
            }

            Encoding::Deflate => {
                write!(f, "Deflate")
            }

            Encoding::Gzip => {
                write!(f, "Gzip")
            }
        }
    }
}

pub enum SizedTransferEncoding {
    Plain(usize),
    Encoded(Vec<Encoding>),
}

impl Clone for SizedTransferEncoding {
    fn clone(&self) -> SizedTransferEncoding {
        match self {
            SizedTransferEncoding::Plain(size) => SizedTransferEncoding::Plain(*size),

            SizedTransferEncoding::Encoded(encodings) => {
                SizedTransferEncoding::Encoded(encodings.to_vec())
            }
        }
    }
}

impl fmt::Debug for SizedTransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizedTransferEncoding::Plain(size) => {
                write!(f, "Plain {}", size)
            }

            SizedTransferEncoding::Encoded(encodings) => {
                write!(f, "Encoded with {:?}", encodings)
            }
        }
    }
}

pub enum ChunkedTransferEncoding {
    Plain,
    Encoded(Vec<Encoding>),
}

impl Clone for ChunkedTransferEncoding {
    fn clone(&self) -> ChunkedTransferEncoding {
        match self {
            ChunkedTransferEncoding::Plain => ChunkedTransferEncoding::Plain,

            ChunkedTransferEncoding::Encoded(encodings) => {
                ChunkedTransferEncoding::Encoded(encodings.to_vec())
            }
        }
    }
}

impl fmt::Debug for ChunkedTransferEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChunkedTransferEncoding::Plain => {
                write!(f, "Plain")
            }

            ChunkedTransferEncoding::Encoded(encodings) => {
                write!(f, "Encoded with {:?}", encodings)
            }
        }
    }
}

pub enum TransferMethod {
    Sized(SizedTransferEncoding),
    Chunked(ChunkedTransferEncoding),
    Unbounded,
}

impl Clone for TransferMethod {
    fn clone(&self) -> TransferMethod {
        match self {
            TransferMethod::Sized(encoding) => TransferMethod::Sized(encoding.clone()),

            TransferMethod::Chunked(encoding) => TransferMethod::Chunked(encoding.clone()),

            TransferMethod::Unbounded => TransferMethod::Unbounded,
        }
    }
}

impl fmt::Debug for TransferMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferMethod::Sized(encoding) => {
                write!(f, "Sized {:?}", encoding)
            }

            TransferMethod::Chunked(encoding) => {
                write!(f, "Chunked {:?}", encoding)
            }

            TransferMethod::Unbounded => {
                write!(f, "Unbounded")
            }
        }
    }
}

pub enum StreamState {
    DecodeHeader,
    DecodeBody(
        TransferMethod,
        PollSender<io::Result<Vec<u8>>>,
        usize,
        Option<io::Result<Vec<u8>>>,
        bool,
        bool,
    ),
}

pub enum ResponseOrAgain {
    Response(Response),
    Again(bool), // Again(transaction_completed)
}

pub struct ResponseStream<'a> {
    state: StreamState,
    buf: ReadBuf<'a>,
    consumed: usize,
    p: *mut u8,
    rh: ReadHalf<ClientStream>,
    pub method: &'static [u8],
}

impl ResponseStream<'_> {
    pub fn new(rh: ReadHalf<ClientStream>) -> ResponseStream<'static> {
        let buf;
        let p;

        unsafe {
            p = libc::calloc(1, 4 * 1024) as *mut u8;
            let s = std::slice::from_raw_parts_mut(p, 4 * 1024);
            buf = ReadBuf::new(&mut *s);
        }

        ResponseStream {
            state: StreamState::DecodeHeader,
            buf,
            consumed: 0,
            p,
            rh,
            method: &[],
        }
    }

    pub fn setup_body_reading(
        &mut self,
        req_method: &[u8],
        r: &Response,
    ) -> io::Result<Option<mpsc::Receiver<io::Result<Vec<u8>>>>> {
        match r.get_response_transfer_method(req_method) {
            Ok(Some(ref method)) => {
                platform_log(LOG_TAG, format!("setting up transfer {:?}", method));

                let (data_tx, data_rx) = mpsc::channel::<io::Result<Vec<u8>>>(8);

                match method {
                    TransferMethod::Sized(encoding) => match encoding {
                        SizedTransferEncoding::Plain(size) => {
                            if *size == 0 {
                                platform_log(LOG_TAG, format!("no data transfer needed"));
                                return Ok(None);
                            } else {
                                self.state = StreamState::DecodeBody(
                                    method.clone(),
                                    PollSender::new(data_tx),
                                    0,
                                    None,
                                    false,
                                    false,
                                );
                            }
                        }

                        SizedTransferEncoding::Encoded(encodings) => {
                            let (codec_tx, codec_rx) = mpsc::channel::<io::Result<Vec<u8>>>(8);
                            let encodings = encodings.to_vec();

                            tokio::spawn(async move {
                                let mut decompressor = Decompressor::new(&encodings, codec_rx);
                                let reader = decompressor.reader();
                                loop {
                                    let mut buf = vec![0; 4 * 1024];
                                    match reader.read(&mut buf).await {
                                        Ok(size) => {
                                            if size == 0 {
                                                break;
                                            } else {
                                                buf.truncate(size);

                                                match data_tx.send(Ok(buf)).await {
                                                    Ok(_) => {}
                                                    Err(_) => {
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        Err(e) => {
                                            match data_tx.send(Err(e)).await {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            }
                                            break;
                                        }
                                    }
                                }
                            });

                            self.state = StreamState::DecodeBody(
                                method.clone(),
                                PollSender::new(codec_tx),
                                0,
                                None,
                                false,
                                false,
                            );
                        }
                    },

                    TransferMethod::Chunked(encoding) => match encoding {
                        ChunkedTransferEncoding::Plain => {
                            self.state = StreamState::DecodeBody(
                                method.clone(),
                                PollSender::new(data_tx),
                                0,
                                None,
                                false,
                                false,
                            );
                        }

                        ChunkedTransferEncoding::Encoded(encodings) => {
                            let (codec_tx, codec_rx) = mpsc::channel::<io::Result<Vec<u8>>>(1);
                            let encodings = encodings.to_vec();

                            tokio::spawn(async move {
                                let mut decompressor = Decompressor::new(&encodings, codec_rx);
                                let reader = decompressor.reader();
                                loop {
                                    let mut buf = vec![0; 4 * 1024];
                                    match reader.read(&mut buf).await {
                                        Ok(size) => {
                                            if size == 0 {
                                                break;
                                            } else {
                                                buf.truncate(size);
                                                match data_tx.send(Ok(buf)).await {
                                                    Ok(_) => {}
                                                    Err(_) => {
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        Err(e) => {
                                            match data_tx.send(Err(e)).await {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            }
                                            break;
                                        }
                                    }
                                }
                            });

                            self.state = StreamState::DecodeBody(
                                method.clone(),
                                PollSender::new(codec_tx),
                                0,
                                None,
                                false,
                                false,
                            );
                        }
                    },

                    TransferMethod::Unbounded => {
                        self.state = StreamState::DecodeBody(
                            method.clone(),
                            PollSender::new(data_tx),
                            0,
                            None,
                            false,
                            false,
                        );
                    }
                }

                Ok(Some(data_rx))
            }

            Ok(None) => {
                platform_log(LOG_TAG, format!("no data transfer found"));
                Ok(None)
            }

            Err(e) => {
                platform_log(
                    LOG_TAG,
                    format!("get_response_transfer_method failed with error {:?}", e),
                );
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }
}

impl futures::Stream for ResponseStream<'_> {
    type Item = ResponseOrAgain;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        match stream.state {
            StreamState::DecodeHeader => {
                platform_log(LOG_TAG, "decoding header");

                let mut decoder =
                    HeaderPartDecoder::new(&mut stream.buf, &mut stream.consumed, &mut stream.rh);
                match Pin::new(&mut decoder).poll(cx) {
                    Poll::Ready(Ok(status)) => match status {
                        HeaderPartDecodeStatus::Success(r) => {
                            Poll::Ready(Some(ResponseOrAgain::Response(r)))
                        }

                        HeaderPartDecodeStatus::Again => {
                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                        }

                        HeaderPartDecodeStatus::BufferTooSmall => {
                            if stream.consumed > 0 {
                                let filled = stream.buf.filled_mut();
                                let len = filled.len();

                                for i in stream.consumed..len {
                                    filled[i - stream.consumed] = filled[i];
                                }

                                stream.buf.set_filled(len - stream.consumed);
                                stream.consumed = 0;

                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                            } else {
                                let capacity = stream.buf.capacity() * 2;
                                if capacity > 4 * 1024 * 1024 {
                                    platform_log(LOG_TAG, "buffer too large");
                                    Poll::Ready(None)
                                } else {
                                    let filled = stream.buf.filled().to_vec();

                                    unsafe {
                                        let p = libc::calloc(1, capacity) as *mut u8;
                                        let s = std::slice::from_raw_parts_mut(p, capacity);
                                        stream.buf = ReadBuf::new(&mut *s);
                                        libc::free(stream.p as *mut c_void);
                                        stream.p = p;
                                    }

                                    stream.buf.put_slice(&filled);

                                    Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                }
                            }
                        }

                        HeaderPartDecodeStatus::EOF => Poll::Ready(None),
                    },

                    Poll::Ready(Err(e)) => {
                        platform_log(LOG_TAG, format!("encountering error {:?}", e));
                        Poll::Ready(None)
                    }

                    Poll::Pending => Poll::Pending,
                }
            }

            StreamState::DecodeBody(
                ref method,
                ref mut data_tx,
                ref mut sent,
                ref mut pending_event,
                ref mut is_last_data_chunk,
                ref mut is_eof,
            ) => {
                match pending_event.take() {
                    Some(event) => {
                        platform_log(LOG_TAG, "decode result waiting to be processed");

                        match data_tx.poll_reserve(cx) {
                            Poll::Ready(Ok(())) => match event {
                                Ok(ref data) => {
                                    platform_log(
                                        LOG_TAG,
                                        format!(
                                            "transfer content body: {}",
                                            String::from_utf8_lossy(&data)
                                        ),
                                    );

                                    let len = data.len();

                                    match data_tx.send_item(event) {
                                        Ok(()) => {
                                            platform_log(LOG_TAG, "content body transfered");

                                            *sent = *sent + len;

                                            if *is_last_data_chunk {
                                                if *is_eof {
                                                    Poll::Ready(None)
                                                } else {
                                                    stream.state = StreamState::DecodeHeader;
                                                    Poll::Ready(Some(ResponseOrAgain::Again(true)))
                                                }
                                            } else {
                                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                            }
                                        }

                                        Err(e) => {
                                            platform_log(
                                                LOG_TAG,
                                                format!("content body cannot be transfered due to pipe error: {:?}", e),
                                            );

                                            // treat it like we've successfully send the response data
                                            *sent = *sent + len;

                                            if *is_last_data_chunk {
                                                if *is_eof {
                                                    Poll::Ready(None)
                                                } else {
                                                    stream.state = StreamState::DecodeHeader;
                                                    Poll::Ready(Some(ResponseOrAgain::Again(true)))
                                                }
                                            } else {
                                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                            }
                                        }
                                    }
                                }

                                Err(ref e) => {
                                    platform_log(LOG_TAG, format!("transfer error {:?}", e));

                                    match data_tx.send_item(event) {
                                        Ok(()) => {
                                            platform_log(LOG_TAG, "error transfered");

                                            Poll::Ready(None)
                                        }

                                        Err(e) => {
                                            platform_log(LOG_TAG, format!("error cannot be transfered due to pipe error: {:?}", e));

                                            Poll::Ready(None)
                                        }
                                    }
                                }
                            },

                            Poll::Ready(Err(e)) => {
                                platform_log(LOG_TAG, format!("channel reserve failed: {:?}", e));

                                match event {
                                    Ok(ref data) => {
                                        platform_log(
                                            LOG_TAG,
                                            format!(
                                                "content body: {:?} cannot be transfered due to receiving end closed",
                                                String::from_utf8_lossy(&data)
                                            ),
                                        );

                                        let len = data.len();

                                        // treat it like we've successfully send the response data
                                        *sent = *sent + len;

                                        if *is_last_data_chunk {
                                            if *is_eof {
                                                Poll::Ready(None)
                                            } else {
                                                stream.state = StreamState::DecodeHeader;
                                                Poll::Ready(Some(ResponseOrAgain::Again(true)))
                                            }
                                        } else {
                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }
                                    }

                                    Err(e) => {
                                        platform_log(LOG_TAG, format!("error {:?} cannot be transfered due to receiving end closed", e));

                                        Poll::Ready(None)
                                    }
                                }
                            }

                            Poll::Pending => {
                                pending_event.replace(event);
                                Poll::Pending
                            }
                        }
                    }

                    None => {
                        if *is_eof {
                            return Poll::Ready(None);
                        }

                        platform_log(
                            LOG_TAG,
                            format!("decoding body with transfer method {:?}", method),
                        );

                        if stream.buf.filled().len() == stream.consumed && stream.consumed != 0 {
                            platform_log(LOG_TAG, "making space for poll_read");
                            stream.buf.clear();
                            stream.consumed = 0;
                        }

                        match method {
                            TransferMethod::Sized(encoding) => {
                                let pending_data = &stream.buf.filled()[stream.consumed..];
                                if pending_data.len() > 0 {
                                    match encoding {
                                        SizedTransferEncoding::Plain(size) => {
                                            let remains = size - *sent;

                                            if pending_data.len() >= remains {
                                                let data = pending_data[..remains].to_vec();

                                                stream.consumed += data.len();

                                                pending_event.replace(Ok(data));

                                                *is_last_data_chunk = true;
                                            } else {
                                                let data = pending_data.to_vec();

                                                stream.consumed += data.len();

                                                pending_event.replace(Ok(data));

                                                *is_last_data_chunk = false;
                                            }

                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }

                                        SizedTransferEncoding::Encoded(_) => {
                                            let data = pending_data.to_vec();

                                            stream.consumed += data.len();

                                            pending_event.replace(Ok(data));

                                            *is_last_data_chunk = false;

                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }
                                    }
                                } else {
                                    let before_read = stream.buf.filled().len();

                                    match Pin::new(&mut stream.rh).poll_read(cx, &mut stream.buf) {
                                        Poll::Ready(Ok(())) => {
                                            platform_log(
                                                LOG_TAG,
                                                format!(
                                                    "poll_read success with new data range {}-{}",
                                                    stream.consumed,
                                                    stream.buf.filled().len()
                                                ),
                                            );

                                            let after_read = stream.buf.filled().len();

                                            if before_read == after_read {
                                                platform_log(LOG_TAG, "no more data");
                                                *pending_event = Some(Err(io::Error::new(
                                                    io::ErrorKind::UnexpectedEof,
                                                    "stream closed before reading last chunk",
                                                )));
                                                *is_eof = true;
                                            }

                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }

                                        Poll::Ready(Err(e)) => {
                                            pending_event.replace(Err(e));

                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }

                                        Poll::Pending => Poll::Pending,
                                    }
                                }
                            }

                            TransferMethod::Chunked(_) => {
                                let mut decoder = ChunkDecoder::new(
                                    &mut stream.buf,
                                    &mut stream.consumed,
                                    &mut stream.rh,
                                );

                                match Pin::new(&mut decoder).poll(cx) {
                                    Poll::Ready(Ok(result)) => match result {
                                        ChunkDecodeResult::Part(data) => {
                                            pending_event.replace(Ok(data));

                                            *is_last_data_chunk = false;

                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }

                                        ChunkDecodeResult::Again => {
                                            Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                        }

                                        ChunkDecodeResult::BufferTooSmall => {
                                            if stream.consumed > 0 {
                                                let filled = stream.buf.filled_mut();
                                                let len = filled.len();

                                                for i in stream.consumed..len {
                                                    filled[i - stream.consumed] = filled[i];
                                                }

                                                stream.buf.set_filled(len - stream.consumed);
                                                stream.consumed = 0;

                                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                            } else {
                                                let capacity = stream.buf.capacity() * 2;
                                                if capacity > 4 * 1024 * 1024 {
                                                    platform_log(LOG_TAG, "buffer too large");
                                                    Poll::Ready(None)
                                                } else {
                                                    let filled = stream.buf.filled().to_vec();

                                                    unsafe {
                                                        let p =
                                                            libc::calloc(1, capacity) as *mut u8;
                                                        let s = std::slice::from_raw_parts_mut(
                                                            p, capacity,
                                                        );
                                                        stream.buf = ReadBuf::new(&mut *s);
                                                        libc::free(stream.p as *mut c_void);
                                                        stream.p = p;
                                                    }

                                                    stream.buf.put_slice(&filled);

                                                    Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                                }
                                            }
                                        }

                                        ChunkDecodeResult::EOF => {
                                            platform_log(LOG_TAG, "on chunk decode EOF");
                                            Poll::Ready(None)
                                        }
                                    },

                                    Poll::Ready(Err(e)) => {
                                        platform_log(
                                            LOG_TAG,
                                            format!("on chunk decode error {:?}", e),
                                        );

                                        match e {
                                            ErrorKind::Io(e) => {
                                                pending_event.replace(Err(e));
                                            }

                                            ErrorKind::Parse => {
                                                pending_event.replace(Err(io::Error::from(
                                                    io::ErrorKind::BrokenPipe,
                                                )));
                                            }
                                        }

                                        Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                    }

                                    Poll::Pending => Poll::Pending,
                                }
                            }

                            TransferMethod::Unbounded => {
                                let pending_data = &stream.buf.filled()[stream.consumed..];
                                if pending_data.len() > 0 {
                                    let data = pending_data.to_vec();

                                    stream.consumed += data.len();

                                    pending_event.replace(Ok(data));

                                    Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                } else {
                                    match Pin::new(&mut stream.rh).poll_read(cx, &mut stream.buf) {
                                        Poll::Ready(Ok(())) => {
                                            platform_log(
                                                LOG_TAG,
                                                format!(
                                                    "poll_read success with new data range {}-{}",
                                                    stream.consumed,
                                                    stream.buf.filled().len()
                                                ),
                                            );

                                            let filled = &stream.buf.filled()[stream.consumed..];
                                            if filled.len() > 0 {
                                                let data = filled.to_vec();

                                                stream.consumed += data.len();

                                                pending_event.replace(Ok(data));

                                                *is_last_data_chunk = false;

                                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                            } else {
                                                platform_log(LOG_TAG, "no more data");

                                                *is_last_data_chunk = true;
                                                *is_eof = true;

                                                Poll::Ready(Some(ResponseOrAgain::Again(false)))
                                            }
                                        }

                                        Poll::Ready(Err(e)) => {
                                            platform_log(LOG_TAG, format!("on error {:?}", e));

                                            pending_event.replace(Err(e));

                                            Poll::Ready(None)
                                        }

                                        Poll::Pending => Poll::Pending,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

unsafe impl Send for ResponseStream<'_> {}
