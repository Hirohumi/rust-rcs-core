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

use std::io::Read;
// use std::sync::mpsc;
use std::sync::{Arc, Mutex};
// use std::thread;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::internet::header::Header;

use crate::io::{DynamicChain, Serializable};

use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpResponseLine;
use super::msrp_chunk::ReportFailure;
use super::msrp_demuxer::MsrpDemuxer;
use super::msrp_muxer::MsrpMuxer;
use super::msrp_transport::msrp_transport_start;
// use super::msrp_transport::MsrpTransportFactory;
// use super::msrp_transport::{MsrpTransport, MsrpTransportWrapper};

pub struct MsrpChannel {
    from_path: Vec<u8>, // local_path
    to_path: Vec<u8>,   // remote_path
    demuxer: Arc<MsrpDemuxer>,
    muxer: MsrpMuxer,
}

impl MsrpChannel {
    pub fn new(
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        demuxer: Arc<MsrpDemuxer>,
        muxer: MsrpMuxer,
    ) -> MsrpChannel {
        MsrpChannel {
            from_path,
            to_path,
            demuxer,
            muxer,
        }
    }

    pub fn on_message<'a>(
        &mut self,
        message: MsrpChunk,
    ) -> Result<Option<MsrpChunk>, &'static str> {
        match &message {
            MsrpChunk::Request(req_line, _, _, _) => {
                if let Some(chunk_info) = message.get_chunk_info() {
                    let transaction_id = req_line.transaction_id.clone();
                    let mut resp_headers = Vec::new();

                    resp_headers.push(Header::new(b"From-Path", chunk_info.from_path.to_vec()));
                    resp_headers.push(Header::new(b"To-Path", chunk_info.to_path.to_vec()));

                    if req_line.request_method == b"SEND" {
                        if let Some(message_id) = chunk_info.message_id {
                            resp_headers.push(Header::new(b"Message-ID", message_id.to_vec()));
                        }

                        let mut failure_report = ReportFailure::Yes;
                        if let Some(failure_report_) = chunk_info.failure_report {
                            failure_report = failure_report_;
                        }

                        match self.muxer.feed(message) {
                            Ok(_) => match failure_report {
                                ReportFailure::Yes => Ok(Some(MsrpChunk::new_response_chunk(
                                    MsrpResponseLine {
                                        transaction_id,
                                        status_code: 200,
                                        comment: Some(b"OK".to_vec()),
                                    },
                                    resp_headers,
                                ))),
                                _ => Ok(None),
                            },

                            Err((status_code, comment)) => match failure_report {
                                ReportFailure::Yes | ReportFailure::Partial => {
                                    Ok(Some(MsrpChunk::new_response_chunk(
                                        MsrpResponseLine {
                                            transaction_id,
                                            status_code,
                                            comment: Some(comment.as_bytes().to_vec()),
                                        },
                                        resp_headers,
                                    )))
                                }
                                _ => Ok(None),
                            },
                        }
                    } else if req_line.request_method == b"REPORT" {
                        if let Ok(_) = self.demuxer.on_report(message) {
                            Ok(None)
                        } else {
                            Ok(None)
                        }
                    } else {
                        Ok(Some(MsrpChunk::new_response_chunk(
                            MsrpResponseLine {
                                transaction_id,
                                status_code: 501,
                                comment: Some(b"Unknown request method".to_vec()),
                            },
                            resp_headers,
                        )))
                    }
                } else {
                    Err("Bad Format")
                }
            }
            MsrpChunk::Response(_, _) => match self.demuxer.on_response(message) {
                Ok(_) => Ok(None),

                Err(_) => Ok(None),
            },
        }
    }
}

pub struct MsrpChannelManager {
    // tx: mpsc::Sender<MsrpChunk>,
    // transports: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Arc<mpsc::Sender<Option<Vec<u8>>>>)>>>,
    channels: Arc<Mutex<Vec<MsrpChannel>>>,
}

impl MsrpChannelManager {
    pub fn new<F, T>(
        mut rx: mpsc::Receiver<MsrpChunk>,
        socket_factory: F,
        rt: Arc<Runtime>,
    ) -> MsrpChannelManager
    where
        F: Fn(&[u8], &[u8]) -> T + Send + 'static,
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        // let (tx, mut rx) = mpsc::channel::<MsrpChunk>(8);

        let transports: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>, Arc<mpsc::Sender<Option<Vec<u8>>>>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let transports_ = Arc::clone(&transports);

        let channels: Arc<Mutex<Vec<MsrpChannel>>> = Arc::new(Mutex::new(Vec::new()));
        let channels_ = Arc::clone(&channels);

        let rt_ = Arc::clone(&rt);
        rt.spawn(async move {
            'thread: while let Some(message) = rx.recv().await {
                let rt = Arc::clone(&rt_);
                let transports = &transports_;
                let channels = &channels_;

                if let Some(chunk_info) = message.get_chunk_info() {
                    let mut guard = transports.lock().unwrap();
                    for (from_path, to_path, tx) in &mut *guard {
                        if from_path == chunk_info.to_path && to_path == chunk_info.to_path {
                            let data_size = message.estimated_size();
                            let mut data = Vec::with_capacity(data_size);
                            {
                                let mut readers = Vec::new();
                                message.get_readers(&mut readers);
                                match DynamicChain::new(readers).read_to_end(&mut data) {
                                    Ok(_) => {}
                                    Err(_) => {} // to-do: early failure
                                }
                            }
                            let tx = tx.as_ref().clone();
                            rt.spawn(async move {
                                match tx.send(Some(data)).await {
                                    Ok(()) => {}
                                    Err(e) => {}
                                }
                            });
                            continue 'thread;
                        }
                    }

                    let channels = Arc::clone(channels);
                    let transports = Arc::clone(&transports);

                    let t = socket_factory(chunk_info.from_path, chunk_info.to_path);
                    let t_id = format!(
                        "{}-{}",
                        String::from_utf8_lossy(chunk_info.from_path),
                        String::from_utf8_lossy(chunk_info.from_path),
                    );

                    let (data_tx, data_rx) = mpsc::channel(8);
                    let data_tx = Arc::new(data_tx);
                    let data_tx_ = data_tx.as_ref().clone();
                    let data_tx_r = Arc::clone(&data_tx);

                    msrp_transport_start(
                        t,
                        t_id,
                        data_tx_,
                        data_rx,
                        move |message| {
                            if let Some(chunk_info) = message.get_chunk_info() {
                                let mut guard = channels.lock().unwrap();
                                for channel in &mut (*guard) {
                                    if channel.from_path == chunk_info.from_path
                                        && channel.to_path == chunk_info.to_path
                                    {
                                        return channel.on_message(message);
                                    }
                                }
                                return Err("Path Does Not Exist");
                            }
                            Err("Bad Format")
                        },
                        move || {
                            let mut guard = transports.lock().unwrap();
                            if let Some(idx) = guard
                                .iter()
                                .position(|(_, _, tx)| Arc::ptr_eq(&tx, &data_tx_r))
                            {
                                guard.swap_remove(idx);
                            }
                        },
                        &rt,
                    );

                    // let transport_wrapper = MsrpTransportWrapper::new(
                    //     t,
                    //     format!(
                    //         "{}-{}",
                    //         &String::from_utf8_lossy(chunk_info.from_path),
                    //         &String::from_utf8_lossy(chunk_info.from_path)
                    //     ),
                    //     move |message| {
                    //         if let Some(chunk_info) = message.get_chunk_info() {
                    //             let mut guard = channels.lock().unwrap();
                    //             for channel in &mut (*guard) {
                    //                 if channel.from_path == chunk_info.from_path
                    //                     && channel.to_path == chunk_info.to_path
                    //                 {
                    //                     return Ok(channel.on_message(message)?);
                    //                 }
                    //             }
                    //             return Err("Path Does Not Exist");
                    //         }
                    //         Err("Bad Format")
                    //     },
                    //     move |transport| {
                    //         let mut guard = transports.lock().unwrap();
                    //         if let Some(idx) = guard
                    //             .iter()
                    //             .position(|(_, _, t)| Arc::ptr_eq(&transport, t))
                    //         {
                    //             guard.swap_remove(idx);
                    //         }
                    //     },
                    //     &rt,
                    // );

                    // let transport = transport_wrapper.get_transport();

                    let data_size = message.estimated_size();
                    let mut data = Vec::with_capacity(data_size);
                    {
                        let mut readers = Vec::new();
                        message.get_readers(&mut readers);
                        match DynamicChain::new(readers).read_to_end(&mut data) {
                            Ok(_) => {}
                            Err(_) => {} // to-do: early failure
                        }
                    }

                    let data_tx_ = Arc::clone(&data_tx);
                    rt.spawn(async move {
                        match data_tx_.send(Some(data)).await {
                            Ok(()) => {}

                            Err(e) => {}
                        }
                    });

                    (*guard).push((
                        chunk_info.from_path.to_vec(),
                        chunk_info.to_path.to_vec(),
                        data_tx,
                    ));
                }
            }
        });

        MsrpChannelManager {
            // tx,
            // transports,
            channels,
        }
    }

    pub fn register_channel(&self, channel: MsrpChannel) {
        let mut guard = self.channels.lock().unwrap();
        (*guard).push(channel);
    }

    // pub fn register_transport(&self, from_path: Vec<u8>, to_path: Vec<u8>, t: Arc<MsrpTransport>) {
    //     let mut guard = self.transports.lock().unwrap();
    //     guard.push((from_path, to_path, t));
    // }

    // pub fn get_tx(&self) -> mpsc::Sender<(MsrpChunk, Option<Arc<MsrpTransport>>)> {
    //     self.tx.clone()
    // }
}
