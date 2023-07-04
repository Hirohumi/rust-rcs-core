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
// use std::io::{Read, Write};
use std::sync::Arc;

// use std::sync::mpsc;
// use std::thread;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::ffi::log::platform_log;
use crate::io::{DynamicChain, Serializable};

// use crate::transport::{Closable, Transport};

use super::msrp_chunk::MsrpChunk;
use super::msrp_parser::MsrpParser;

// pub trait MsrpTransportImpl: AsyncRead + AsyncWrite {}
// pub trait MsrpTransportImpl: Transport + Read + Write + Closable + Send {}

const LOG_TAG: &str = "msrp";

// pub struct MsrpTransport {
//     tx: Option<mpsc::Sender<Option<Vec<u8>>>>, // thread: Option<(
//                                                //     mpsc::Sender<Option<Vec<u8>>>,
//                                                //     Box<dyn MsrpTransportImpl>,
//                                                //     std::thread::JoinHandle<()>,
//                                                //     std::thread::JoinHandle<()>,
//                                                // )>,
// }

// pub struct MsrpTransportWrapper {
//     transport: Arc<MsrpTransport>,
// }

// impl MsrpTransportWrapper {
//     pub fn new<T, MC, TRC>(
//         t: T,
//         t_id: String,
//         tx: mpsc::Sender<Option<Vec<u8>>>,
//         rx: mpsc::Receiver<Option<Vec<u8>>>,
//         mut message_callback: MC,
//         transport_release_callback: TRC,
//         rt: &Arc<Runtime>,
//     ) -> MsrpTransportWrapper
//     where
//         T: AsyncRead + AsyncWrite + Send + 'static,
//         MC: FnMut(MsrpChunk) -> Result<Option<MsrpChunk>, &'static str> + Send + Sync + 'static,
//         TRC: Fn(Arc<MsrpTransport>) + Send + Sync + 'static,
//     {
//         let (mut rh, mut wh) = tokio::io::split(t);

//         // let (tx, mut rx): (
//         //     mpsc::Sender<Option<Vec<u8>>>,
//         //     mpsc::Receiver<Option<Vec<u8>>>,
//         // ) = mpsc::channel(8);
//         // let tx_ = tx.clone();

//         let transport = MsrpTransport { tx: Some(tx) };
//         let transport = Arc::new(transport);
//         let transport_ = Arc::clone(&transport);

//         rt.spawn(async move {
//             let mut parser = MsrpParser::new();
//             let mut data: [u8; 4096] = [0; 4096];
//             'read: while let Ok(size) = rh.read(&mut data).await {
//                 parser.feed(&data[..size]);
//                 loop {
//                     match parser.produce() {
//                         Ok(message) => {
//                             if let Some(message) = message {
//                                 if let Ok(resp_message) = message_callback(message) {
//                                     if let Some(resp_message) = resp_message {
//                                         let data_size = resp_message.estimated_size();
//                                         let mut data = Vec::with_capacity(data_size);
//                                         {
//                                             let mut readers = Vec::new();
//                                             resp_message.get_readers(&mut readers);
//                                             match DynamicChain::new(readers).read_to_end(&mut data)
//                                             {
//                                                 Ok(_) => {}
//                                                 Err(_) => {} // to-do: early failure
//                                             }
//                                         }
//                                         match tx.send(Some(data)).await {
//                                             Ok(()) => {}
//                                             Err(e) => {}
//                                         }
//                                     }
//                                     continue 'read;
//                                 }

//                                 platform_log(
//                                     LOG_TAG,
//                                     format!("received bad chunk from transport {}", t_id),
//                                 );
//                                 break 'read;
//                             } else {
//                                 continue 'read;
//                             }
//                         }
//                         Err(e) => {
//                             platform_log(
//                                 LOG_TAG,
//                                 format!("msrp parsing error for transport {}: {}", t_id, e),
//                             );
//                             break 'read;
//                         }
//                     }
//                 }
//             }

//             transport_release_callback(transport_);
//         });

//         rt.spawn(async move {
//             'thread: loop {
//                 let mut written = 0;
//                 if let Some(Some(data)) = rx.recv().await {
//                     while let Ok(size) = wh.write(&data[written..]).await {
//                         if size > 0 {
//                             written = written + size;
//                             if written == data.len() {
//                                 continue 'thread;
//                             }
//                             continue;
//                         }
//                     }
//                 } else {
//                     break;
//                 }
//             }

//             match wh.shutdown().await {
//                 Ok(_) => {}

//                 Err(_) => {}
//             }
//         });

//         // MsrpTransport { tx: Some(tx) }
//         MsrpTransportWrapper { transport }
//     }

//     pub fn get_transport(&self) -> Arc<MsrpTransport> {
//         Arc::clone(&self.transport)
//     }
// }

// impl MsrpTransport {
//     // pub fn new<T, MC, TC>(
//     //     t: T,
//     //     t_id: String,
//     //     message_callback: MC,
//     //     transport_callback: TC,
//     //     rt: Arc<Runtime>,
//     // ) -> MsrpTransport
//     // where
//     //     T: AsyncRead + AsyncWrite + Send + 'static,
//     //     MC: Fn(MsrpChunk) -> Result<Option<MsrpChunk>, &'static str> + Send + Sync + 'static,
//     //     TC: Fn(Arc<MsrpTransport>) + Send + Sync + 'static,
//     // {

//     // }

//     // pub fn start<C>(&mut self, t: Box<dyn MsrpTransportImpl>, callback: C)
//     // where
//     //     C: Fn(MsrpChunk) -> Result<Option<MsrpChunk>, &'static str> + Send + Sync + 'static,
//     // {
//     //     if self.thread.is_none() {
//     //         if let Some((mut r, mut w)) = t.get_read_write_interface() {
//     //             let transport_id = self.transport_id;

//     //             let (tx, rx): (
//     //                 mpsc::Sender<Option<Vec<u8>>>,
//     //                 mpsc::Receiver<Option<Vec<u8>>>,
//     //             ) = mpsc::channel();
//     //             let tx_ = tx.clone();

//     //             let read_thread = thread::spawn(move || {
//     //                 let mut parser = MsrpParser::new();
//     //                 let mut data: [u8; 4096] = [0; 4096];
//     //                 'read: while let Ok(size) = r.read(&mut data) {
//     //                     parser.feed(&data[..size]);
//     //                     loop {
//     //                         match parser.produce() {
//     //                             Ok(message) => {
//     //                                 if let Some(message) = message {
//     //                                     if let Ok(resp_message) = callback(message) {
//     //                                         if let Some(resp_message) = resp_message {
//     //                                             tx_.send(Some(resp_message.serialize())).unwrap();
//     //                                         }
//     //                                         continue 'read;
//     //                                     }

//     //                                     println!(
//     //                                         "received bad chunk from transport {}",
//     //                                         transport_id,
//     //                                     );
//     //                                     break 'read;
//     //                                 } else {
//     //                                     continue 'read;
//     //                                 }
//     //                             }
//     //                             Err(e) => {
//     //                                 println!(
//     //                                     "msrp parsing error for transport {}: {}",
//     //                                     transport_id, e
//     //                                 );
//     //                                 break 'read;
//     //                             }
//     //                         }
//     //                     }
//     //                 }
//     //             });

//     //             let write_thread = thread::spawn(move || 'thread: loop {
//     //                 let mut written = 0;
//     //                 if let Some(data) = rx.recv().unwrap() {
//     //                     while let Ok(size) = w.write(&data[written..]) {
//     //                         if size > 0 {
//     //                             written = written + size;
//     //                             if written == data.len() {
//     //                                 continue 'thread;
//     //                             }
//     //                             continue;
//     //                         }
//     //                     }
//     //                 }
//     //             });

//     //             self.thread.replace((tx, t, read_thread, write_thread));
//     //         }
//     //     }
//     // }

//     pub fn send(&self, data: Vec<u8>, rt: &Arc<Runtime>) {
//         if let Some(tx) = &self.tx {
//             let tx_ = tx.clone();
//             rt.spawn(async move {
//                 match tx_.send(Some(data)).await {
//                     Ok(()) => {}

//                     Err(e) => {}
//                 }
//             });
//         }
//     }

//     pub fn close(&mut self) {
//         self.tx.take();
//     }
// }

// impl Drop for MsrpTransport {
//     fn drop(&mut self) {
//         if let Some((_, mut t, read_thread, write_thread)) = self.thread.take() {
//             t.close();

//             read_thread.join().unwrap();
//             write_thread.join().unwrap();
//         }
//     }
// }

// pub trait MsrpTransportFactory<T> {
//     fn create_transport(&self, from_path: &[u8], to_path: &[u8]) -> T;
// }

pub fn msrp_transport_start<T, MC, TRC>(
    t: T,
    t_id: String,
    tx: mpsc::Sender<Option<Vec<u8>>>,
    mut rx: mpsc::Receiver<Option<Vec<u8>>>,
    mut message_callback: MC,
    transport_release_callback: TRC,
    rt: &Arc<Runtime>,
) where
    T: AsyncRead + AsyncWrite + Send + 'static,
    MC: FnMut(MsrpChunk) -> Result<Option<MsrpChunk>, &'static str> + Send + Sync + 'static,
    TRC: FnOnce() + Send + Sync + 'static,
{
    let (mut rh, mut wh) = tokio::io::split(t);

    rt.spawn(async move {
        let mut parser = MsrpParser::new();
        let mut data: [u8; 4096] = [0; 4096];
        'read: while let Ok(size) = rh.read(&mut data).await {
            parser.feed(&data[..size]);
            loop {
                match parser.produce() {
                    Ok(message) => {
                        if let Some(message) = message {
                            if let Ok(resp_message) = message_callback(message) {
                                if let Some(resp_message) = resp_message {
                                    let data_size = resp_message.estimated_size();
                                    let mut data = Vec::with_capacity(data_size);
                                    {
                                        let mut readers = Vec::new();
                                        resp_message.get_readers(&mut readers);
                                        match DynamicChain::new(readers).read_to_end(&mut data) {
                                            Ok(_) => {}
                                            Err(_) => {} // to-do: early failure
                                        }
                                    }
                                    match tx.send(Some(data)).await {
                                        Ok(()) => {}
                                        Err(e) => {}
                                    }
                                }
                                continue 'read;
                            }

                            platform_log(
                                LOG_TAG,
                                format!("received bad chunk from transport {}", t_id),
                            );
                            break 'read;
                        } else {
                            continue 'read;
                        }
                    }
                    Err(e) => {
                        platform_log(
                            LOG_TAG,
                            format!("msrp parsing error for transport {}: {}", t_id, e),
                        );
                        break 'read;
                    }
                }
            }
        }

        transport_release_callback();
    });

    rt.spawn(async move {
        'thread: loop {
            let mut written = 0;
            if let Some(Some(data)) = rx.recv().await {
                while let Ok(size) = wh.write(&data[written..]).await {
                    if size > 0 {
                        written = written + size;
                        if written == data.len() {
                            continue 'thread;
                        }
                        continue;
                    }
                }
            } else {
                break;
            }
        }

        match wh.shutdown().await {
            Ok(_) => {}

            Err(_) => {}
        }
    });
}
