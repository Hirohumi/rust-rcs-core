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

use std::ops::Range;
// use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::internet::header::Header;
use crate::internet::headers::byte_range;

use crate::util::rand;
use crate::util::ranges::RangeOperations;
// use crate::util::timer::Timer;

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpRequestLine;

const MAX_MSRP_CHUNK_SIZE: usize = 10 * 1024;

enum DeliveryStatus {
    AwaitPositiveReport(Vec<Range<usize>>, usize),
    AwaitNegativeReport,
    AwaitPositiveAndNegativeReport(Vec<Range<usize>>, usize),
    DontCare,
}

enum TransactionStatus {
    AwaitResponse,
    AwaitResponseAndTimeout,
    Sent,
    DontCare,
}

pub struct MsrpDemuxer {
    pub from_path: Vec<u8>,
    pub to_path: Vec<u8>,
    waitlist: Arc<
        Mutex<
            Vec<(
                Vec<u8>,
                DeliveryStatus,
                Vec<(Vec<u8>, TransactionStatus)>,
                bool,
                Arc<Mutex<Option<Box<dyn FnOnce(u16, String) + Send + Sync>>>>,
            )>,
        >,
    >,
}

impl MsrpDemuxer {
    pub fn new(from_path: Vec<u8>, to_path: Vec<u8>) -> MsrpDemuxer {
        MsrpDemuxer {
            from_path,
            to_path,
            waitlist: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start<R, C>(
        &self,
        from_path: Vec<u8>,
        to_path: Vec<u8>,
        content_type: Option<Vec<u8>>,
        total: usize,
        mut r: R,
        c: C,
        // tx: mpsc::Sender<MsrpChunk>,
        tx: mpsc::Sender<MsrpChunk>,
        // timer: Arc<Timer>,
        rt: &Arc<Runtime>,
    ) where
        // R: MsrpDataReader + Send + Sync + 'static,
        R: std::io::Read + Send + Sync + 'static,
        C: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let c: Arc<Mutex<Option<Box<dyn FnOnce(u16, String) + Send + Sync>>>> =
            Arc::new(Mutex::new(Some(Box::new(c))));

        let waitlist = Arc::clone(&self.waitlist);

        let rt_ = Arc::clone(rt);

        rt.spawn(async move {
            let message_id = rand::create_raw_alpha_numeric_string(16);
            let mut sent: usize = 0;
            // let mut buffer = None;
            let mut read_complete = false;
            let mut buffer = [0; MAX_MSRP_CHUNK_SIZE];
            let mut filled_buffer: Option<Vec<u8>> = None;
            while let Ok(result) = r.read(&mut buffer[..]) {
                if result > 0 {
                    if let Some(filled_buffer) = filled_buffer.take() {
                        let transaction_id = rand::create_raw_alpha_numeric_string(16);
                        let chunk = build_msrp_chunk(
                            &transaction_id,
                            &from_path,
                            &to_path,
                            &message_id,
                            &content_type,
                            Some(filled_buffer),
                            &mut sent,
                            total,
                            ContinuationFlag::Continuation,
                        );

                        let transaction_id_ = transaction_id.clone();
                        let transaction_status =
                            (transaction_id_, TransactionStatus::AwaitResponseAndTimeout);
                        let message_id_ = message_id.clone();
                        let mut delivery_status = (
                            message_id_,
                            DeliveryStatus::AwaitNegativeReport,
                            Vec::new(),
                            false,
                            Arc::clone(&c),
                        );
                        delivery_status.2.push(transaction_status);

                        {
                            let mut guard = waitlist.lock().unwrap();
                            (*guard).push(delivery_status);
                        }

                        match tx.send(chunk).await {
                            Ok(()) => {}
                            Err(_) => {
                                let mut guard = c.lock().unwrap();
                                match (*guard).take() {
                                    Some(c) => {
                                        c(408, String::from("Timeout"));
                                    }
                                    None => {}
                                }
                            }
                        }

                        start_timeout(&waitlist, transaction_id, &rt_);
                    }

                    filled_buffer = Some(buffer[..result].to_vec());
                } else {
                    read_complete = true;
                    break;
                }
            }

            let transaction_id = rand::create_raw_alpha_numeric_string(16);
            let chunk = build_msrp_chunk(
                &transaction_id,
                &from_path,
                &to_path,
                &message_id,
                &content_type,
                filled_buffer,
                &mut sent,
                total,
                ContinuationFlag::Complete,
            );

            let transaction_id_ = transaction_id.clone();
            let transaction_status = (transaction_id_, TransactionStatus::AwaitResponseAndTimeout);
            let message_id_ = message_id.clone();
            let mut delivery_status = (
                message_id_,
                DeliveryStatus::AwaitNegativeReport,
                Vec::new(),
                false,
                Arc::clone(&c),
            );
            delivery_status.2.push(transaction_status);

            {
                let mut guard = waitlist.lock().unwrap();
                (*guard).push(delivery_status);
            }

            match tx.send(chunk).await {
                Ok(()) => {}
                Err(_) => {
                    let mut guard = c.lock().unwrap();
                    match (*guard).take() {
                        Some(c) => {
                            c(408, String::from("Timeout"));
                        }
                        None => {}
                    }
                }
            }

            start_timeout(&waitlist, transaction_id, &rt_);

            if !read_complete {
                let mut guard = waitlist.lock().unwrap();
                let mut i = 0;
                for (message_id_, _, _, _, _) in &mut *guard {
                    if message_id_ == &message_id {
                        let (_, _, _, _, _) = (*guard).remove(i);
                        break;
                    }
                    i = i + 1;
                }

                let mut guard = c.lock().unwrap();
                match (*guard).take() {
                    Some(c) => {
                        c(500, String::from("Internal Error"));
                    }
                    None => {}
                }
            }
        });
    }

    pub fn on_report(&self, message: MsrpChunk) -> Result<(), &'static str> {
        if let Some(report_status) = message.get_report_status() {
            if report_status.ns == 0 {
                let mut guard = self.waitlist.lock().unwrap();
                let mut i = 0;
                for (message_id, status, _, _, _) in &mut *guard {
                    if message_id == report_status.message_id {
                        if report_status.status_code == 200 {
                            if let Some(byte_range) = report_status.byte_range {
                                if let Some(byte_range) = byte_range::parse(byte_range) {
                                    if let Some(to) = byte_range.to {
                                        match &mut *status {
                                            DeliveryStatus::AwaitPositiveReport(ranges, total)
                                            | DeliveryStatus::AwaitPositiveAndNegativeReport(
                                                ranges,
                                                total,
                                            ) => {
                                                if byte_range.total != 0
                                                    && byte_range.from <= to
                                                    && byte_range.from > 1
                                                {
                                                    let mut range = Range {
                                                        start: byte_range.from - 1,
                                                        end: to,
                                                    };
                                                    let mut i = 0;
                                                    while i < ranges.len() {
                                                        let lhs = &ranges[i];
                                                        if let Some(r) = range.union(lhs) {
                                                            ranges.remove(i);
                                                            range = r;
                                                            i = 0;
                                                        } else {
                                                            i = i + 1;
                                                        }
                                                    }
                                                    if ranges.len() == 0 {
                                                        if range.covering(&Range {
                                                            start: 0,
                                                            end: *total,
                                                        }) {
                                                            let (_, _, _, _, c) =
                                                                (*guard).remove(i);
                                                            let mut guard = c.lock().unwrap();
                                                            match (*guard).take() {
                                                                Some(c) => {
                                                                    c(200, String::from("Ok"));
                                                                }
                                                                None => {}
                                                            }
                                                            return Ok(());
                                                        }
                                                    }
                                                    ranges.push(range);
                                                }
                                                return Ok(());
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        } else {
                            match status {
                                DeliveryStatus::AwaitNegativeReport
                                | DeliveryStatus::AwaitPositiveAndNegativeReport(_, _) => {
                                    let (_, _, _, _, c) = (*guard).remove(i);
                                    let mut guard = c.lock().unwrap();
                                    match (*guard).take() {
                                        Some(c) => {
                                            let reason_phrase =
                                                if let Some(comment) = report_status.comment {
                                                    String::from_utf8_lossy(comment).to_string()
                                                } else {
                                                    String::from("")
                                                };
                                            c(report_status.status_code, reason_phrase);
                                        }
                                        None => {}
                                    }
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }
                    i = i + 1;
                }
            }
        }

        Err("Server Internal Error")
    }

    pub fn on_response(&self, message: MsrpChunk) -> Result<(), (u16, &'static str)> {
        match message {
            MsrpChunk::Response(resp_line, _) => {
                let mut guard = self.waitlist.lock().unwrap();
                let mut i = 0;
                for (_, _, transaction_status_arr, all_sent, _) in &mut *guard {
                    for (t, status) in transaction_status_arr.iter_mut() {
                        if resp_line.transaction_id == *t {
                            match status {
                                TransactionStatus::AwaitResponse
                                | TransactionStatus::AwaitResponseAndTimeout => {
                                    if resp_line.status_code == 200 {
                                        *status = TransactionStatus::Sent;
                                        if *all_sent {
                                            if !transaction_status_arr.iter().any(|(_, status)| {
                                                match status {
                                                    TransactionStatus::Sent => false,
                                                    _ => true,
                                                }
                                            }) {
                                                let (_, _, _, _, c) = (*guard).remove(i);
                                                let mut guard = c.lock().unwrap();
                                                match (*guard).take() {
                                                    Some(c) => {
                                                        c(200, String::from("Ok"));
                                                    }
                                                    None => {}
                                                }
                                            }
                                        }
                                    } else {
                                        let (_, _, _, _, c) = (*guard).remove(i);
                                        let mut guard = c.lock().unwrap();
                                        match (*guard).take() {
                                            Some(c) => {
                                                let reason_phrase =
                                                    if let Some(comment) = &resp_line.comment {
                                                        String::from_utf8_lossy(comment).to_string()
                                                    } else {
                                                        String::from("")
                                                    };

                                                c(resp_line.status_code, reason_phrase);
                                            }
                                            None => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                            return Ok(());
                        }
                    }
                    i = i + 1;
                }
            }
            _ => {}
        }

        Err((500, "Server Internal Error"))
    }
}

fn build_msrp_chunk(
    transaction_id: &[u8],
    from_path: &[u8],
    to_path: &[u8],
    message_id: &[u8],
    content_type: &Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    sent: &mut usize,
    total: usize,
    continuation_flag: ContinuationFlag,
) -> MsrpChunk {
    let mut message = MsrpChunk::new_request_chunk(
        MsrpRequestLine {
            transaction_id: transaction_id.to_vec(),
            request_method: b"SEND".to_vec(),
        },
        Vec::new(),
        data,
        continuation_flag,
    );

    message.add_header(Header::new(b"From-Path", from_path.to_vec()));

    message.add_header(Header::new(b"To-Path", to_path.to_vec()));

    message.add_header(Header::new(b"Message-ID", message_id.to_vec()));

    if let Some(body) = message.get_body() {
        if let Some(content_type) = content_type {
            let length = body.len();

            message.add_header(Header::new(
                b"Byte-Range",
                format!("{}-{}/{}", *sent + 1, *sent + length, total),
            ));

            message.add_header(Header::new(b"Content-Type", content_type.to_vec()));

            *sent = *sent + length;
        } else {
            panic!("")
        }
    }

    message.add_header(Header::new(b"Failure-Report", b"yes"));

    message
}

fn start_timeout(
    waitlist: &Arc<
        Mutex<
            Vec<(
                Vec<u8>,
                DeliveryStatus,
                Vec<(Vec<u8>, TransactionStatus)>,
                bool,
                Arc<Mutex<Option<Box<dyn FnOnce(u16, String) + Send + Sync>>>>,
            )>,
        >,
    >,
    transaction_id: Vec<u8>,
    rt: &Arc<Runtime>,
) {
    let waitlist = Arc::clone(&waitlist);
    // timer.schedule(Duration::from_secs(30), move || {
    //     let mut guard = waitlist.lock().unwrap();
    //     for (_, _, transaction_status_arr, _, c) in &mut *guard {
    //         let mut i = 0;
    //         for (t, status) in transaction_status_arr.iter() {
    //             if *t == transaction_id {
    //                 match status {
    //                     TransactionStatus::AwaitResponseAndTimeout => {
    //                         let (_, _) = transaction_status_arr.remove(i);
    //                         let mut guard = c.lock().unwrap();
    //                         match (*guard).take() {
    //                             Some(c) => {
    //                                 c(408);
    //                             }
    //                             None => {}
    //                         }
    //                     }
    //                     _ => {}
    //                 }
    //                 return;
    //             }
    //             i = i + 1;
    //         }
    //     }
    // });
    rt.spawn(async move {
        sleep(Duration::from_secs(30)).await;
        let mut guard = waitlist.lock().unwrap();
        for (_, _, transaction_status_arr, _, c) in &mut *guard {
            let mut i = 0;
            for (t, status) in transaction_status_arr.iter() {
                if *t == transaction_id {
                    match status {
                        TransactionStatus::AwaitResponseAndTimeout => {
                            let (_, _) = transaction_status_arr.remove(i);
                            let mut guard = c.lock().unwrap();
                            match (*guard).take() {
                                Some(c) => {
                                    c(408, String::from("Timeout"));
                                }
                                None => {}
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                i = i + 1;
            }
        }
    });
}
