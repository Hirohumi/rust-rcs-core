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

use std::collections::HashMap;

use crate::internet::headers::byte_range;

use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpChunkInfo;

struct DanglingChunk {
    from: usize,
    total: usize,
    chunk: MsrpChunk,
}

pub trait MsrpDataWriter {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)>;
    fn complete(&mut self) -> Result<(), (u16, &'static str)>; // to-do: use FnOnce to improve code readability
}

pub trait MsrpMessageReceiver {
    fn on_message(
        &mut self,
        message_id: &[u8],
        content_type: &[u8],
    ) -> Result<Box<dyn MsrpDataWriter + Send + Sync>, (u16, &'static str)>;
}

pub struct MsrpMuxer {
    message_receiver: Box<dyn MsrpMessageReceiver + Send + Sync>,
    writers: HashMap<
        Vec<u8>,
        (
            Box<dyn MsrpDataWriter + Send + Sync>,
            Vec<DanglingChunk>,
            usize,
        ),
    >,
}

impl MsrpMuxer {
    pub fn new<R>(message_receiver: R) -> MsrpMuxer
    where
        R: MsrpMessageReceiver + Send + Sync + 'static,
    {
        MsrpMuxer {
            message_receiver: Box::new(message_receiver),
            writers: HashMap::new(),
        }
    }

    pub fn feed<'a>(&mut self, chunk: MsrpChunk) -> Result<(), (u16, &'static str)> {
        if let Some(chunk_info) = chunk.get_chunk_info() {
            if let Some(message_id) = chunk_info.message_id {
                if !self.writers.contains_key(message_id) {
                    if let Some(content_type) = chunk_info.content_type {
                        let writer = self.message_receiver.on_message(message_id, content_type)?;
                        let dangling_chunks = Vec::new();
                        self.writers
                            .insert(message_id.to_vec(), (writer, dangling_chunks, 0));
                    } else {
                        return Err((400, "Missing Content-Type header"));
                    }
                }

                if let Some((writer, dangling_chunks, written)) = self.writers.get_mut(message_id) {
                    let result = try_consume(&chunk, &chunk_info, writer, written)?;
                    match result {
                        ConsumeResult::FullyWritten | ConsumeResult::HalfwayWritten => match result
                        {
                            ConsumeResult::FullyWritten => {
                                writer.complete()?;
                                self.writers.remove(message_id);
                                return Ok(());
                            }
                            _ => {
                                while let Some(dangling) = dangling_chunks.first() {
                                    if dangling.from == *written + 1 {
                                        let chunk = &dangling.chunk;
                                        if let Some(chunk_data) = chunk.get_data() {
                                            let size = writer.write(chunk_data)?;
                                            if size != chunk_data.len() {
                                                return Err((0, "IO"));
                                            }
                                            *written = *written + size;
                                            if *written + 1 == dangling.total {
                                                writer.complete()?;
                                                self.writers.remove(message_id);
                                                return Ok(());
                                            } else {
                                                dangling_chunks.remove(0);
                                                continue;
                                            }
                                        } else {
                                            return Err((400, "Missing chunk data"));
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        },
                        ConsumeResult::ShouldQueue => {
                            if let Some(byte_range) = chunk_info.byte_range {
                                if let Some(byte_range) = byte_range::parse(byte_range) {
                                    let mut iter = dangling_chunks.iter();
                                    if let Some(position) =
                                        iter.position(|dangling| dangling.from > byte_range.from)
                                    {
                                        dangling_chunks.insert(
                                            position,
                                            DanglingChunk {
                                                from: byte_range.from,
                                                total: byte_range.total,
                                                chunk,
                                            },
                                        );
                                        return Ok(());
                                    } else {
                                        dangling_chunks.push(DanglingChunk {
                                            from: byte_range.from,
                                            total: byte_range.total,
                                            chunk,
                                        });
                                        return Ok(());
                                    }
                                }
                            }
                            return Err((400, "Missing Byte-Range info"));
                        }
                    }
                }

                return Ok(());
            }
        }

        Err((400, "Invalid chunk info"))
    }
}

enum ConsumeResult {
    FullyWritten,
    HalfwayWritten,
    ShouldQueue,
}

fn try_consume<'a>(
    chunk: &MsrpChunk,
    chunk_info: &MsrpChunkInfo<'a>,
    writer: &mut Box<dyn MsrpDataWriter + Send + Sync>,
    written: &mut usize,
) -> Result<ConsumeResult, (u16, &'static str)> {
    if let Some(byte_range) = chunk_info.byte_range {
        if let Some(byte_range) = byte_range::parse(byte_range) {
            if byte_range.from == *written + 1 {
                if let Some(chunk_data) = chunk.get_data() {
                    let size = writer.write(chunk_data)?;
                    *written = *written + size;
                    if *written + 1 == byte_range.total {
                        return Ok(ConsumeResult::FullyWritten);
                    } else {
                        return Ok(ConsumeResult::HalfwayWritten);
                    }
                }
            }
            return Ok(ConsumeResult::ShouldQueue);
        }
    }

    Err((400, "Missing Byte-Range info"))
}
