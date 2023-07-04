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

extern crate async_compression;
extern crate tokio;
extern crate tokio_stream;

use std::io;
use std::marker::Unpin;

use async_compression::futures::bufread::BrotliDecoder;
use async_compression::futures::bufread::DeflateDecoder;
use async_compression::futures::bufread::GzipDecoder;

use futures::io::{AsyncBufRead, AsyncReadExt};
use futures::stream::TryStreamExt;

use tokio::sync::mpsc;

use tokio_stream::wrappers::ReceiverStream;

use super::response::Encoding;

pub struct Decompressor {
    reader: Box<dyn AsyncBufRead + Send + Unpin>,
}

impl Decompressor {
    pub fn new(encodings: &[Encoding], rx: mpsc::Receiver<io::Result<Vec<u8>>>) -> Decompressor {
        let stream = ReceiverStream::new(rx);

        let reader = stream.into_async_read();
        let mut reader: Box<dyn AsyncBufRead + Send + Unpin> = Box::new(reader);

        for encoding in encodings {
            match encoding {
                Encoding::Brotli => {
                    reader = Box::new(
                        Box::pin(futures::stream::try_unfold(
                            BrotliDecoder::new(reader),
                            |mut encoder| async move {
                                let mut chunk = vec![0; 8 * 1024];
                                let len = encoder.read(&mut chunk).await?;
                                if len == 0 {
                                    Ok(None)
                                } else {
                                    chunk.truncate(len);
                                    Ok(Some((chunk, encoder)))
                                }
                            },
                        ))
                        .into_async_read(),
                    );
                }

                Encoding::Compress => {
                    panic!("Not Implemented")
                }

                Encoding::Deflate => {
                    reader = Box::new(
                        Box::pin(futures::stream::try_unfold(
                            DeflateDecoder::new(reader),
                            |mut encoder| async move {
                                let mut chunk = vec![0; 8 * 1024];
                                let len = encoder.read(&mut chunk).await?;
                                if len == 0 {
                                    Ok(None)
                                } else {
                                    chunk.truncate(len);
                                    Ok(Some((chunk, encoder)))
                                }
                            },
                        ))
                        .into_async_read(),
                    );
                }

                Encoding::Gzip => {
                    reader = Box::new(
                        Box::pin(futures::stream::try_unfold(
                            GzipDecoder::new(reader),
                            |mut encoder| async move {
                                let mut chunk = vec![0; 8 * 1024];
                                let len = encoder.read(&mut chunk).await?;
                                if len == 0 {
                                    Ok(None)
                                } else {
                                    chunk.truncate(len);
                                    Ok(Some((chunk, encoder)))
                                }
                            },
                        ))
                        .into_async_read(),
                    );
                }
            }
        }

        Decompressor { reader }
    }

    pub fn reader(&mut self) -> &mut Box<dyn AsyncBufRead + Send + Unpin> {
        &mut self.reader
    }
}
