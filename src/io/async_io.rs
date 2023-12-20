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

use std::{
    io::Read,
    pin::Pin,
    task::{Context, Poll},
};

use futures::AsyncRead;

use super::{BytesReader, DynamicChain};

impl AsyncRead for BytesReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = self.get_mut();
        match p.read(buf) {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncRead for DynamicChain<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = self.get_mut();
        match p.read(buf) {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
