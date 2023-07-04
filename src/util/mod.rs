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

#[cfg_attr(target_arch = "arm", path = "id_generator.rs")]
#[cfg_attr(target_arch = "aarch64", path = "id_generator64.rs")]
pub mod id_generator;
pub mod rand;
pub mod ranges;
pub mod raw_string;
pub mod thread_pool;
pub mod timer;

pub use thread_pool::ThreadPool;
pub use timer::Timer;
