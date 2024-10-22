// This file is part of BoolNetwork.

// Copyright (C) BoolNetwork (HK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod bls;
mod ecdsa;
mod eddsa;
mod schnorr;

pub use bls::*;
pub use ecdsa::*;
pub use eddsa::*;
pub use schnorr::*;
pub use sp_io::hashing::sha2_256;
use sp_core::bounded::alloc::vec::Vec;

#[allow(missing_docs)]
#[derive(Clone)]
pub enum Hash256 {
    Sha2_256,
    Sha3_256,
    Keccak256,
    Blake2256,
    Twox256,
}

pub fn keccak_256(msgs: &[u8]) -> Vec<u8> {
    sp_io::hashing::keccak_256(msgs).to_vec()
}

pub fn sha3_256(msgs: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(msgs);
    let result = hasher.finalize();
    result[..].to_vec()
}



