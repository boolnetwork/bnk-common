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

use crate::{crypto::inner_ecdsa_verify, Hash256};

pub fn to_tron_signed_message_hash(msg: Vec<u8>) -> Vec<u8> {
    bnk_chain_bridge::utils::to_eth_signed_message_hash(&msg, sp_io::hashing::keccak_256)
}

/// Verify tron ecdsa signature(sha2_256)
pub fn tron_ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> Result<(), String> {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, to_tron_signed_message_hash)
}
