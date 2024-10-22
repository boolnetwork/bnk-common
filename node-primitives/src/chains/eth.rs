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

use sp_core::bounded::alloc::{string::String, format, vec, vec::Vec};
use sp_core::U256;
use crate::{Hash256, inner_ecdsa_verify};

/// Verify eth ecdsa signature(sha2_256)
pub fn eth_ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> Result<(), String> {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, to_eth_signed_message_hash)
}

fn to_eth_signed_message_hash(msg: Vec<u8>) -> Vec<u8> {
    bnk_chain_bridge::utils::to_eth_signed_message_hash(&msg, sp_io::hashing::keccak_256)
}

pub fn eth_abi_encode_for_random_num(
    chain_id: u32,        // u256
    vrn_port: &[u8],      // address
    consumer_addr: &[u8], // address
    nonce: &[u8],         // u256
    number: &[u8],        // u256
) -> Result<Vec<u8>, String> {
    let heads_len = 5 * 32;
    let mut result = Vec::with_capacity(heads_len);
    let mut fixed_chain_id = [0u8; 32];
    sp_core::U256::from(chain_id).to_big_endian(&mut fixed_chain_id);
    if vrn_port.len() != 20 {
        return Err(format!(
            "invalid vrn port address length: {:?}",
            vrn_port.len()
        ));
    }
    let mut fixed_vrn_port = [0u8; 32];
    fixed_vrn_port[12..].copy_from_slice(vrn_port.as_ref());
    result.append(&mut vec![fixed_chain_id.as_slice()]);
    result.append(&mut vec![fixed_vrn_port.as_slice()]);
    result.append(&mut vec![consumer_addr]);
    result.append(&mut vec![nonce]);
    result.append(&mut vec![number]);
    Ok(result.iter().flat_map(|iterm| iterm.to_vec()).collect())
}

pub fn decode_random_num_params_from_eth_bytes(
    bytes: Vec<u8>,
) -> Result<(u32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if bytes.len() != 5 * 32 {
        return Err(format!("invalid eth encode bytes len: {:?}", bytes.len()));
    }
    let chain_id = &bytes[..32];
    let vrn_port = &bytes[32..64];
    let consumer_addr = &bytes[64..96];
    let nonce = &bytes[96..128];
    let number = &bytes[128..];

    let chain_id = U256::from_big_endian(chain_id).as_u32();
    Ok((
        chain_id,
        vrn_port.to_vec(),
        consumer_addr.to_vec(),
        nonce.to_vec(),
        number.to_vec(),
    ))
}
