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

use sp_core::bounded::alloc::{string::{String, ToString}, vec::Vec};
use super::Hash256;
use crate::sha3_256;

/// Verify ecdsa signature(sha2_256)
pub fn ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> Result<(), String> {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, |v| v)
}

/// Recover ecdsa public key(sha2_256)
pub fn ecdsa_recover(msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> Vec<u8> {
    inner_ecdsa_recover(msg, sig, hash256, |v| v)
}

/// Verify ecdsa signature(default: sha2_256)
pub fn inner_ecdsa_verify<F>(
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    hash256: Option<Hash256>,
    expand: F,
) -> Result<(), String>
    where
        F: Fn(Vec<u8>) -> Vec<u8>,
{
    let hash256 = hash256.unwrap_or(Hash256::Sha2_256);
    let hash = match hash256 {
        Hash256::Sha2_256 => sp_io::hashing::sha2_256(msg).to_vec(),
        Hash256::Sha3_256 => sha3_256(msg),
        Hash256::Keccak256 => sp_io::hashing::keccak_256(msg).to_vec(),
        Hash256::Blake2256 => sp_io::hashing::blake2_256(msg).to_vec(),
        Hash256::Twox256 => sp_io::hashing::twox_256(msg).to_vec(),
    };

    let hash = expand(hash);

    let mut msg = [0u8; 32];
    msg.copy_from_slice(&hash);
    let message = secp256k1::Message::parse(&msg);
    let signature = secp256k1::Signature::parse_slice(sig).map_err(|e| e.to_string())?;
    let pubkey = secp256k1::PublicKey::parse_slice(pubkey, None).map_err(|e| e.to_string())?;
    if !secp256k1::verify(&message, &signature, &pubkey) {
        return Err("ecdsa secp256k1 verify signature failed".to_string());
    }
    Ok(())
}

/// Recover ecdsa pubkey(default: sha2_256)
fn inner_ecdsa_recover<F>(msg: &[u8], sig: &[u8], hash256: Option<Hash256>, expand: F) -> Vec<u8>
    where
        F: Fn(Vec<u8>) -> Vec<u8>,
{
    let hash256 = hash256.unwrap_or(Hash256::Sha2_256);
    let hash = match hash256 {
        Hash256::Sha2_256 => sp_io::hashing::sha2_256(msg).to_vec(),
        Hash256::Sha3_256 => sha3_256(msg),
        Hash256::Keccak256 => sp_io::hashing::keccak_256(msg).to_vec(),
        Hash256::Blake2256 => sp_io::hashing::blake2_256(msg).to_vec(),
        Hash256::Twox256 => sp_io::hashing::twox_256(msg).to_vec(),
    };

    let hash = expand(hash);

    let mut msg = [0u8; 32];
    msg.copy_from_slice(&hash);
    let message = secp256k1::Message::parse(&msg);
    let signature = match secp256k1::Signature::parse_slice(&sig[..64]) {
        Ok(sig) => sig,
        Err(_) => return Vec::new(),
    };
    let recovery_id = match secp256k1::RecoveryId::parse(sig[64]) {
        Ok(recovery_id) => recovery_id,
        Err(_) => return Vec::new(),
    };
    match secp256k1::recover(&message, &signature, &recovery_id) {
        Ok(pk) => pk.serialize_compressed().to_vec(),
        Err(_) => Vec::new(),
    }
}
