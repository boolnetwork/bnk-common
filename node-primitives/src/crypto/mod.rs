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

use bnk_chain_bridge::utils::disintegrate_fil_msg;
use secp256k1::Message;
use sp_std::vec::Vec;

pub use bls::*;
pub use ecdsa::*;
pub use eddsa::*;
pub use schnorr::*;
pub use sp_io::hashing::sha2_256;

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

pub fn verify_filecoin(pubkey: &[u8], raw: &[u8], sig: &[u8], engine: &str) -> bool {
    let msg_vec = match disintegrate_fil_msg(&hex::encode(raw), engine) {
        Ok(param) => param.1,
        Err(e) => {
            log::error!("invalid filecoin msgs to parse: {:?}", e);
            return false;
        }
    };
    match engine {
        "ECDSA" => {
            let mut msg = [0; 32];
            msg.copy_from_slice(&msg_vec);
            let message = Message::parse(&msg);
            let signature = match secp256k1::Signature::parse_slice(&sig[..64]) {
                Ok(sig) => sig,
                Err(e) => {
                    log::error!("parse filecoin ecdsa signature failed for: {:?}", e);
                    return false;
                }
            };
            let pubkey = match secp256k1::PublicKey::parse_slice(pubkey, None) {
                Ok(pk) => pk,
                Err(e) => {
                    log::error!("parse filecoin ecdsa pubkey failed for: {:?}", e);
                    return false;
                }
            };
            if !secp256k1::verify(&message, &signature, &pubkey) {
                log::error!("filecoin ecdsa signature verify failed");
                return false;
            }
        }
        "BLS" => {
            let mut msg = [0; 38];
            msg.copy_from_slice(&msg_vec);
            return bls_verify(pubkey, &msg, sig);
        }
        _ => return false,
    }
    true
}

/// Verify ecdsa signature(sha2_256)
fn inner_ecdsa_verify<F>(
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    hash256: Option<Hash256>,
    expand: F,
) -> bool
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
    let signature = match secp256k1::Signature::parse_slice(sig) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let pubkey = match secp256k1::PublicKey::parse_slice(pubkey, None) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    secp256k1::verify(&message, &signature, &pubkey)
}

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
