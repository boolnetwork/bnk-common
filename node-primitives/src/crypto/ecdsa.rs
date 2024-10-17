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

use super::{inner_ecdsa_recover, inner_ecdsa_verify, Hash256};
use scale_info::prelude::format;
use scale_info::prelude::string::String;
use sp_core::U256;
use sp_std::{vec, vec::Vec};

/// Verify ecdsa signature(sha2_256)
pub fn ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> bool {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, |v| v)
}

/// Recover ecdsa public key(sha2_256)
pub fn ecdsa_recover(msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> Vec<u8> {
    inner_ecdsa_recover(msg, sig, hash256, |v| v)
}

/// Verify eth ecdsa signature(sha2_256)
pub fn eth_ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> bool {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, to_eth_signed_message_hash)
}

/// Verify tron ecdsa signature(sha2_256)
pub fn tron_ecdsa_verify(pubkey: &[u8], msg: &[u8], sig: &[u8], hash256: Option<Hash256>) -> bool {
    inner_ecdsa_verify(pubkey, msg, sig, hash256, to_tron_signed_message_hash)
}

pub fn verify_btc_ecdsa(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (msgs, sigs) = match disintegrate_btc_msgs_and_sigs(msg, sig, true) {
        Some(data) => data,
        None => {
            log::error!("disintegrate btc msgs and sigs failed");
            return false;
        }
    };
    if msgs.len() != sigs.len() {
        log::error!("invalid length for btc msgs and sigs");
        return false;
    }
    for i in 0..msgs.len() {
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&msgs[i]);
        let message = secp256k1::Message::parse(&msg);
        let signature = match secp256k1::Signature::parse_slice(&sigs[i][..64]) {
            Ok(sig) => sig,
            Err(e) => {
                log::error!("parse btc signature failed for: {:?}", e);
                return false;
            }
        };
        let pubkey = match secp256k1::PublicKey::parse_slice(pubkey, None) {
            Ok(pk) => pk,
            Err(e) => {
                log::error!("parse btc pubkey failed for: {:?}", e);
                return false;
            }
        };
        if !secp256k1::verify(&message, &signature, &pubkey) {
            log::error!("btc signature verify failed");
            return false;
        }
    }
    true
}

pub fn verify_ckb_ecdsa(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_btc_ecdsa(pubkey, msg, sig)
}

pub fn disintegrate_btc_msgs_and_sigs(
    msg: &[u8],
    sig: &[u8],
    is_ecdsa: bool,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let msgs = match bnk_chain_bridge::utils::disintegrate_btc_msg(&hex::encode(msg)) {
        Ok(msg) => {
            let mut msgs = Vec::new();
            for i in 0..msg.1.len() {
                let batch_msg = &msg.1[i];
                for j in 0..batch_msg.len() {
                    match hex::decode(&batch_msg[j]) {
                        Ok(msg) => msgs.push(msg),
                        Err(e) => {
                            log::error!("hex decode failed for: {:?}", e);
                            return None;
                        }
                    }
                }
            }
            msgs
        }
        Err(e) => {
            log::error!("disintegrate btc msg failed for: {:?}", e);
            return None;
        }
    };
    let sigs = match disintegrate_btc_signatures(sig.to_vec(), is_ecdsa) {
        Some(sigs) => sigs,
        None => return None,
    };
    if msgs.len() != sigs.len() {
        return None;
    }
    Some((msgs, sigs))
}

fn to_eth_signed_message_hash(msg: Vec<u8>) -> Vec<u8> {
    bnk_chain_bridge::utils::to_eth_signed_message_hash(&msg, sp_io::hashing::keccak_256)
}

pub fn to_tron_signed_message_hash(msg: Vec<u8>) -> Vec<u8> {
    bnk_chain_bridge::utils::to_eth_signed_message_hash(&msg, sp_io::hashing::keccak_256)
}

fn disintegrate_btc_signatures(raw_sig: Vec<u8>, is_ecdsa: bool) -> Option<Vec<Vec<u8>>> {
    let sig_len = if is_ecdsa { 65 } else { 64 };
    if raw_sig.len() < sig_len || raw_sig.len() % sig_len != 0 {
        log::error!("invalid raw_sig length: {:?}", raw_sig.len());
        return None;
    }
    let mut all_sigs = Vec::new();
    let sig_num = raw_sig.len() / sig_len as usize;
    for i in 0..sig_num {
        let sig = &raw_sig.as_slice()[i * sig_len..(i + 1) * sig_len];
        all_sigs.push(sig.to_vec());
    }
    Some(all_sigs)
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

#[test]
fn test_eth_abi_encode() {
    let mut nonce = [0u8; 32];
    U256::from(1).to_big_endian(&mut nonce);
    let bytes = eth_abi_encode_for_random_num(
        31337,
        &hex::decode("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac").unwrap(),
        &hex::decode("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0").unwrap(),
        nonce.as_slice(),
        &hex::decode("c2c68711b3ca322f219051da719406d55c9d6842a0af46bb9d391802830861be").unwrap(),
    )
    .unwrap();

    println!("bytes: {:?}", hex::encode(bytes));

    let msg = "02000000000101c26797f01a735974f08d31bd04cebe78f8ccf2470f2fc96efa5684036e47b1a00100000000fdffffff025802000000000000225120fe030062aac48064b60e5856dc6927a095795786a63c19cc9e3dd3cd7dc8e656a4b10000000000002251207e95a10448c199672d0af43fc85ee42f8956ed728ba9fe4ecc4d909a0162575d0140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000101e979b5b3bd3a5662f7c596cd273ba022c6c634977f682235da4979d647f2f7ff0000000000fdffffff01c1010000000000002251207e95a10448c199672d0af43fc85ee42f8956ed728ba9fe4ecc4d909a0162575d0340000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c207e95a10448c199672d0af43fc85ee42f8956ed728ba9fe4ecc4d909a0162575dac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800367b2270223a226272632d3230222c226f70223a227472616e73666572222c227469636b223a2273617473222c22616d74223a2231227d6821c07e95a10448c199672d0af43fc85ee42f8956ed728ba9fe4ecc4d909a0162575d00000000020000000001011cd0aa5a7a573cac85c417a41f9055fcc9df7a82fe6a9e9a0ae786b05c94b6cb0000000000fdffffff023301000000000000160014bf2ea035e25fbfcbb4b12fee9f708649d5e5e7290000000000000000226a204804211e4d45db413a0a06ba3b4e2dec92dc642f828662358b2c4136d9dbf03001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd00000041010000c1000000007b993362dfc238f3348722c98b95b9b39c47a2a8e5374db19deffe30aa79dd1580f82e74a0f05e819ffd263aca7ff8a85960c24765c14e6fda7f7ad9e4b9c306ae15dbb89d50f1baaab17929cd464c6592d83ff99cb3a5e01a75e328bdaae201010101";
    let (txs, hash_to_sign, _values, is_brc20) =
        bnk_chain_bridge::utils::disintegrate_btc_msg(msg).unwrap();
    println!("txs: {txs:?}, hash_to_sign: {hash_to_sign:?}, is_brc20: {is_brc20:?}");
}
