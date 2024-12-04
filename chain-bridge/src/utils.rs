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

use codec::{Encode, Decode};

#[derive(Encode, Decode, PartialEq, Clone, Debug)]
pub enum AssetType {
    Native,
    Brc20,
    Runes,
}

#[derive(Encode, Decode, PartialEq, Clone, Debug)]
pub struct BtcTxMessage {
    pub txs: Vec<BtcSingleTx>,
    pub asset: AssetType,
    pub taproot_data: Option<Vec<u8>>,
}

#[derive(Encode, Decode, PartialEq, Clone, Debug)]
pub struct BtcSingleTx {
    pub raw_hex: String,
    pub hash_to_sign: Vec<String>,
    pub input_values: Vec<u64>,
}

pub fn disintegrate_btc_msg(
    raw_msg: &str,
) -> Result<BtcTxMessage, String> {
    let raw_msg = hex::decode(raw_msg).map_err(|e| e.to_string())?;
    let btc_msg = BtcTxMessage::decode(
        &mut raw_msg.as_slice(),
    ).map_err(|e| format!("BtcTxMessage decode from raw msg faild for: {e:?}"))?;

    match btc_msg.asset {
        AssetType::Native | AssetType::Runes => {
            if btc_msg.txs.len() != 1 {
                return Err(format!("btc msg invalid tx num {}, expect 1", btc_msg.txs.len()));
            }
            for tx in &btc_msg.txs {
                if tx.hash_to_sign.is_empty() {
                    return Err(
                        format!(
                            "invalid tx hash legnth to sign {}",
                            tx.hash_to_sign.len(),
                        )
                    );
                }
                if tx.hash_to_sign.len() != tx.input_values.len() {
                    return Err(
                        format!(
                            "btc msg invalid hash_to_sign num {} with input_values num {}",
                            tx.hash_to_sign.len(),
                            tx.input_values.len()
                        )
                    );
                }
            }
        },
        AssetType::Brc20 => {
            if btc_msg.txs.len() != 3 {
                return Err(format!("btc msg invalid tx num {}, expect 3", btc_msg.txs.len()));
            }
            for tx in &btc_msg.txs {
                if tx.hash_to_sign.is_empty() {
                    return Err(
                        format!(
                            "invalid tx hash legnth to sign {}",
                            tx.hash_to_sign.len(),
                        )
                    );
                }
            }
        }
    }
    Ok(btc_msg)
}

fn disintegrate_btc_signatures(raw_sig: Vec<u8>, is_ecdsa: bool) -> Option<Vec<Vec<u8>>> {
    let sig_len = if is_ecdsa { 65 } else { 64 };
    if raw_sig.len() < sig_len || raw_sig.len() % sig_len != 0 {
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

pub fn disintegrate_btc_msgs_and_sigs(
    msg: &[u8],
    sig: &[u8],
    is_ecdsa: bool,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let msgs = match disintegrate_btc_msg(&hex::encode(msg)) {
        Ok(msg) => {
            let mut msgs = Vec::new();
            for tx in msg.txs {
                for hash in tx.hash_to_sign {
                    match hex::decode(&hash) {
                        Ok(hash) => msgs.push(hash),
                        Err(_) => {
                            return None;
                        }
                    }
                }
            }
            msgs
        }
        Err(_) => {
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

pub fn disintegrate_fil_msg(raw_msg: &str, engine: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut raw_msg = hex::decode(raw_msg).map_err(|e| e.to_string())?;
    let hash_length = match engine {
        "ECDSA" => 32,
        "BLS" => 38,
        _ => unimplemented!(),
    };
    if raw_msg.len() <= hash_length {
        return Err("invalid message length".to_string());
    }
    raw_msg.reverse();
    let msg_need_to_sign = &mut raw_msg[..hash_length].to_vec();
    let raw_tx = &mut raw_msg[hash_length..].to_vec();
    msg_need_to_sign.reverse();
    raw_tx.reverse();
    Ok((raw_tx.to_vec(), msg_need_to_sign.to_vec()))
}

pub const PREFIX: &str = "\x19Ethereum Signed Message:\n";

pub fn to_eth_signed_message_hash<F, V: AsRef<[u8]>>(msg: &[u8], keccak256: F) -> Vec<u8>
    where F: Fn(&[u8]) -> V
{
    let mut eth_message = format!("{}{}", PREFIX, msg.len()).into_bytes();
    eth_message.extend_from_slice(msg);
    keccak256(&eth_message).as_ref().to_vec()
}

pub const TRON_PREFIX: &str = "\x19TRON Signed Message:\n";

pub fn to_tron_signed_message_hash<F, V: AsRef<[u8]>>(msg: &[u8], keccak256: F) -> Vec<u8>
    where F: Fn(&[u8]) -> V
{
    let mut tron_message = format!("{}{}", TRON_PREFIX, msg.len()).into_bytes();
    tron_message.extend_from_slice(msg);
    keccak256(&tron_message).as_ref().to_vec()
}
