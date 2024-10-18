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

pub fn disintegrate_btc_msg(
    raw_msg: &str,
) -> Result<(Vec<String>, Vec<Vec<String>>, Vec<Vec<u64>>, bool), String> {
    let mut raw_msg = hex::decode(raw_msg).map_err(|e| e.to_string())?;
    if raw_msg.len() <= 2 {
        return Err(format!("msg length too short: {} ", raw_msg.len()));
    }

    // read taproot data.
    let is_taproot = raw_msg.pop().unwrap() == 1;
    if is_taproot {
        raw_msg.truncate(raw_msg.len() - 32);
    }

    let is_brc20 = raw_msg.pop().unwrap() == 1;
    if is_brc20 {
        // three tx's msg_hash offset num(u8)
        if raw_msg.len() <= 3 {
            return Err(format!("invalid brc20 tx length: {}", raw_msg.len()));
        }
        let transfer_tx_to_sign_num = raw_msg.pop().unwrap() as usize;
        let reveal_to_sign_num = raw_msg.pop().unwrap() as usize;
        let commit_tx_to_sign_num = raw_msg.pop().unwrap() as usize;
        let total_hash_num_to_sign =
            transfer_tx_to_sign_num + reveal_to_sign_num + commit_tx_to_sign_num;
        if raw_msg.len() <= total_hash_num_to_sign * 32 {
            return Err(format!("invalid brc20 msg length: {}", raw_msg.len()));
        }
        raw_msg.reverse();
        let all_to_sign = &mut raw_msg[..total_hash_num_to_sign * 32];
        all_to_sign.reverse();
        let mut commit_tx_to_sign = Vec::new();
        for i in 0..commit_tx_to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            commit_tx_to_sign.push(hex::encode(msg));
        }
        let mut reveal_tx_to_sign = Vec::new();
        for i in commit_tx_to_sign_num..commit_tx_to_sign_num + reveal_to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            reveal_tx_to_sign.push(hex::encode(msg));
        }

        let mut transfer_tx_to_sign = Vec::new();
        for i in commit_tx_to_sign_num + reveal_to_sign_num..total_hash_num_to_sign {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            transfer_tx_to_sign.push(hex::encode(msg));
        }

        // todo: use struct
        // |commit_tx_raw|reveal_tx_raw|transfer_tx_raw|commit_tx_len|reveal_tx_len|transfer_tx_len|
        let tx_msgs_with_offset = &mut raw_msg[total_hash_num_to_sign * 32..].to_vec();
        if tx_msgs_with_offset.len() <= 3 * 4 {
            return Err(format!(
                "brc20 raw msg off set error, raw msg len: {}",
                tx_msgs_with_offset.len()
            ));
        }
        let (transfer_tx_len_bytes, reset1) = tx_msgs_with_offset.split_at_mut(4);
        let (reveal_tx_len_bytes, reset2) = reset1.split_at_mut(4);
        let (commit_tx_len_bytes, reset3) = reset2.split_at_mut(4);
        transfer_tx_len_bytes.reverse();
        reveal_tx_len_bytes.reverse();
        commit_tx_len_bytes.reverse();
        let mut transfer_tx_len_tmp = [0u8; 4];
        transfer_tx_len_tmp.copy_from_slice(&transfer_tx_len_bytes);
        let mut reveal_tx_len_tmp = [0u8; 4];
        reveal_tx_len_tmp.copy_from_slice(&reveal_tx_len_bytes);
        let mut commit_tx_len_tmp = [0u8; 4];
        commit_tx_len_tmp.copy_from_slice(&commit_tx_len_bytes);

        let transfer_tx_len = u32::from_le_bytes(transfer_tx_len_tmp) as usize;
        let reveal_tx_len = u32::from_le_bytes(reveal_tx_len_tmp) as usize;
        let commit_tx_len = u32::from_le_bytes(commit_tx_len_tmp) as usize;

        if reset3.len() != (transfer_tx_len + reveal_tx_len + commit_tx_len) {
            return Err(format!(
                "invalid brc20 raw msg length: {}, expect: {}",
                reset3.len(),
                (transfer_tx_len + reveal_tx_len + commit_tx_len)
            ));
        }

        let mut transfer_tx = reset3[..transfer_tx_len].as_ref().to_vec();
        let mut reveal_tx = reset3[transfer_tx_len..transfer_tx_len + reveal_tx_len]
            .as_ref()
            .to_vec();
        let mut commit_tx = reset3[transfer_tx_len + reveal_tx_len..].as_ref().to_vec();
        transfer_tx.reverse();
        reveal_tx.reverse();
        commit_tx.reverse();

        Ok((
            vec![
                hex::encode(commit_tx),
                hex::encode(reveal_tx),
                hex::encode(transfer_tx),
            ],
            vec![commit_tx_to_sign, reveal_tx_to_sign, transfer_tx_to_sign],
            vec![],
            is_brc20,
        ))
    } else {
        let to_sign_num = raw_msg.pop().unwrap() as usize;
        if raw_msg.len() <= to_sign_num * 8 + to_sign_num * 32 {
            return Err("invalid message length".to_string());
        }
        raw_msg.reverse();
        let all_values = &mut raw_msg[0..to_sign_num * 8].to_vec(); // [0..16]
        let all_to_sign =
            &mut raw_msg[to_sign_num * 8..(to_sign_num * 8 + to_sign_num * 32)].to_vec(); // [16..80]
        let msg_vec = &mut raw_msg[(to_sign_num * 8 + to_sign_num * 32)..].to_vec();
        all_values.reverse();
        all_to_sign.reverse();
        msg_vec.reverse();
        let raw_tx = hex::encode(&msg_vec); // [80..]
        let mut messages_should_sign = Vec::new();
        for i in 0..to_sign_num {
            let msg = &all_to_sign[i * 32..(i + 1) * 32];
            messages_should_sign.push(hex::encode(msg));
        }
        let mut values = Vec::new();
        let value_num = all_values.len() / 8usize;
        for i in 0..value_num {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&all_values[i * 8..(i + 1) * 8]);
            values.push(u64::from_le_bytes(tmp))
        }
        Ok((
            vec![raw_tx],
            vec![messages_should_sign],
            vec![values],
            is_brc20,
        ))
    }
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
            for i in 0..msg.1.len() {
                let batch_msg = &msg.1[i];
                for j in 0..batch_msg.len() {
                    match hex::decode(&batch_msg[j]) {
                        Ok(msg) => msgs.push(msg),
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
