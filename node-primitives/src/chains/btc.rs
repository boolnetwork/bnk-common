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

use bnk_chain_bridge::utils::disintegrate_btc_msgs_and_sigs;

pub fn verify_btc_ecdsa(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let (msgs, sigs) = match disintegrate_btc_msgs_and_sigs(msg, sig, true) {
        Some(data) => data,
        None => {
            return Err("disintegrate btc msgs and sigs failed".to_string());
        }
    };
    if msgs.len() != sigs.len() {
        return Err("invalid length for btc msgs and sigs".to_string());
    }
    for i in 0..msgs.len() {
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&msgs[i]);
        let message = secp256k1::Message::parse(&msg);
        let signature = secp256k1::Signature::parse_slice(&sigs[i][..64]).map_err(|e| e.to_string())?;
        let pubkey = secp256k1::PublicKey::parse_slice(pubkey, None).map_err(|e| e.to_string())?;
        if !secp256k1::verify(&message, &signature, &pubkey) {
            return Err("btc ecdsa signature verify failed".to_string());
        }
    }
    Ok(())
}
