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

use bls_signatures::{verify as verify_bls_sig, Serialize};

pub fn bls_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk = match bls_signatures::PublicKey::from_bytes(&pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("parse filecoin bls pubkey failed for: {:?}", e);
            return false;
        }
    };

    // generate signature struct from bytes
    let sig = match bls_signatures::Signature::from_bytes(sig) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("parse filecoin bls signature failed for: {:?}", e);
            return false;
        }
    };
    let hashed = bls_signatures::hash(&msg);
    // BLS verify hash against key
    if !verify_bls_sig(&sig, &[hashed], &[pk]) {
        log::error!("filecoin bls signature verify failed");
        return false;
    }
    true
}
