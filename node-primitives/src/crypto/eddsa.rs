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

use sp_std::convert::TryFrom;

/// Verify ed25519 signature
pub fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use sp_core::ed25519::{Public, Signature};

    let pk = match Public::try_from(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature = match Signature::try_from(sig) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    sp_io::crypto::ed25519_verify(&signature, msg, &pk)
}