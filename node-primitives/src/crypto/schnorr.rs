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

use core::ops::Neg;
use secp256k1::curve::{Affine, Jacobian, Scalar, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT};
use secp256k1::{Error as ECError, PublicKey as ECPK, PublicKeyFormat, SecretKey as ECSK};
use sha2::{Digest, Sha256};
use sp_std::convert::TryFrom;
use crate::disintegrate_btc_msgs_and_sigs;

pub fn sr25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use sp_core::sr25519::{Public, Signature};

    let pk = match Public::try_from(pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("failed to parse sr25519 public: {:?}", e);
            return false;
        }
    };
    let signature = match Signature::try_from(sig) {
        Ok(signature) => signature,
        Err(e) => {
            log::error!("failed to parse sr25519 signature: {:?}", e);
            return false;
        }
    };
    sp_io::crypto::sr25519_verify(&signature, msg, &pk)
}

// H(R, X, m)
fn sr_secp256k1_hash(r: &[u8], x: &[u8], m: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(r);
    hasher.update(x);
    hasher.update(m);

    let result_hex = hasher.finalize();

    let mut bin = [0u8; 32];
    bin.copy_from_slice(&result_hex[..]);
    let mut h = Scalar::default();
    let _ = h.set_b32(&bin);
    h
}

pub fn sr_secp256k1_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 65 {
        log::error!("invalid length of signature.");
        return false;
    }

    let r: ECSK = match ECSK::parse_slice(&signature[..32]) {
        Ok(sr) => sr,
        Err(e) => {
            log::error!("failed to parse r from signature: {:?}", e);
            return false;
        }
    };
    let v: ECPK = match ECPK::parse_slice(&signature[32..], Some(PublicKeyFormat::Compressed)) {
        Ok(sv) => sv,
        Err(e) => {
            log::error!("failed to parse v from signature: {:?}", e);
            return false;
        }
    };
    let pk: ECPK = match ECPK::parse_slice(pubkey, Some(PublicKeyFormat::Full)) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("failed to parse public key: {:?}, error: {:?}", pubkey, e);
            return false;
        }
    };
    let e = sr_secp256k1_hash(
        &v.serialize_compressed(),
        &pk.serialize_compressed(),
        message,
    );
    let mut e_y_j = Jacobian::default();
    ECMULT_CONTEXT.ecmult_const(&mut e_y_j, &pk.into(), &e);

    let e_y_plus_v_j = e_y_j.add_ge(&v.into());

    let mut g_j_s = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut g_j_s, &r.into());

    let g_s = Affine::from_gej(&g_j_s);
    let e_y_plus_v: Affine = Affine::from_gej(&e_y_plus_v_j);

    // R + H(R,X,m) * X = s * G
    return e_y_plus_v == g_s;
}

// SHA256 (SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge")||R.x||P.x||M)
pub fn bitcoin_sha256_tagged(r_x: &[u8], p_x: &[u8], m: &[u8]) -> Scalar {
    // SHA256("BIP0340/challenge")
    const CHALLENGE_PREFIX: [u8; 32] = [
        123u8, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130, 210, 243, 242,
        216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124,
    ];

    let mut hasher = Sha256::new();

    // add prefix
    hasher.update(CHALLENGE_PREFIX);
    hasher.update(CHALLENGE_PREFIX);

    hasher.update(r_x);
    hasher.update(p_x);
    hasher.update(m);

    let result_hex = hasher.finalize();

    let mut bin = [0u8; 32];
    bin.copy_from_slice(&result_hex[..]);
    let mut h = Scalar::default();
    let _ = h.set_b32(&bin);
    h
}

pub fn load_xonly_pubkey(pubkey: &[u8]) -> Result<ECPK, ECError> {
    if pubkey.len() != 32 {
        return Err(ECError::InvalidPublicKey);
    }
    let mut tmp = [2u8; 33];
    tmp[1..].copy_from_slice(pubkey);
    ECPK::parse_compressed(&tmp)
}

// https://github.com/joschisan/schnorr_secp256k1/blob/main/src/schnorr.rs#LL90C1-L90C1
pub fn btc_schnorr_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        log::error!("invalid length of signature.");
        return false;
    }

    if pubkey.len() != 32 {
        log::error!("invalid length of public key.");
        return false;
    }

    let p: ECPK = match load_xonly_pubkey(&pubkey) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("failed to parse public key: {:?}, error: {:?}", pubkey, e);
            return false;
        }
    };
    
    let r: ECPK = match load_xonly_pubkey(&signature[..32]) {
        Ok(r) => r,
        Err(e) => {
            log::error!("failed to parse r from signature: {:?}", e);
            return false;
        }
    };
    let s: ECSK = match ECSK::parse_slice(&signature[32..]) {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to parse s from signature: {:?}", e);
            return false;
        }
    };

    // compute e
    let e = bitcoin_sha256_tagged(&signature[..32], &pubkey, message);

    // Compute rj =  s*G + (-e)*pkj
    let mut e_p_j = Jacobian::default();
    let e = e.neg();
    ECMULT_CONTEXT.ecmult_const(&mut e_p_j, &p.into(), &e);

    let mut g_j_s = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut g_j_s, &s.into());

    let rj = e_p_j.add_var(&g_j_s, None);
    let mut rx = Affine::from_gej(&rj);
    if rx.is_infinity() {
        return false;
    }

    rx.x.normalize_var();
    rx.y.normalize_var();
    let r: Affine = r.into();

    return !rx.y.is_odd() && rx.x == r.x;
}

pub fn verify_btc_schnorr(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (msgs, sigs) = match disintegrate_btc_msgs_and_sigs(msg, sig, false) {
        Some(data) => data,
        None => {
            log::error!("disintegrate btc msgs and sigs failed");
            return false
        }
    };
    if msgs.len() != sigs.len() {
        log::error!("invalid length for btc msgs and sigs");
        return false
    }
    let pubkey = match pubkey.len() {
        33 | 65 => &pubkey[1..33],
        _ => &pubkey
    };
    for i in 0..msgs.len() {
        if !btc_schnorr_verify(pubkey, &msgs[i], &sigs[i]) {
            log::error!("btc signature verify failed");
            return false
        }
    }
    true
}

// 0x
// ca1883c8121363c529bc47fabfa50f372458873a908ff0caa39dc0747f2491c4e9a05e612a4c71b12d339cebd74115fe19e346edb622186bd185ecaec12b4533
// 6dcac02ede07fa40c07bb0307b8d341e711c547af52fcd353881fe4346ed784fe822f9006883f548870f82202b5e8feaef5182a49d9eeb90616eccd3fcfbb94e
// 2074a9ac84fa4c1c773cfa7780cd0df2fb30167825f9890a5ad6508b6f9583b618cb85b14896faaf718c2d3ec5676c468a0a899a69f0f5aaeafc1dc2197fba86
#[test]
pub fn test_btc_schnorr_verify() {
    let signature = "d569f1d9dd2feb75d8b8bedf3c08dbc256b1d73f416fe3146bc3327a7cb5d3d3815d430aa6e2eadc746468ef7efc398d6fa271b84aa1c28336ecdde027cf4753";
    let msg = "06ae15dbb89d50f1baaab17929cd464c6592d83ff99cb3a5e01a75e328bdaae2";
    let pubkey = "7e95a10448c199672d0af43fc85ee42f8956ed728ba9fe4ecc4d909a0162575d";

    let signature = hex::decode(signature).unwrap();
    let msg = hex::decode(msg).unwrap();
    let pubkey = hex::decode(pubkey).unwrap();
    btc_schnorr_verify(&pubkey, &msg, &signature);
    assert!(btc_schnorr_verify(&pubkey, &msg, &signature))
}