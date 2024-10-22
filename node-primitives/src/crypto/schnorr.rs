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

use sp_core::bounded::alloc::{string::{ToString, String}, format};
use core::ops::Neg;
use bnk_chain_bridge::utils::disintegrate_btc_msgs_and_sigs;
use secp256k1::curve::{Affine, Jacobian, Scalar, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT};
use secp256k1::{Error as ECError, PublicKey as ECPK, PublicKeyFormat, SecretKey as ECSK};
use sha2::{Digest, Sha256};

pub fn sr25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use sp_core::sr25519::{Public, Signature};

    let pk = Public::try_from(pubkey).map_err(|_| "sr25519 pubkey from bytes".to_string())?;
    let signature = Signature::try_from(sig).map_err(|_| "sr25519 signature from bytes".to_string())?;
    if !sp_io::crypto::sr25519_verify(&signature, msg, &pk) {
        return Err("verify sr25519 signature failed".to_string());
    }
    Ok(())
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

pub fn sr_secp256k1_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    if signature.len() != 65 {
        return Err("invalid length of sr secp256k1 signature".to_string());
    }
    let r: ECSK = ECSK::parse_slice(&signature[..32]).map_err(|e| format!("failed to parse r from signature: {:?}", e))?;
    let v: ECPK = ECPK::parse_slice(&signature[32..], Some(PublicKeyFormat::Compressed)).map_err(|e| format!("failed to parse v from signature: {:?}", e))?;
    let pk: ECPK = ECPK::parse_slice(pubkey, Some(PublicKeyFormat::Full)).map_err(|e| format!("failed to parse public key: {:?}, error: {:?}", pubkey, e))?;
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
    if e_y_plus_v != g_s {
        return Err("verify sr secp256k1 signature failed".to_string());
    }
    Ok(())
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
pub fn btc_schnorr_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    if signature.len() != 64 {
        return Err("invalid length of btc schnorr signature".to_string());
    }
    if pubkey.len() != 32 {
        return Err("invalid length of btc schnorr public key".to_string());
    }
    let p: ECPK = load_xonly_pubkey(&pubkey).map_err(|e| e.to_string())?;
    let r: ECPK = load_xonly_pubkey(&signature[..32]).map_err(|e| e.to_string())?;
    let s: ECSK = ECSK::parse_slice(&signature[32..]).map_err(|e| e.to_string())?;

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
        return Err("verify btc schnorr signature failed for rx is infinity".to_string());
    }

    rx.x.normalize_var();
    rx.y.normalize_var();
    let r: Affine = r.into();

    if rx.y.is_odd() {
        return Err("verify btc schnorr signature failed for rx.y is odd".to_string());
    }
    if rx.x != r.x {
        return Err("verify btc schnorr signature failed for rx.x is not eq to r.x".to_string());
    }
    return Ok(())
}

pub fn verify_btc_schnorr(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let (msgs, sigs) = match disintegrate_btc_msgs_and_sigs(msg, sig, false) {
        Some(data) => data,
        None => {
            return Err("disintegrate btc msgs and sigs failed".to_string());
        }
    };
    if msgs.len() != sigs.len() {
        return Err("invalid length for btc msgs and sigs".to_string());
    }
    let pubkey = match pubkey.len() {
        33 | 65 => &pubkey[1..33],
        _ => &pubkey
    };
    for i in 0..msgs.len() {
        btc_schnorr_verify(
            pubkey,
            &msgs[i],
            &sigs[i],
        ).map_err(|e| format!("btc signature verify failed: {e:?} for index: {i:?}"))?;
    }
    Ok(())
}

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