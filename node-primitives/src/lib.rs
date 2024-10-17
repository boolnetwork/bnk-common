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

//! Low-level types used throughout the code.

#![allow(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod crypto;
pub mod error;
pub mod rpc;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
pub use secp256k1::*;
use sha3::{Digest, Keccak256};
use sp_core::{ecdsa, H160, H256};
pub use sp_io::hashing::sha2_256;
use sp_runtime::{generic, traits::{BlakeTwo256, IdentifyAccount, Verify}, OpaqueExtrinsic, RuntimeDebug};
pub use crypto::*;
pub use error::*;
pub use rpc::*;
// use fp_account::EthereumSignature;

#[cfg(feature = "serde")]
use sp_std::hash::Hash as HashT;

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = BnkSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// The type for looking up accounts. We don't expect more than 4 billion of them.
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = u128;

/// Type used for expressing timestamp.
pub type Moment = u64;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// A timestamp: milliseconds since the unix epoch.
/// `u64` is enough to represent a duration of half a billion years, when the
/// time scale is milliseconds.
pub type Timestamp = u64;

/// Digest item type.
pub type DigestItem = generic::DigestItem;
/// Header type.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type.
pub type Block = generic::Block<Header, OpaqueExtrinsic>;
/// Block ID.
pub type BlockId = generic::BlockId<Block>;

/// The account type to be used in BoolNetwork. It is compatible with the ethereum.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "serde", derive(HashT))]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "serde")]
impl_serde::impl_fixed_hash_serde!(AccountId20, 20);

#[cfg(feature = "std")]
impl std::fmt::Display for AccountId20 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl core::fmt::Debug for AccountId20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", H160(self.0))
    }
}

impl From<[u8; 20]> for AccountId20 {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; 20]> for AccountId20 {
    fn into(self) -> [u8; 20] {
        self.0
    }
}

impl From<H160> for AccountId20 {
    fn from(h160: H160) -> Self {
        Self(h160.0)
    }
}

#[cfg(feature = "std")]
impl TryFrom<&[u8]> for AccountId20 {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("invalid account bytes length".to_string())
        }
        let mut account = [0u8; 20];
        account.copy_from_slice(&bytes[..20]);
        Ok(account.into())
    }
}

impl Into<H160> for AccountId20 {
    fn into(self) -> H160 {
        H160(self.0)
    }
}

#[cfg(feature = "std")]
impl std::str::FromStr for AccountId20 {
    type Err = &'static str;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        H160::from_str(input)
            .map(Into::into)
            .map_err(|_| "invalid hex address.")
    }
}

mod app {
    use sp_application_crypto::{app_crypto, ecdsa};
    use sp_core::crypto::KeyTypeId;

    const KEY_TYPE_ID: KeyTypeId = KeyTypeId(*b"aura");

    app_crypto!(ecdsa, KEY_TYPE_ID);
}

sp_application_crypto::with_pair! {
    /// An Aura authority keypair using ecdsa as its crypto.
    pub type AuthorityPair = app::Pair;
}

/// Public key for an Ethereum / BoolNetwork compatible account
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct BnkSigner([u8; 20]);

impl sp_runtime::traits::IdentifyAccount for BnkSigner {
    type AccountId = AccountId20;
    fn into_account(self) -> AccountId20 {
        AccountId20(self.0)
    }
}

impl From<[u8; 20]> for BnkSigner {
    fn from(x: [u8; 20]) -> Self {
        BnkSigner(x)
    }
}

impl From<ecdsa::Public> for BnkSigner {
    fn from(x: ecdsa::Public) -> Self {
        let decompressed =
            secp256k1::PublicKey::parse_slice(&x.0, Some(secp256k1::PublicKeyFormat::Compressed))
                .expect("Wrong compressed public key provided")
                .serialize();
        let mut m = [0u8; 64];
        m.copy_from_slice(&decompressed[1..65]);
        let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
        BnkSigner(account.into())
    }
}

impl From<secp256k1::PublicKey> for BnkSigner {
    fn from(x: secp256k1::PublicKey) -> Self {
        let mut m = [0u8; 64];
        m.copy_from_slice(&x.serialize()[1..65]);
        let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
        BnkSigner(account.into())
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for BnkSigner {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ethereum signature: {:?}", H160::from_slice(&self.0))
    }
}

/// Signature for an Ethereum / BoolNetwork compatible account
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub struct BnkSignature(ecdsa::Signature);

impl From<ecdsa::Signature> for BnkSignature {
    fn from(x: ecdsa::Signature) -> Self {
        BnkSignature(x)
    }
}

impl sp_runtime::traits::Verify for BnkSignature {
    type Signer = BnkSigner;
    fn verify<L: sp_runtime::traits::Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId20) -> bool {
        let m = sp_io::hashing::keccak_256(msg.get());
        match sp_io::crypto::secp256k1_ecdsa_recover(self.0.as_ref(), &m) {
            Ok(pubkey) => {
                let account = AccountId20::from(H160::from_slice(
                    &sp_io::hashing::keccak_256(pubkey.as_ref())[12..],
                ));
                account == *signer
            }
            Err(sp_io::EcdsaVerifyError::BadRS) => {
                log::error!(target: "evm", "Error recovering: Incorrect value of R or S");
                false
            }
            Err(sp_io::EcdsaVerifyError::BadV) => {
                log::error!(target: "evm", "Error recovering: Incorrect value of V");
                false
            }
            Err(sp_io::EcdsaVerifyError::BadSignature) => {
                log::error!(target: "evm", "Error recovering: Invalid signature");
                false
            }
        }
    }
}

#[test]
fn test_evm_addr() {
    let pk = &hex::decode("040534412bfd27bcaddd571ddb1ac05f90a177e30545126772e957c912375332bda593b692277ee1b8cf1744427d6289785df12ee26e0606898e6e379e6c077cd6").unwrap()[1..];
    let addr = &sp_io::hashing::keccak_256(pk.as_ref())[12..];
    println!("addr: {:?}", hex::encode(addr));
    let a = hex::decode("02e178cd5342c7629e3a547f0075544b136962e701cfc119a6900272da15aa4b").unwrap();
    println!("a: {:?}", a);


    let name = b"BoolNetwork";
    let addr = &sp_io::hashing::sha2_256(name.as_ref());
    println!("addr: {:?}", hex::encode(addr));
}