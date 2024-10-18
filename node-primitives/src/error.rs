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

#[cfg(feature = "std")]
pub use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(feature = "std")]
use std::fmt;

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    jsonrpc: String,
    pub error: ErrorData,
    id: u32
}

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorData {
    code: u32,
    message: String,
    pub data: String,
}

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum CustomError {
    InvalidSession = 0,
    NoNeedToSendHeartbeat = 1,
    HeartbeatExist = 2,
    ImOnlineInvalidSignature = 3,
    InvalidForkId = 4,
    InvalidCmtStatus = 5,
    NotAllowFork = 6,
    InvalidRvrfDuration = 7,
    InvalidRvrfProof = 8,
    CandidatesExist = 9,
    CandidatesEnough = 10,
    InvalidTxSender = 11,
    InvalidTxSenderSignature = 12,
    InvalidEpoch = 13,
    InvalidCmtPubkey = 14,
    NoRewardsForFork = 15,
    NoRewardsForMember = 16,
    InvalidTxStatus = 17,
    InvalidCmtSignature = 18,
    NotCmtMember = 19,
    TxTimeout = 20,
    NoSourceHash = 21,
    InvalidSourceHash = 22,
    InvalidBtcTxTunnelStatus = 23,
    IncorrectEnclaveHash = 24,
    InvalidDidVersion = 25,
    PrecompileParseUnsignedTxParamsFailed = 26,
    PrecompileSelectorParseFailed = 27,
    InvalidVersion = 28,
    InvalidReport = 29,
    InvalidRegisterSignature = 30,
    ParseOnChainProofErr = 31,
    VerifyOnChainProofErr = 32,
    NoDeviceInfo = 33,
    InCorrectDeviceState = 34,
    InvalidStandbySignature = 35,
    NoNeedToUpdateAssets = 36,
    AlreadyUpdate = 37,
    DuplicateExpose = 38,
    InvalidPartySignature = 39,
    InvalidXudtIssueStatus = 40,
    InvalidGlobalEpoch = 41,
    InvalidReportChangeDuration = 42,
    DuplicateCall = 43,
    InvalidDuration = 44,
    InvalidSignature = 45,
    InvalidDevice = 46,
    NoValidStateVote = 47,
    UidConsensusNotInit = 48,
    UidConsensusAlreadyFinished = 49,
    Unknown,
}

#[cfg(feature = "std")]
impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CustomError::InvalidSession => write!(f, "Invalid heartbeat session"),
            CustomError::NoNeedToSendHeartbeat => write!(f, "Device should not send heartbeat"),
            CustomError::HeartbeatExist => write!(f, "Heartbeat exist"),
            CustomError::ImOnlineInvalidSignature => write!(f, "Verify im_online signature failed"),
            CustomError::InvalidForkId => write!(f, "Invalid fork id for committee"),
            CustomError::InvalidCmtStatus => write!(f, "Invalid committee's status"),
            CustomError::NotAllowFork => write!(f, "Committee's status not allow to fork"),
            CustomError::InvalidRvrfDuration => write!(f, "Invalid time to submit Rvrf for committee"),
            CustomError::InvalidRvrfProof => write!(f, "Rvrf proof verify failed"),
            CustomError::CandidatesExist => write!(f, "Sender has been candidate before"),
            CustomError::CandidatesEnough => write!(f, "There are enough candidates"),
            CustomError::InvalidTxSender => write!(f, "Not expect sender about the tx"),
            CustomError::InvalidTxSenderSignature => write!(f, "Invalid sender's signature"),
            CustomError::InvalidEpoch => write!(f, "Invalid committee's epoch"),
            CustomError::InvalidCmtPubkey => write!(f, "Invalid committee's pubkey"),
            CustomError::NoRewardsForFork => write!(f, "No rewards for target fork id"),
            CustomError::NoRewardsForMember => write!(f, "No rewards for target memeber"),
            CustomError::InvalidTxStatus => write!(f, "Invalid status for target tx"),
            CustomError::InvalidCmtSignature => write!(f, "Verify committee's signature failed"),
            CustomError::NotCmtMember => write!(f, "Not committee's member"),
            CustomError::TxTimeout => write!(f, "Tx has been time-out"),
            CustomError::NoSourceHash => write!(f, "No source hash about the committee"),
            CustomError::InvalidSourceHash => write!(f, "Invalid source to confirm"),
            CustomError::InvalidBtcTxTunnelStatus => write!(f, "Invalid btc tx tunnel status"),
            CustomError::IncorrectEnclaveHash => write!(f, "Invalid Enclave Hash"),
            CustomError::InvalidDidVersion => write!(f, "Invalid device version to report im online"),
            CustomError::PrecompileParseUnsignedTxParamsFailed => write!(f, "Invalid params for report result precompile"),
            CustomError::PrecompileSelectorParseFailed => write!(f, "Invalid selector for precompile"),
            CustomError::InvalidVersion => write!(f, "invalid device version"),
            CustomError::InvalidReport => write!(f, "invalid device register report"),
            CustomError::InvalidRegisterSignature => write!(f, "invalid signature for register report"),
            CustomError::ParseOnChainProofErr => write!(f, "invalid on chain proof data for register report"),
            CustomError::VerifyOnChainProofErr => write!(f, "verify on chain proof data err for register report"),
            CustomError::NoDeviceInfo => write!(f, "No Device info stored"),
            CustomError::InCorrectDeviceState => write!(f, "Incorrect Device state"),
            CustomError::InvalidStandbySignature => write!(f, "Invalid report standby signature"),
            CustomError::NoNeedToUpdateAssets => write!(f, "cid not at update assets list"),
            CustomError::AlreadyUpdate => write!(f, "cid assets already update"),
            CustomError::DuplicateExpose => write!(f, "duplicate expose"),
            CustomError::InvalidPartySignature => write!(f, "Invalid party's signature"),
            CustomError::InvalidXudtIssueStatus => write!(f, "Invalid xudt issue record status"),
            CustomError::InvalidGlobalEpoch => write!(f, "Invalid global epoch"),
            CustomError::InvalidReportChangeDuration => write!(f, "Invalid report change duration"),
            CustomError::DuplicateCall => write!(f, "Duplicate call"),
            CustomError::InvalidDuration => write!(f, "Invalid duration"),
            CustomError::InvalidSignature => write!(f, "Invalid signature"),
            CustomError::InvalidDevice => write!(f, "Invalid device"),
            CustomError::NoValidStateVote => write!(f, "No valid state vote"),
            CustomError::UidConsensusNotInit => write!(f, "Uid consensus mission not init"),
            CustomError::UidConsensusAlreadyFinished => write!(f, "Uid consensus mission already finished"),
            CustomError::Unknown => write!(f, "unknown error"),
        }
    }
}

#[cfg(feature = "std")]
impl CustomError {
    pub fn from_num(num: u8) -> Self {
        match num {
            0 => Self::InvalidSession,
            1 => Self::NoNeedToSendHeartbeat,
            2 => Self::HeartbeatExist,
            3 => Self::ImOnlineInvalidSignature,
            4 => Self::InvalidForkId,
            5 => Self::InvalidCmtStatus,
            6 => Self::NotAllowFork,
            7 => Self::InvalidRvrfDuration,
            8 => Self::InvalidRvrfProof,
            9 => Self::CandidatesExist,
            10 => Self::CandidatesEnough,
            11 => Self::InvalidTxSender,
            12 => Self::InvalidTxSenderSignature,
            13 => Self::InvalidEpoch,
            14 => Self::InvalidCmtPubkey,
            15 => Self::NoRewardsForFork,
            16 => Self::NoRewardsForMember,
            17 => Self::InvalidTxStatus,
            18 => Self::InvalidCmtSignature,
            19 => Self::NotCmtMember,
            20 => Self::TxTimeout,
            21 => Self::NoSourceHash,
            22 => Self::InvalidSourceHash,
            23 => Self::InvalidBtcTxTunnelStatus,
            24 => Self::IncorrectEnclaveHash,
            25 => Self::InvalidDidVersion,
            26 => Self::PrecompileParseUnsignedTxParamsFailed,
            27 => Self::PrecompileSelectorParseFailed,
            28 => Self::InvalidVersion,
            29 => Self::InvalidReport,
            30 => Self::InvalidRegisterSignature,
            31 => Self::ParseOnChainProofErr,
            32 => Self::VerifyOnChainProofErr,
            33 => Self::NoDeviceInfo,
            34 => Self::InCorrectDeviceState,
            35 => Self::InvalidStandbySignature,
            36 => Self::NoNeedToUpdateAssets,
            37 => Self::AlreadyUpdate,
            38 => Self::DuplicateExpose,
            39 => Self::InvalidPartySignature,
            40 => Self::InvalidXudtIssueStatus,
            41 => Self::InvalidGlobalEpoch,
            42 => Self::InvalidReportChangeDuration,
            43 => Self::DuplicateCall,
            44 => Self::InvalidDuration,
            45 => Self::InvalidSignature,
            46 => Self::InvalidDevice,
            47 => Self::NoValidStateVote,
            48 => Self::UidConsensusNotInit,
            49 => Self::UidConsensusAlreadyFinished,
            _ => Self::Unknown,
        }
    }
}
