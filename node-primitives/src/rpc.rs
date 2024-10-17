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
#[derive(Debug, Serialize, Deserialize)]
pub enum RawRewardDestination {
    Staked,
    Stash,
    Controller,
    Account(String),
    None,
}

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawNominatorInfo {
    pub stash_account: String,
    pub target_validators: Vec<String>,
    pub total_staking: String,
    pub active_staking: String,
    pub rewrds_destination: RawRewardDestination,
}

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawValidatorInfo {
    pub stash_account: String,
    pub state: bool,
    pub total_staking: String,
    pub owner_staking: String,
    pub nominators: String,
    pub commission: String,
    pub can_nominated: bool,
}

#[cfg(feature = "std")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawProvider {
    pub pid: String,
    pub owner: String,
    pub cap_pledge: String,
    pub total_pledge: String,
    pub devices_num: String,
    pub total_punishment: String,
    pub total_rewards: String,
    pub unpaid_rewards: String,
}