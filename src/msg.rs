use cosmwasm_std::{Addr, Binary, StdError, StdResult, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::batch;
use crate::storage::claim::Claim;
use crate::storage::expiration::{Duration, Expiration};
use crate::transaction_history::{RichTx, Tx};
use crate::viewing_key_obj::ViewingKeyObj;

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub readonly_admin: Addr,
    pub symbol: String,
    pub initial_balances: Vec<WalletBalances>,
    pub airdrop_source_wallet: Addr,
    pub prng_seed: Binary,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Native coin interactions
    Stake {
        amount: Uint128,
    },
    Unstake {
        amount: Uint128,
    },
    /// claim unbonded tokens
    Claim {},
    /// Claim does not check if contract has enough funds, owner must ensure it. /// jla: FIXME
    ClaimAirdrop {
        stage: u8,
        amount: Uint128,
        /// Proof is hex-encoded merkle proof.
        proof: Vec<String>,
    },

    /// Base ERC-20 stuff
    Transfer {
        recipient: Addr,
        amount: Uint128,
        memo: Option<String>,
        padding: Option<String>,
    },
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },
    TransferFrom {
        spender: Addr,
        recipient: Addr,
        amount: Uint128,
        memo: Option<String>,
        padding: Option<String>,
    },
    BatchTransferFrom {
        actions: Vec<batch::TransferFromAction>,
        padding: Option<String>,
    },

    /// Admin
    ChangeAdmin {
        address: Addr,
        padding: Option<String>,
    },
    SetContractStatus {
        level: ContractStatusLevel,
        padding: Option<String>,
    },
    RegisterAirdropSourceWallet {
        address: Addr,
    },
    RegisterMerkleRoot {
        /// MerkleRoot is hex-encoded merkle root.
        merkle_root: String,
        expiration: Expiration,
        start: Expiration,
        total_amount: Uint128,
    },
    ReplaceMerkleRoot {
        stage: u8,
        merkle_root: String,
        expiration: Expiration,
        start: Expiration,
        total_amount: Uint128,
    },
    /// Withdraw the remaining tokens after expire time (only owner)
    WithdrawUnclaimed {
        stage: u8,
        address: String,
    },
    GetAll {},
    GetAllClaimed {},
    UpdateExpDate {
        stage: u8,
        new_expiration: Expiration,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    // Native
    Stake {
        status: ResponseStatus,
    },
    Unstake {
        status: ResponseStatus,
    },
    Claim {
        status: ResponseStatus,
        amount: u128,
    },
    // Base
    Transfer {
        status: ResponseStatus,
    },
    RegisterReceive {
        status: ResponseStatus,
    },
    CreateViewingKey {
        key: ViewingKeyObj,
    },
    SetViewingKey {
        status: ResponseStatus,
    },
    TransferFrom {
        status: ResponseStatus,
    },
    BatchTransferFrom {
        status: ResponseStatus,
    },

    // Other
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
    RegisterAirdropSourceWallet {
        status: ResponseStatus,
    },
    RegisterMerkleRoot {
        stage: u8,
        start: Expiration,
        expiration: Expiration,
        merkle_root: String,
        airdrop_source_wallet: String,
    },
    WithdrawUnclaimed {
        status: ResponseStatus,
        amount: u128,
    },
    GetAll {
        result: Vec<WalletBalances>,
    },
    GetAllClaimed {
        result: Vec<WalletClaimBalances>,
    },
    UpdateExpDate {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    TokenInfo {},
    TokenConfig {},
    ContractStatus {},
    Balance {
        address: Addr,
        key: String,
    },
    Claim {
        address: Addr,
        key: String,
    },
    TransferHistory {
        address: Addr,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
    TransactionHistory {
        address: Addr,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
    MerkleRoot {
        stage: u8,
    },
    LatestStage {},
    IsAirdropClaimed {
        stage: u8,
        address: Addr,
        key: String,
    },
}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&Addr>, ViewingKeyObj) {
        match self {
            Self::Balance { address, key } => (vec![address], ViewingKeyObj(key.clone())),
            Self::Claim { address, key } => (vec![address], ViewingKeyObj(key.clone())),
            Self::TransferHistory { address, key, .. } => {
                (vec![address], ViewingKeyObj(key.clone()))
            }
            Self::TransactionHistory { address, key, .. } => {
                (vec![address], ViewingKeyObj(key.clone()))
            }
            Self::IsAirdropClaimed { address, key, .. } => {
                (vec![address], ViewingKeyObj(key.clone()))
            }
            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Uint128,
    },
    TokenConfig {
        decimals: u8,
        unbonding_period: Duration,
    },
    ContractStatus {
        status: ContractStatusLevel,
    },
    Balance {
        amount: Uint128,
        staked_amount: Uint128,
    },
    Claim {
        amounts: Vec<Claim>,
    },
    TransferHistory {
        txs: Vec<Tx>,
        total: Option<u64>,
    },
    TransactionHistory {
        txs: Vec<RichTx>,
        total: Option<u64>,
    },
    ViewingKeyError {
        msg: String,
    },
    AirdropClaimed {
        claimed: bool,
        amount: u128,
        expiration: Expiration,
        start: Expiration,
    },
    AirdropStage {
        stage: u8,
    },
    MerkleRoot {
        stage: u8,
        /// MerkleRoot is hex-encoded merkle root.
        merkle_root: String,
        expiration: Expiration,
        start: Expiration,
        total_amount: Uint128,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct CreateViewingKeyResponse {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatusLevel {
    NormalRun,
    StopAllButUnstake,
    StopAll,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ClaimMsg {
    // To provide claiming via ledger, the address is passed in the memo field of a cosmos msg.
    #[serde(rename = "memo")]
    address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MerkleRootResponse {
    pub stage: u8,
    /// MerkleRoot is hex-encoded merkle root.
    pub merkle_root: String,
    pub expiration: Expiration,
    pub start: Option<Expiration>,
    pub total_amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LatestStageResponse {
    pub latest_stage: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WalletBalances {
    pub(crate) address: String,
    pub(crate) staked: u128,
    pub(crate) unstaked: u128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WalletClaimBalances {
    pub(crate) address: String,
    pub(crate) stage: u8,
    pub(crate) amount: u128,
}

pub fn status_level_to_u8(status_level: ContractStatusLevel) -> u8 {
    match status_level {
        ContractStatusLevel::NormalRun => 0,
        ContractStatusLevel::StopAllButUnstake => 1,
        ContractStatusLevel::StopAll => 2,
    }
}

pub fn u8_to_status_level(status_level: u8) -> StdResult<ContractStatusLevel> {
    match status_level {
        0 => Ok(ContractStatusLevel::NormalRun),
        1 => Ok(ContractStatusLevel::StopAllButUnstake),
        2 => Ok(ContractStatusLevel::StopAll),
        _ => Err(StdError::generic_err("Invalid state level")),
    }
}

// Take a Vec<u8> and pad it up to a multiple of `block_size`, using spaces at the end.
pub fn space_pad(block_size: usize, message: &mut Vec<u8>) -> &mut Vec<u8> {
    let len = message.len();
    let surplus = len % block_size;
    if surplus == 0 {
        return message;
    }

    let missing = block_size - surplus;
    message.reserve(missing);
    message.extend(std::iter::repeat(b' ').take(missing));
    message
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{from_slice, StdResult};

    use super::*;

    #[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub enum Something {
        Var { padding: Option<String> },
    }

    #[test]
    fn test_deserialization_of_missing_option_fields() -> StdResult<()> {
        let input = b"{ \"var\": {} }";
        let obj: Something = from_slice(input)?;
        assert_eq!(
            obj,
            Something::Var { padding: None },
            "unexpected value: {:?}",
            obj
        );
        Ok(())
    }
}
