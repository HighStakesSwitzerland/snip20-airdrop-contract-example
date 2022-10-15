use std::str::FromStr;

use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use schemars::JsonSchema;
use secret_toolkit::serialization::Json;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

use crate::msg::{ContractStatusLevel, WalletBalances, WalletClaimBalances};
use crate::storage::claim::Claims;
use crate::storage::expiration::{Duration, Expiration};

pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const KEY_TX_COUNT: &[u8] = b"tx-count";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_STAKED_BALANCES: &[u8] = b"staked_balances";
pub const PREFIX_CLAIMED_AIRDROP: &[u8] = b"claim";
pub const PREFIX_MERKLE_ROOT: &[u8] = b"merkle_root";
pub const PREFIX_STAGE_EXPIRATION: &[u8] = b"stage_exp";
pub const PREFIX_STAGE_START: &[u8] = b"stage_start";
pub const PREFIX_STAGE_TOTAL_AMOUNT: &[u8] = b"stage_total_amount";
pub const PREFIX_STAGE_TOTAL_AMOUNT_CLAIMED: &[u8] = b"stage_claimed_total_amount";
pub const PREFIX_LATEST_STAGE: &[u8] = b"stage";

pub static CLAIMS: Claims = Claims::new("claims");

pub static CONSTANTS: Item<Constants, Json> = Item::new(KEY_CONSTANTS);
pub static TOTAL_SUPPLY: Item<u128, Json> = Item::new(KEY_TOTAL_SUPPLY);
pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);
pub static TX_COUNT: Item<u64, Json> = Item::new(KEY_TX_COUNT);
pub static BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_BALANCES);
pub static STAKED_BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_STAKED_BALANCES);

pub static MERKLE_ROOT: Keymap<u8, String> = Keymap::new(PREFIX_MERKLE_ROOT);
pub static CLAIMED_AIRDROP: Keymap<String, u128, Json> = Keymap::new(PREFIX_CLAIMED_AIRDROP);
pub static LATEST_STAGE: Item<u8> = Item::new(PREFIX_LATEST_STAGE);
pub static STAGE_EXPIRATION: Keymap<u8, String> = Keymap::new(PREFIX_STAGE_EXPIRATION);
pub static STAGE_START: Keymap<u8, String> = Keymap::new(PREFIX_STAGE_START);
pub static STAGE_TOTAL_AMOUNT: Keymap<u8, u128> = Keymap::new(PREFIX_STAGE_TOTAL_AMOUNT);
pub static STAGE_TOTAL_AMOUNT_CLAIMED: Keymap<u8, u128> =
    Keymap::new(PREFIX_STAGE_TOTAL_AMOUNT_CLAIMED);

// Config

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub admin: Addr,
    pub readonly_admin: Addr,
    pub symbol: String,
    // unbonding period before being able to storage tokens
    pub unbonding_period: Duration,
    // the address of this contract, used to validate query permits
    pub contract_address: Addr,
    // wallet that contains tokens for airdrops to be taken from on claim
    pub airdrop_source_wallet: Addr,
}

impl Constants {
    pub fn load(store: &dyn Storage) -> StdResult<Constants> {
        CONSTANTS
            .load(store)
            .map_err(|_err| StdError::generic_err("no constants stored"))
    }

    pub fn save(store: &mut dyn Storage, constants: &Constants) -> StdResult<()> {
        CONSTANTS.save(store, constants)
    }
}

pub struct TotalSupplyStore {}
impl TotalSupplyStore {
    pub fn load(store: &dyn Storage) -> StdResult<u128> {
        TOTAL_SUPPLY
            .load(store)
            .map_err(|_err| StdError::generic_err("no total supply stored"))
    }

    pub fn save(store: &mut dyn Storage, supply: u128) -> StdResult<()> {
        TOTAL_SUPPLY.save(store, &supply)
    }
}

pub struct ContractStatusStore {}
impl ContractStatusStore {
    pub fn load(store: &dyn Storage) -> StdResult<ContractStatusLevel> {
        CONTRACT_STATUS
            .load(store)
            .map_err(|_err| StdError::generic_err("no contract status stored"))
    }

    pub fn save(store: &mut dyn Storage, status: ContractStatusLevel) -> StdResult<()> {
        CONTRACT_STATUS.save(store, &status)
    }
}

pub struct TxCountStore {}
impl TxCountStore {
    pub fn load(store: &dyn Storage) -> u64 {
        TX_COUNT.load(store).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, count: u64) -> StdResult<()> {
        TX_COUNT.save(store, &count)
    }
}

pub struct BalancesStore {}
impl BalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        BALANCES.get(store, account).unwrap_or(0)
    }

    pub fn get_all(store: &dyn Storage) -> Vec<WalletBalances> {
        let iterator = BALANCES.iter(store).unwrap();
        let mut balances = Vec::new();

        for item in iterator {
            let (addr, amount) = item.unwrap();
            let bal: WalletBalances = WalletBalances {
                address: addr.to_string(),
                unstaked: amount,
                staked: StakedBalancesStore::load(store, &addr),
            };
            balances.push(bal);
        }

        balances
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        BALANCES.insert(store, account, &amount)
    }
}

pub struct StakedBalancesStore {}
impl StakedBalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        STAKED_BALANCES.get(store, account).unwrap_or(0)
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        STAKED_BALANCES.insert(store, account, &amount)
    }
}

pub struct MerkleRoots {}
impl MerkleRoots {
    pub fn get(store: &dyn Storage, stage: u8) -> Option<String> {
        MERKLE_ROOT.get(store, &stage)
    }

    pub fn save(store: &mut dyn Storage, stage: u8, proof: &String) -> StdResult<()> {
        MERKLE_ROOT.insert(store, &stage, proof)
    }
}

pub struct AirdropsClaimed {}
impl AirdropsClaimed {
    pub fn get(store: &dyn Storage, stage: u8, addr: String) -> Option<u128> {
        let mut stage_as_vec = Vec::new();
        stage_as_vec.push(stage);
        let key = addr.clone() + std::str::from_utf8(stage_as_vec.as_slice()).unwrap();
        CLAIMED_AIRDROP.get(store, &key)
    }

    pub fn get_all(store: &dyn Storage) -> Vec<WalletClaimBalances> {
        let iterator = CLAIMED_AIRDROP.iter(store).unwrap();
        let mut balances = Vec::new();

        for item in iterator {
            let (key, amount) = item.unwrap();
            let mut stage_as_vec = Vec::from(key);
            let stage = stage_as_vec.pop().unwrap();
            let address = std::str::from_utf8(stage_as_vec.as_slice())
                .unwrap()
                .to_string();
            let bal: WalletClaimBalances = WalletClaimBalances {
                address: address.clone(),
                stage,
                amount,
            };
            balances.push(bal);
        }
        balances
    }

    pub fn set_claimed(
        store: &mut dyn Storage,
        stage: u8,
        addr: String,
        amount: u128,
    ) -> StdResult<()> {
        let mut stage_as_vec = Vec::new();
        stage_as_vec.push(stage);
        let key = addr.clone() + std::str::from_utf8(stage_as_vec.as_slice())?;
        CLAIMED_AIRDROP.insert(store, &key, &amount)
    }
}
pub struct AirdropStages {}
impl AirdropStages {
    pub fn get_latest(store: &dyn Storage) -> StdResult<u8> {
        LATEST_STAGE
            .load(store)
            .map_err(|_err| StdError::generic_err("no stage defined!"))
    }

    pub fn set_new_stage(store: &mut dyn Storage, stage: u8) -> StdResult<()> {
        LATEST_STAGE.save(store, &stage)
    }
}

pub struct AirdropStagesExpiration {}
impl AirdropStagesExpiration {
    pub fn get(store: &dyn Storage, stage: u8) -> Expiration {
        Expiration::from_str(STAGE_EXPIRATION.get(store, &stage).unwrap().as_str()).unwrap()
    }

    pub fn save(store: &mut dyn Storage, stage: u8, exp: Expiration) -> StdResult<()> {
        STAGE_EXPIRATION.insert(store, &stage, &exp.to_string())
    }
}

pub struct AirdropStagesStart {}
impl AirdropStagesStart {
    pub fn get(store: &dyn Storage, stage: u8) -> Option<Expiration> {
        let stage_exp = STAGE_START.get(store, &stage);
        if stage_exp == None {
            return None;
        }
        Some(Expiration::from_str(stage_exp.unwrap().as_str()).unwrap())
    }

    pub fn save(store: &mut dyn Storage, stage: u8, date: Expiration) -> StdResult<()> {
        STAGE_START.insert(store, &stage, &date.to_string())
    }
}

pub struct AirdropStagesTotalAmount {}
impl AirdropStagesTotalAmount {
    pub fn load(store: &dyn Storage, stage: u8) -> u128 {
        STAGE_TOTAL_AMOUNT.get(store, &stage).unwrap()
    }

    pub fn save(store: &mut dyn Storage, stage: u8, amount: u128) -> StdResult<()> {
        STAGE_TOTAL_AMOUNT.insert(store, &stage, &amount)
    }
}

pub struct AirdropStagesTotalAmountCaimed {}
impl AirdropStagesTotalAmountCaimed {
    pub fn load(store: &dyn Storage, stage: u8) -> u128 {
        STAGE_TOTAL_AMOUNT_CLAIMED.get(store, &stage).unwrap_or(0)
    }

    pub fn save(store: &mut dyn Storage, stage: u8, amount: u128) -> StdResult<()> {
        STAGE_TOTAL_AMOUNT_CLAIMED.insert(store, &stage, &amount)
    }
}
