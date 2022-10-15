use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Api, CanonicalAddr, Coin, StdError, StdResult, Storage, Uint128};

use secret_toolkit::storage::AppendStore;

use crate::state::TxCountStore;

const PREFIX_TXS: &[u8] = b"transactions";
const PREFIX_TRANSFERS: &[u8] = b"transfers";

// Note that id is a globally incrementing counter.
// Since it's 64 bits long, even at 50 tx/s it would take
// over 11 billion years for it to rollback. I'm pretty sure
// we'll have bigger issues by then.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Tx {
    pub id: u64,
    pub from: Addr,
    pub sender: Addr,
    pub receiver: Addr,
    pub coins: Coin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    // The block time and block height are optional so that the JSON schema
    // reflects that some SNIP-20 contracts may not include this info.
    pub block_time: Option<u64>,
    pub block_height: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TxAction {
    Transfer {
        from: Addr,
        sender: Addr,
        recipient: Addr,
    },
    Burn {
        burner: Addr,
        owner: Addr,
    },
    Stake {},
    Unstake {},
}

// Note that id is a globally incrementing counter.
// Since it's 64 bits long, even at 50 tx/s it would take
// over 11 billion years for it to rollback. I'm pretty sure
// we'll have bigger issues by then.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RichTx {
    pub id: u64,
    pub action: TxAction,
    pub coins: Coin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    pub block_time: u64,
    pub block_height: u64,
}

// Stored types:

/// This type is the stored version of the legacy transfers
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredLegacyTransfer {
    id: u64,
    from: CanonicalAddr,
    sender: CanonicalAddr,
    receiver: CanonicalAddr,
    coins: Coin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredLegacyTransfer {
    pub fn into_humanized(self, api: &dyn Api) -> StdResult<Tx> {
        let tx = Tx {
            id: self.id,
            from: api.addr_humanize(&self.from)?,
            sender: api.addr_humanize(&self.sender)?,
            receiver: api.addr_humanize(&self.receiver)?,
            coins: self.coins,
            memo: self.memo,
            block_time: Some(self.block_time),
            block_height: Some(self.block_height),
        };
        Ok(tx)
    }

    fn append_transfer(
        store: &mut dyn Storage,
        tx: &StoredLegacyTransfer,
        for_address: &CanonicalAddr,
    ) -> StdResult<()> {
        let current_addr_store = TRANSFERS.add_suffix(for_address);
        current_addr_store.push(store, tx)
    }

    pub fn get_transfers(
        api: &dyn Api,
        storage: &dyn Storage,
        for_address: &CanonicalAddr,
        page: u32,
        page_size: u32,
    ) -> StdResult<(Vec<Tx>, u64)> {
        let current_addr_store = TRANSFERS.add_suffix(for_address);
        let len = current_addr_store.get_len(storage)? as u64;
        // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
        // txs from the start.
        let transfer_iter = current_addr_store
            .iter(storage)?
            .rev()
            .skip((page * page_size) as _)
            .take(page_size as _);

        // The `and_then` here flattens the `StdResult<StdResult<RichTx>>` to an `StdResult<RichTx>`
        let transfers: StdResult<Vec<Tx>> = transfer_iter
            .map(|tx| tx.map(|tx| tx.into_humanized(api)).and_then(|x| x))
            .collect();
        transfers.map(|txs| (txs, len))
    }
}

static TRANSFERS: AppendStore<StoredLegacyTransfer> = AppendStore::new(PREFIX_TRANSFERS);

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TxCode {
    Transfer = 0,
    Stake = 1,
    Unstake = 2,
    Burn = 3,
}

impl TxCode {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(n: u8) -> StdResult<Self> {
        use TxCode::*;
        match n {
            0 => Ok(Transfer),
            1 => Ok(Stake),
            2 => Ok(Unstake),
            3 => Ok(Burn),
            other => Err(StdError::generic_err(format!(
                "Unexpected Tx code in transaction history: {} Storage is corrupted.",
                other
            ))),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
struct StoredTxAction {
    tx_type: u8,
    address1: Option<CanonicalAddr>,
    address2: Option<CanonicalAddr>,
    address3: Option<CanonicalAddr>,
}

impl StoredTxAction {
    fn transfer(from: CanonicalAddr, sender: CanonicalAddr, recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Transfer.to_u8(),
            address1: Some(from),
            address2: Some(sender),
            address3: Some(recipient),
        }
    }
    fn stake() -> Self {
        Self {
            tx_type: TxCode::Stake.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }
    fn unstake() -> Self {
        Self {
            tx_type: TxCode::Unstake.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }

    fn into_humanized(self, api: &dyn Api) -> StdResult<TxAction> {
        let transfer_addr_err = || {
            StdError::generic_err(
                "Missing address in stored Transfer transaction. Storage is corrupt",
            )
        };
        let burn_addr_err = || {
            StdError::generic_err("Missing address in stored Burn transaction. Storage is corrupt")
        };

        // In all of these, we ignore fields that we don't expect to find populated
        let action = match TxCode::from_u8(self.tx_type)? {
            TxCode::Transfer => {
                let from = self.address1.ok_or_else(transfer_addr_err)?;
                let sender = self.address2.ok_or_else(transfer_addr_err)?;
                let recipient = self.address3.ok_or_else(transfer_addr_err)?;
                let from = api.addr_humanize(&from)?;
                let sender = api.addr_humanize(&sender)?;
                let recipient = api.addr_humanize(&recipient)?;
                TxAction::Transfer {
                    from,
                    sender,
                    recipient,
                }
            }
            TxCode::Burn => {
                let burner = self.address1.ok_or_else(burn_addr_err)?;
                let owner = self.address2.ok_or_else(burn_addr_err)?;
                let burner = api.addr_humanize(&burner)?;
                let owner = api.addr_humanize(&owner)?;
                TxAction::Burn { burner, owner }
            }
            TxCode::Stake => TxAction::Stake {},
            TxCode::Unstake => TxAction::Unstake {},
        };

        Ok(action)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredRichTx {
    id: u64,
    action: StoredTxAction,
    coins: Coin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredRichTx {
    fn new(
        id: u64,
        action: StoredTxAction,
        coins: Coin,
        memo: Option<String>,
        block: &cosmwasm_std::BlockInfo,
    ) -> Self {
        Self {
            id,
            action,
            coins,
            memo,
            block_time: block.time.seconds(),
            block_height: block.height,
        }
    }

    fn into_humanized(self, api: &dyn Api) -> StdResult<RichTx> {
        Ok(RichTx {
            id: self.id,
            action: self.action.into_humanized(api)?,
            coins: self.coins,
            memo: self.memo,
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }

    fn from_stored_legacy_transfer(transfer: StoredLegacyTransfer) -> Self {
        let action = StoredTxAction::transfer(transfer.from, transfer.sender, transfer.receiver);
        Self {
            id: transfer.id,
            action,
            coins: transfer.coins,
            memo: transfer.memo,
            block_time: transfer.block_time,
            block_height: transfer.block_height,
        }
    }

    fn append_tx(
        store: &mut dyn Storage,
        tx: &StoredRichTx,
        for_address: &CanonicalAddr,
    ) -> StdResult<()> {
        let current_addr_store = TRANSACTIONS.add_suffix(for_address);
        current_addr_store.push(store, tx)
    }

    pub fn get_txs(
        api: &dyn Api,
        storage: &dyn Storage,
        for_address: &CanonicalAddr,
        page: u32,
        page_size: u32,
    ) -> StdResult<(Vec<RichTx>, u64)> {
        let current_addr_store = TRANSACTIONS.add_suffix(for_address);
        let len = current_addr_store.get_len(storage)? as u64;

        // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
        // txs from the start.
        let tx_iter = current_addr_store
            .iter(storage)?
            .rev()
            .skip((page * page_size) as _)
            .take(page_size as _);

        // The `and_then` here flattens the `StdResult<StdResult<RichTx>>` to an `StdResult<RichTx>`
        let txs: StdResult<Vec<RichTx>> = tx_iter
            .map(|tx| tx.map(|tx| tx.into_humanized(api)).and_then(|x| x))
            .collect();
        txs.map(|txs| (txs, len))
    }
}

static TRANSACTIONS: AppendStore<StoredRichTx> = AppendStore::new(PREFIX_TXS);

// Storage functions:

fn increment_tx_count(store: &mut dyn Storage) -> StdResult<u64> {
    let id = TxCountStore::load(store) + 1;
    TxCountStore::save(store, id)?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_transfer_in_history(
    store: &mut dyn Storage,
    owner: &CanonicalAddr,
    sender: &CanonicalAddr,
    receiver: &CanonicalAddr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let transfer = StoredLegacyTransfer {
        id,
        from: owner.clone(),
        sender: sender.clone(),
        receiver: receiver.clone(),
        coins,
        memo,
        block_time: block.time.seconds(),
        block_height: block.height,
    };
    let tx = StoredRichTx::from_stored_legacy_transfer(transfer.clone());

    // Write to the owners history if it's different from the other two addresses
    if owner != sender && owner != receiver {
        // cosmwasm_std::debug_print("saving transaction history for owner");
        StoredRichTx::append_tx(store, &tx, owner)?;
        StoredLegacyTransfer::append_transfer(store, &transfer, owner)?;
    }
    // Write to the sender's history if it's different from the receiver
    if sender != receiver {
        // cosmwasm_std::debug_print("saving transaction history for sender");
        StoredRichTx::append_tx(store, &tx, sender)?;
        StoredLegacyTransfer::append_transfer(store, &transfer, sender)?;
    }
    // Always write to the recipient's history
    // cosmwasm_std::debug_print("saving transaction history for receiver");
    StoredRichTx::append_tx(store, &tx, receiver)?;
    StoredLegacyTransfer::append_transfer(store, &transfer, receiver)?;

    Ok(())
}

pub fn store_stake_in_history(
    store: &mut dyn Storage,
    recipient: &CanonicalAddr,
    amount: Uint128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::stake();
    let tx = StoredRichTx::new(id, action, coins, None, block);

    StoredRichTx::append_tx(store, &tx, recipient)?;

    Ok(())
}

pub fn store_unstake_in_history(
    store: &mut dyn Storage,
    redeemer: &CanonicalAddr,
    amount: Uint128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::unstake();
    let tx = StoredRichTx::new(id, action, coins, None, block);

    StoredRichTx::append_tx(store, &tx, redeemer)?;

    Ok(())
}
