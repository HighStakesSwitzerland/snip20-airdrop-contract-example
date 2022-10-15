//! Types used in batch operations

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Uint128};

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TransferFromAction {
    pub owner: Addr,
    pub recipient: Addr,
    pub amount: Uint128,
    pub memo: Option<String>,
}
