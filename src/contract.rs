use std::str;

/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Storage, Uint128,
};
use hex::FromHexError;
use secret_toolkit::crypto::sha_256;
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};
use sha2::Digest;

use crate::batch;
use crate::msg::{
    space_pad, ContractStatusLevel, ExecuteAnswer, ExecuteMsg, InstantiateMsg, QueryAnswer,
    QueryMsg, ResponseStatus::Success,
};
use crate::state::{
    AirdropStages, AirdropStagesExpiration, AirdropStagesStart, AirdropStagesTotalAmount,
    AirdropStagesTotalAmountCaimed, AirdropsClaimed, BalancesStore, Constants, ContractStatusStore,
    MerkleRoots, StakedBalancesStore, TotalSupplyStore, CLAIMS,
};
use crate::storage::expiration::{Expiration, WEEK};
use crate::transaction_history::{
    store_stake_in_history, store_transfer_in_history, store_unstake_in_history,
    StoredLegacyTransfer, StoredRichTx,
};
use crate::viewing_key_obj::ViewingKeyObj;

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,6}",
        ));
    }

    let admin = info.sender;
    let mut total_supply: u128 = 0;
    {
        for balance in msg.initial_balances {
            let amount = balance.unstaked;
            BalancesStore::save(
                deps.storage,
                &Addr::unchecked(balance.address.clone()),
                amount,
            )?;

            let staked_amount = balance.staked;
            StakedBalancesStore::save(
                deps.storage,
                &Addr::unchecked(balance.address),
                staked_amount,
            )?;

            if let Some(new_total_supply) = total_supply.checked_add(amount) {
                total_supply = new_total_supply;
            } else {
                return Err(StdError::generic_err(
                    "The sum of all initial balances exceeds the maximum possible total supply",
                ));
            }
            if let Some(new_total_supply) = total_supply.checked_add(staked_amount) {
                total_supply = new_total_supply;
            } else {
                return Err(StdError::generic_err(
                    "The sum of all initial balances exceeds the maximum possible total supply",
                ));
            }
        }
    }

    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    // init constants
    Constants::save(
        deps.storage,
        &Constants {
            name: msg.name,
            symbol: msg.symbol,
            admin: admin.clone(),
            readonly_admin: msg.readonly_admin,
            // Unbonding period hardcoded
            unbonding_period: WEEK,
            contract_address: env.contract.address,
            airdrop_source_wallet: msg.airdrop_source_wallet,
        },
    )?;

    AirdropStages::set_new_stage(deps.storage, 0)?;
    TotalSupplyStore::save(deps.storage, total_supply)?;
    ContractStatusStore::save(deps.storage, ContractStatusLevel::NormalRun)?;

    ViewingKey::set_seed(deps.storage, &prng_seed_hashed);
    Ok(Response::default())
}

fn pad_response(response: StdResult<Response>) -> StdResult<Response> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let contract_status = ContractStatusStore::load(deps.storage)?;

    match contract_status {
        ContractStatusLevel::StopAll => {
            let response = match msg {
                ExecuteMsg::SetContractStatus { level, .. } => {
                    set_contract_status(deps, &info, level)
                }
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_response(response);
        }
        ContractStatusLevel::StopAllButUnstake => {
            let response = match msg {
                ExecuteMsg::SetContractStatus { level, .. } => {
                    set_contract_status(deps, &info, level)
                }
                ExecuteMsg::Unstake { amount, .. }
                    if contract_status == ContractStatusLevel::StopAllButUnstake =>
                {
                    try_unstake(deps, env, &info, amount)
                }
                ExecuteMsg::Claim {} => try_claim(deps, env, &info),
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_response(response);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }

    let response = match msg {
        // Native
        ExecuteMsg::Stake { amount, .. } => try_stake(deps, env, &info, amount),
        ExecuteMsg::Unstake { amount, .. } => try_unstake(deps, env, &info, amount),
        ExecuteMsg::Claim { .. } => try_claim(deps, env, &info),
        // Base
        ExecuteMsg::Transfer {
            recipient,
            amount,
            memo,
            ..
        } => try_transfer(deps, env, &info, recipient, amount, memo),
        ExecuteMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, &info, entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, &info, key),
        ExecuteMsg::TransferFrom {
            spender,
            recipient,
            amount,
            memo,
            ..
        } => try_transfer_from(deps, &env, &info, &spender, &recipient, amount, memo),
        ExecuteMsg::BatchTransferFrom { actions, .. } => {
            try_batch_transfer_from(deps, &env, &info, actions)
        }
        ExecuteMsg::RegisterMerkleRoot {
            merkle_root,
            expiration,
            start,
            total_amount,
        } => execute_register_merkle_root(
            deps,
            &info,
            merkle_root,
            expiration,
            start,
            total_amount,
            None,
        ),
        ExecuteMsg::ReplaceMerkleRoot {
            stage,
            merkle_root,
            start,
            expiration,
            total_amount,
        } => execute_register_merkle_root(
            deps,
            &info,
            merkle_root,
            expiration,
            start,
            total_amount,
            Some(stage),
        ),
        ExecuteMsg::RegisterAirdropSourceWallet { address } => {
            execute_register_airdrop_source_wallet(deps, &info, address)
        }
        ExecuteMsg::WithdrawUnclaimed { address, stage } => {
            execute_withdraw_airdrop_unclaimed(deps, env, &info, stage, address)
        }
        ExecuteMsg::ClaimAirdrop {
            stage,
            amount,
            proof,
        } => execute_claim_airdrop(deps, env, &info, stage, amount, proof),
        ExecuteMsg::ChangeAdmin { address, .. } => change_admin(deps, &info, address),
        ExecuteMsg::SetContractStatus { level, .. } => set_contract_status(deps, &info, level),
        ExecuteMsg::GetAll { .. } => get_all_token_balances(deps, &info),
        ExecuteMsg::GetAllClaimed { .. } => get_all_airdrop_claims(deps, &info),
        ExecuteMsg::UpdateExpDate {
            stage,
            new_expiration,
        } => execute_update_stage_exp(deps, &info, stage, new_expiration),
    };

    pad_response(response)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::TokenInfo {} => query_token_info(deps.storage),
        QueryMsg::TokenConfig {} => query_token_config(deps.storage),
        QueryMsg::ContractStatus {} => query_contract_status(deps.storage),
        QueryMsg::LatestStage { .. } => query_latest_sage(deps.storage),
        QueryMsg::MerkleRoot { stage } => query_merkle_root(deps.storage, stage),
        _ => viewing_keys_queries(deps, msg),
    }
}

fn viewing_keys_queries(deps: Deps, msg: QueryMsg) -> StdResult<Binary> {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let result = ViewingKey::check(deps.storage, address.as_str(), key.as_str());
        if result.is_ok() {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(deps, &address),
                QueryMsg::Claim { address, .. } => query_claim(deps, &address),
                QueryMsg::TransferHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transfers(deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::TransactionHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transactions(deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::IsAirdropClaimed { address, stage, .. } => {
                    query_airdrop_claimed(deps, stage, &address)
                }
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })
}

fn query_token_info(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = Constants::load(storage)?;

    let total_supply = Uint128::new(TotalSupplyStore::load(storage)?);

    to_binary(&QueryAnswer::TokenInfo {
        name: constants.name,
        symbol: constants.symbol,
        decimals: 0u8,
        total_supply,
    })
}

fn query_token_config(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = Constants::load(storage)?;

    to_binary(&QueryAnswer::TokenConfig {
        decimals: 0u8,
        unbonding_period: constants.unbonding_period,
    })
}

fn query_contract_status(storage: &dyn Storage) -> StdResult<Binary> {
    let contract_status = ContractStatusStore::load(storage)?;

    to_binary(&QueryAnswer::ContractStatus {
        status: contract_status,
    })
}

fn query_latest_sage(storage: &dyn Storage) -> StdResult<Binary> {
    let stage = AirdropStages::get_latest(storage)?;
    to_binary(&QueryAnswer::AirdropStage { stage })
}

fn query_merkle_root(storage: &dyn Storage, stage: u8) -> StdResult<Binary> {
    let start = AirdropStagesStart::get(storage, stage);

    if start == None {
        return to_binary(&QueryAnswer::MerkleRoot {
            stage,
            expiration: Expiration::Never {},
            start: Expiration::Never {},
            merkle_root: String::from(""),
            total_amount: Uint128::new(0),
        });
    }

    let merkle_root = MerkleRoots::get(storage, stage);
    if merkle_root.is_none() {
        return Err(StdError::generic_err("No airdrop for this stage"));
    }
    let expiration = AirdropStagesExpiration::get(storage, stage);
    let total_amount = AirdropStagesTotalAmount::load(storage, stage);
    to_binary(&QueryAnswer::MerkleRoot {
        stage,
        expiration,
        total_amount: Uint128::new(total_amount),
        merkle_root: merkle_root.unwrap(),
        start: start.unwrap(),
    })
}

fn query_transfers(deps: Deps, account: &Addr, page: u32, page_size: u32) -> StdResult<Binary> {
    let address = deps.api.addr_canonicalize(account.as_str())?;
    let (txs, total) =
        StoredLegacyTransfer::get_transfers(deps.api, deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransferHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

fn query_transactions(deps: Deps, account: &Addr, page: u32, page_size: u32) -> StdResult<Binary> {
    let address = deps.api.addr_canonicalize(account.as_str())?;
    let (txs, total) = StoredRichTx::get_txs(deps.api, deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransactionHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

fn query_balance(deps: Deps, account: &Addr) -> StdResult<Binary> {
    let amount = Uint128::new(BalancesStore::load(deps.storage, account));
    let staked_amount = Uint128::new(StakedBalancesStore::load(deps.storage, account));

    let response = QueryAnswer::Balance {
        amount,
        staked_amount,
    };
    to_binary(&response)
}

fn query_airdrop_claimed(deps: Deps, stage: u8, address: &Addr) -> StdResult<Binary> {
    // check stage exists
    let latest_stage = AirdropStages::get_latest(deps.storage).unwrap();
    if stage > latest_stage {
        return Err(StdError::generic_err("No such stage"));
    }

    let start = AirdropStagesStart::get(deps.storage, stage).unwrap();
    let expiration = AirdropStagesExpiration::get(deps.storage, stage);
    let amount = AirdropsClaimed::get(deps.storage, stage, address.to_string()).unwrap_or(0);
    let response = QueryAnswer::AirdropClaimed {
        claimed: amount > 0,
        amount,
        expiration,
        start,
    };
    return to_binary(&response);
}

fn change_admin(deps: DepsMut, info: &MessageInfo, address: Addr) -> StdResult<Response> {
    let mut constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    constants.admin = address;
    Constants::save(deps.storage, &constants)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ChangeAdmin { status: Success })?))
}

fn try_set_key(deps: DepsMut, info: &MessageInfo, key: String) -> StdResult<Response> {
    ViewingKey::set(deps.storage, info.sender.as_str(), key.as_str());
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetViewingKey {
            status: Success,
        })?),
    )
}

fn try_create_key(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    entropy: String,
) -> StdResult<Response> {
    let key = ViewingKey::create(
        deps.storage,
        info,
        &env,
        info.sender.as_str(),
        (&entropy).as_ref(),
    );

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::CreateViewingKey {
            key: ViewingKeyObj(key),
        })?),
    )
}

fn set_contract_status(
    deps: DepsMut,
    info: &MessageInfo,
    status_level: ContractStatusLevel,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    ContractStatusStore::save(deps.storage, status_level)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetContractStatus {
            status: Success,
        })?),
    )
}

fn try_stake(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    amount_to_stake: Uint128,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;

    if amount_to_stake.is_zero() {
        return Err(StdError::generic_err("No funds were sent to be staked"));
    }

    let unstaked_balance = BalancesStore::load(deps.storage, &info.sender);
    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;

    if let Some(balance) = unstaked_balance.checked_sub(amount_to_stake.u128()) {
        // reduce the sender's unstaked balance
        BalancesStore::save(deps.storage, &info.sender, balance)?;
    } else {
        // Trying to stake an amount over the current wallet balance
        return Err(StdError::generic_err("Not enough funds."));
    }

    // update the sender's staked balance
    let staked_balance = StakedBalancesStore::load(deps.storage, &info.sender);
    let new_staked_balance = staked_balance.checked_add(amount_to_stake.u128());
    if new_staked_balance.is_some() {
        StakedBalancesStore::save(deps.storage, &info.sender, new_staked_balance.unwrap())?;
    } else {
        return Err(StdError::generic_err(
            "This stake would overflow your balance",
        ));
    }

    // update wallet's history
    store_stake_in_history(
        deps.storage,
        &sender_address,
        amount_to_stake,
        constants.symbol,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Stake { status: Success })?))
}

fn try_unstake(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;
    let amount_raw = amount.u128();

    let staked_balances = StakedBalancesStore::load(deps.storage, &info.sender);
    let new_staked_balance = staked_balances.checked_sub(amount_raw);

    // reduce staked balance
    if new_staked_balance.is_some() {
        StakedBalancesStore::save(deps.storage, &info.sender, new_staked_balance.unwrap())?;
    } else {
        return Err(StdError::generic_err(format!(
            "Insufficient funds to unstake: balance={}, wanted={}",
            staked_balances, amount_raw
        )));
    }

    CLAIMS.create_claim(
        deps.storage,
        &info.sender,
        amount,
        constants.unbonding_period.after(&env.block),
    )?;

    store_unstake_in_history(
        deps.storage,
        &sender_address,
        amount,
        constants.symbol,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Unstake { status: Success })?))
}

fn try_claim(deps: DepsMut, env: Env, info: &MessageInfo) -> StdResult<Response> {
    let release = CLAIMS.claim_tokens(
        deps.storage,
        &info.sender,
        &env.block,
        Some(Uint128::new(100000)),
    )?;

    if release.is_zero() {
        return Err(StdError::generic_err("Nothing to claim"));
    }

    // update balance
    let to_transfer = BalancesStore::load(deps.storage, &info.sender) + release.u128();
    BalancesStore::save(deps.storage, &info.sender, to_transfer)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Claim {
        status: Success,
        amount: to_transfer,
    })?))
}

fn query_claim(deps: Deps, account: &Addr) -> StdResult<Binary> {
    let claim_result = CLAIMS.query_claims(deps, &deps.api.addr_validate(account.as_str())?);

    let response = QueryAnswer::Claim {
        amounts: claim_result.unwrap().claims,
    };
    to_binary(&response)
}

fn try_transfer_impl(
    deps: &mut DepsMut,
    sender: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    perform_transfer(deps.storage, sender, recipient, amount.u128())?;

    let symbol = Constants::load(deps.storage)?.symbol;
    let sender = deps.api.addr_canonicalize(sender.as_str())?;
    let recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    store_transfer_in_history(
        deps.storage,
        &sender,
        &sender,
        &recipient,
        amount,
        symbol,
        memo,
        block,
    )?;

    Ok(())
}

fn try_transfer(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    recipient: Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    try_transfer_impl(
        &mut deps,
        &info.sender,
        &recipient,
        amount,
        memo,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Transfer { status: Success })?))
}

fn try_transfer_from_impl(
    deps: &mut DepsMut,
    env: &Env,
    spender: &Addr,
    owner: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<()> {
    let raw_amount = amount.u128();

    perform_transfer(deps.storage, spender, recipient, raw_amount)?;

    let symbol = Constants::load(deps.storage)?.symbol;

    let owner = deps.api.addr_canonicalize(owner.as_str())?;
    let spender = deps.api.addr_canonicalize(spender.as_str())?;
    let recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    store_transfer_in_history(
        deps.storage,
        &owner,
        &spender,
        &recipient,
        amount,
        symbol,
        memo,
        &env.block,
    )?;

    Ok(())
}

fn try_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    spender: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    try_transfer_from_impl(
        &mut deps,
        env,
        spender,
        &info.sender,
        recipient,
        amount,
        memo,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::TransferFrom { status: Success })?))
}

fn try_batch_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    actions: Vec<batch::TransferFromAction>,
) -> StdResult<Response> {
    for action in actions {
        try_transfer_from_impl(
            &mut deps,
            env,
            &info.sender,
            &action.owner,
            &action.recipient,
            action.amount,
            action.memo,
        )?;
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::BatchTransferFrom {
            status: Success,
        })?),
    )
}

fn execute_register_merkle_root(
    deps: DepsMut,
    info: &MessageInfo,
    merkle_root: String,
    expiration: Expiration,
    start: Expiration,
    total_amount: Uint128,
    stage: Option<u8>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    // check merkle root length
    let mut root_buf: [u8; 32] = [0; 32];
    let decoded: Result<(), FromHexError> = hex::decode_to_slice(&merkle_root, &mut root_buf);
    if decoded.is_err() {
        return Err(StdError::generic_err("Invalid markle root"));
    }

    let next_stage = if let Some(stage) = stage {
        stage
    } else {
        AirdropStages::get_latest(deps.storage)? + 1
    };

    MerkleRoots::save(deps.storage, next_stage, &merkle_root)?;
    AirdropStages::set_new_stage(deps.storage, next_stage)?;
    AirdropStagesExpiration::save(deps.storage, next_stage, expiration)?;
    AirdropStagesStart::save(deps.storage, next_stage, start)?;
    AirdropStagesTotalAmount::save(deps.storage, next_stage, total_amount.u128())?;
    AirdropStagesTotalAmountCaimed::save(deps.storage, next_stage, 0u128)?;
    Constants::save(deps.storage, &constants)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RegisterMerkleRoot {
            stage: next_stage,
            expiration,
            start,
            merkle_root,
            airdrop_source_wallet: constants.airdrop_source_wallet.to_string(),
        })?),
    )
}

fn execute_claim_airdrop(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    stage: u8,
    amount: Uint128,
    proof: Vec<String>,
) -> StdResult<Response> {
    // check stage exists
    let latest_stage = AirdropStages::get_latest(deps.storage).unwrap();
    if stage > latest_stage {
        return Err(StdError::generic_err("No such stage"));
    }

    let start = AirdropStagesStart::get(deps.storage, stage);
    if start == None || !start.unwrap().is_triggered(&env.block) {
        return Err(StdError::generic_err(
            "airdrop stage is not live yet: Start ".to_string()
                + start.unwrap().as_seconds().to_string().as_str()
                + " seconds vs Current block time "
                + &env.block.time.seconds().to_string(),
        ));
    }

    // not expired
    let expiration = AirdropStagesExpiration::get(deps.storage, stage);
    if expiration.is_expired(&env.block) {
        return Err(StdError::generic_err(
            "airdrop stage has expired. Expiration ".to_string()
                + expiration.as_seconds().to_string().as_str()
                + " seconds vs Current block "
                + &env.block.time.seconds().to_string(),
        ));
    }

    // verify not claimed
    let proof_addr = info.sender.to_string();
    if let Some(claimed) = AirdropsClaimed::get(deps.storage, stage, proof_addr.clone()) {
        return Err(StdError::generic_err(format!(
            "Already claimed amount {}",
            claimed
        )));
    }

    let user_input = format!("{}{}", proof_addr, amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes())
        .as_slice()
        .try_into()
        .map_err(|_| StdError::generic_err("Wrong length"))?;

    let hash = proof.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        let res = hex::decode_to_slice(p, &mut proof_buf);
        if res.is_err() {
            return Err(StdError::generic_err("Hash verification failed."));
        }
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        sha2::Sha256::digest(&hashes.concat())
            .as_slice()
            .try_into()
            .map_err(|_| StdError::generic_err("Wrong length"))
    })?;

    // verify merkle root
    let merkle_root = MerkleRoots::get(deps.storage, stage);
    if merkle_root.is_none() {
        return Err(StdError::generic_err("No airdrop for this stage."));
    }
    let mut root_buf: [u8; 32] = [0; 32];
    let res = hex::decode_to_slice(merkle_root.unwrap(), &mut root_buf);
    if res.is_err() || root_buf != hash {
        return Err(StdError::generic_err("Root verification failed."));
    }

    // Update claim index to the current stage
    AirdropsClaimed::set_claimed(deps.storage, stage, proof_addr.clone(), amount.u128()).unwrap();

    // Update total claimed to reflect
    let mut total_claimed_amount = AirdropStagesTotalAmountCaimed::load(deps.storage, stage);
    total_claimed_amount += amount.u128();
    AirdropStagesTotalAmountCaimed::save(deps.storage, stage, total_claimed_amount)?;

    // transfer tokens
    let constants = Constants::load(deps.storage)?;
    try_transfer_from_impl(
        &mut deps,
        &env,
        &constants.airdrop_source_wallet,
        &constants.contract_address,
        &Addr::unchecked(proof_addr),
        amount,
        None, // FIXME: from HS with love?
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Claim {
        amount: amount.u128(),
        status: Success,
    })?))
}

fn execute_register_airdrop_source_wallet(
    deps: DepsMut,
    info: &MessageInfo,
    address: Addr,
) -> StdResult<Response> {
    let mut constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    constants.airdrop_source_wallet = address;
    Constants::save(deps.storage, &constants)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RegisterAirdropSourceWallet {
            status: Success,
        })?),
    )
}

fn execute_withdraw_airdrop_unclaimed(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    stage: u8,
    address: String,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    // make sure is started
    let start = AirdropStagesStart::get(deps.storage, stage);
    if start == None || !start.unwrap().is_expired(&env.block) {
        return Err(StdError::generic_err("Airdrop has not started"));
    }

    // make sure is expired
    let expiration = AirdropStagesExpiration::get(deps.storage, stage);
    if !expiration.is_expired(&env.block) {
        return Err(StdError::generic_err("Airdrop has not expired"));
    }

    // Get total amount per stage and total claimed
    let total_amount = AirdropStagesTotalAmount::load(deps.storage, stage);
    let claimed_amount = AirdropStagesTotalAmountCaimed::load(deps.storage, stage);

    // impossible but who knows
    if claimed_amount > total_amount {
        return Err(StdError::generic_err("Claimed amount > total amount"));
    }

    // Get balance
    let balance_to_withdraw = total_amount - claimed_amount;

    // Validate address
    let recipient = deps.api.addr_validate(&address)?;

    // Withdraw the tokens and response
    let constants = Constants::load(deps.storage)?;
    try_transfer_from_impl(
        &mut deps,
        &env,
        &constants.airdrop_source_wallet,
        &constants.contract_address,
        &recipient,
        Uint128::new(balance_to_withdraw),
        None,
    )?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::WithdrawUnclaimed {
            amount: balance_to_withdraw,
            status: Success,
        })?),
    )
}

fn execute_update_stage_exp(
    deps: DepsMut,
    info: &MessageInfo,
    stage: u8,
    new_expiration: Expiration,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    AirdropStagesExpiration::save(deps.storage, stage, new_expiration)?;
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::UpdateExpDate {
            status: Success,
        })?),
    )
}

fn perform_transfer(
    store: &mut dyn Storage,
    from: &Addr,
    to: &Addr,
    amount: u128,
) -> StdResult<()> {
    let mut from_balance = BalancesStore::load(store, from);

    if let Some(new_from_balance) = from_balance.checked_sub(amount) {
        from_balance = new_from_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds for {}: balance={}, required={}",
            from.to_string(),
            from_balance,
            amount
        )));
    }
    BalancesStore::save(store, from, from_balance)?;

    let mut to_balance = BalancesStore::load(store, to);
    to_balance = to_balance.checked_add(amount).ok_or_else(|| {
        StdError::generic_err("This tx will literally make them too rich. Try transferring less")
    })?;
    BalancesStore::save(store, to, to_balance)?;

    Ok(())
}

fn get_all_token_balances(deps: DepsMut, info: &MessageInfo) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_readonly_admin(&constants.readonly_admin, &info.sender)?;

    let all_balances = BalancesStore::get_all(deps.storage);

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::GetAll {
        result: all_balances,
    })?))
}

fn get_all_airdrop_claims(deps: DepsMut, info: &MessageInfo) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_readonly_admin(&constants.readonly_admin, &info.sender)?;

    let all_balances = AirdropsClaimed::get_all(deps.storage);

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::GetAllClaimed {
            result: all_balances,
        })?),
    )
}

fn check_if_admin(config_admin: &Addr, account: &Addr) -> StdResult<()> {
    if config_admin != account {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

fn check_if_readonly_admin(config_admin: &Addr, account: &Addr) -> StdResult<()> {
    if config_admin != account {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from readonly admin address"
                .to_string()
                + config_admin.as_str(),
        ));
    }

    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    (3..=30).contains(&len)
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = (3..=6).contains(&len);

    len_is_valid && symbol.bytes().all(|byte| (b'A'..=b'Z').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, from_slice, Coin, OwnedDeps, QueryResponse, Timestamp};
    use serde::Deserialize;

    use crate::msg::ResponseStatus;
    use crate::msg::WalletBalances;
    use crate::storage::claim::Claim as ClaimAmount;
    use crate::storage::expiration::Duration;
    use crate::viewing_key_obj::ViewingKeyObj;

    use super::*;

    pub const VIEWING_KEY_SIZE: usize = 32;

    // Helper functions

    fn init_helper(
        initial_balances: Vec<WalletBalances>,
    ) -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[]);
        let env = mock_env();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {
            name: "stoken".to_string(),
            readonly_admin: Addr::unchecked("admin_readonly".to_string()),
            symbol: "TOKEN".to_string(),
            initial_balances,
            airdrop_source_wallet: Addr::unchecked("airdrop_source_wallet".to_string()),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    fn init_helper_with_config(
        initial_balances: Vec<WalletBalances>,
        contract_bal: u128,
    ) -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "stoken".to_string(),
            amount: Uint128::new(contract_bal),
        }]);

        let env = mock_env();
        let info = mock_info("admin", &[]);

        let init_msg = InstantiateMsg {
            name: "stoken".to_string(),
            readonly_admin: Addr::unchecked("admin_readonly".to_string()),
            symbol: "TOKEN".to_string(),
            initial_balances,
            airdrop_source_wallet: Addr::unchecked("airdrop_source_wallet".to_string()),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    fn init_helper_with_airdrop(
        total_amount: u128,
    ) -> (Vec<u8>, OwnedDeps<MockStorage, MockApi, MockQuerier>) {
        let (init_result, deps) = init_helper(vec![WalletBalances {
            address: "airdrop_source_wallet".to_string(),
            unstaked: total_amount,
            staked: 0,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let test_data = "{
            \"account\": \"wasm1k9hwzxs889jpvd7env8z49gad3a3633vg350tq\",
            \"amount\": \"100\",
            \"root\": \"b45c1ea28b26adb13e412933c9e055b01fdf7585304b00cd8f1cb220aa6c5e88\",
            \"proofs\": [
                \"a714186eaedddde26b08b9afda38cf62fdf88d68e3aa0d5a4b55033487fe14a1\",
                \"fb57090a813128eeb953a4210dd64ee73d2632b8158231effe2f0a18b2d3b5dd\",
                \"c30992d264c74c58b636a31098c6c27a5fc08b3f61b7eafe2a33dcb445822343\"
            ]}"
        .as_bytes();

        (test_data.to_owned(), deps)
    }

    fn init_helper_airdrop_multiple_users(
        total_amount: u128,
    ) -> (MultipleData, OwnedDeps<MockStorage, MockApi, MockQuerier>) {
        let (_init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "airdrop_source_wallet".to_string(),
            unstaked: total_amount,
            staked: 0,
        }]);
        let test_data = "{
            \"root\": \"b45c1ea28b26adb13e412933c9e055b01fdf7585304b00cd8f1cb220aa6c5e88\",
            \"accounts\": [
                 {\"account\": \"wasm1k9hwzxs889jpvd7env8z49gad3a3633vg350tq\",
                    \"amount\": \"100\",
                    \"proofs\": [
                        \"a714186eaedddde26b08b9afda38cf62fdf88d68e3aa0d5a4b55033487fe14a1\",
                        \"fb57090a813128eeb953a4210dd64ee73d2632b8158231effe2f0a18b2d3b5dd\",
                        \"c30992d264c74c58b636a31098c6c27a5fc08b3f61b7eafe2a33dcb445822343\"
                    ]},{\"account\": \"wasm1uy9ucvgerneekxpnfwyfnpxvlsx5dzdpf0mzjd\",
                    \"amount\": \"1010\",
                    \"proofs\": [
                        \"d496b14f0a6207db1c9a1be70d5f3684d3c76f27c0bc75ee979f3e2a71a97ed0\",
                        \"e3746c7f0e1d1f60708f9e5facaaee77424a8c5f6527f1813f60e8c3755d3b5d\",
                        \"c30992d264c74c58b636a31098c6c27a5fc08b3f61b7eafe2a33dcb445822343\"
                    ]},{\"account\": \"wasm1a4x6au55s0fusctyj2ulrxvfpmjcxa92k7ze2v\",
                    \"amount\": \"10220\",
                    \"proofs\": [
                        \"b69c5239d434753af2f6c3eab47f4e78c436f862f14e6989be5c9027c2b6dfe2\",
                        \"e3746c7f0e1d1f60708f9e5facaaee77424a8c5f6527f1813f60e8c3755d3b5d\",
                        \"c30992d264c74c58b636a31098c6c27a5fc08b3f61b7eafe2a33dcb445822343\"
                    ]},{\"account\": \"wasm1ylna88nach9sn5n7qe7u5l6lh7dmt6lp2y63xx\",
                    \"amount\": \"10333\",
                    \"proofs\": [\"f89c4ec6a98e26fb5690e50e16e189f9942f0576a5ba711ed75fe01140ddb2af\",\"374f1a32b0a5d5dab16f8fbed8c248e183448732f897002375e0d4ca6e13ad73\"]
                }]}"
            .as_bytes();
        let test_data: MultipleData = from_slice(test_data.clone()).unwrap();
        let env = mock_env();

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root.clone(),
            expiration: Duration::Time(10000).after(&env.block),
            start: Duration::Time(1001).after(&env.block),
            total_amount: Uint128::new(42103),
        };

        let info = mock_info("admin", &[]);
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        (test_data, deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(response) => {
                let bin_err = (&response as &dyn Any)
                    .downcast_ref::<QueryResponse>()
                    .expect("An error was expected, but no error could be extracted");
                match from_binary(bin_err).unwrap() {
                    QueryAnswer::ViewingKeyError { msg } => msg,
                    _ => panic!("Unexpected query answer"),
                }
            }
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected result from init"),
            },
        }
    }

    fn ensure_success(handle_result: Response) -> bool {
        let handle_result: ExecuteAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            ExecuteAnswer::Stake { status }
            | ExecuteAnswer::Claim { status, .. }
            | ExecuteAnswer::Unstake { status }
            | ExecuteAnswer::Transfer { status }
            | ExecuteAnswer::RegisterReceive { status }
            | ExecuteAnswer::SetViewingKey { status }
            | ExecuteAnswer::TransferFrom { status }
            | ExecuteAnswer::ChangeAdmin { status }
            | ExecuteAnswer::SetContractStatus { status } => {
                matches!(status, ResponseStatus::Success { .. })
            }
            _ => panic!(
                "ExecuteAnswer not supported for success extraction: {:?}",
                handle_result
            ),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "lebron".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = Constants::load(&deps.storage).unwrap();
        assert_eq!(TotalSupplyStore::load(&deps.storage).unwrap(), 20000);
        assert_eq!(
            ContractStatusStore::load(&deps.storage).unwrap(),
            ContractStatusLevel::NormalRun
        );
        assert_eq!(constants.name, "stoken".to_string());
        assert_eq!(constants.admin, Addr::unchecked("admin".to_string()));
        assert_eq!(constants.symbol, "TOKEN".to_string());

        ViewingKey::set(deps.as_mut().storage, "lebron", "lolz fun yay");
        let is_vk_correct = ViewingKey::check(&deps.storage, "lebron", "lolz fun yay");
        assert!(
            is_vk_correct.is_ok(),
            "Viewing key verification failed!: {}",
            is_vk_correct.err().unwrap()
        );
    }

    #[test]
    fn test_init_with_config_sanity() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "lebron".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            }],
            0,
        );
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = Constants::load(&deps.storage).unwrap();
        assert_eq!(TotalSupplyStore::load(&deps.storage).unwrap(), 20000);
        assert_eq!(
            ContractStatusStore::load(&deps.storage).unwrap(),
            ContractStatusLevel::NormalRun
        );
        assert_eq!(constants.name, "stoken".to_string());
        assert_eq!(constants.admin, Addr::unchecked("admin".to_string()));
        assert_eq!(constants.symbol, "TOKEN".to_string());

        ViewingKey::set(deps.as_mut().storage, "lebron", "lolz fun yay");
        let is_vk_correct = ViewingKey::check(&deps.storage, "lebron", "lolz fun yay");
        assert!(
            is_vk_correct.is_ok(),
            "Viewing key verification failed!: {}",
            is_vk_correct.err().unwrap()
        );
    }

    #[test]
    fn test_total_supply_overflow() {
        let (init_result, _deps) = init_helper(vec![WalletBalances {
            address: "lebron".to_string(),
            unstaked: u128::MAX,
            staked: 0,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result, _deps) = init_helper(vec![
            WalletBalances {
                address: "lebron".to_string(),
                unstaked: u128::MAX,
                staked: 0,
            },
            WalletBalances {
                address: "giannis".to_string(),
                unstaked: 1,
                staked: 1,
            },
        ]);
        let error = extract_error_msg(init_result);
        assert_eq!(
            error,
            "The sum of all initial balances exceeds the maximum possible total supply"
        );
    }

    // Handle tests

    #[test]
    fn test_handle_transfer() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "daniel".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: None,
            padding: None,
        };
        let info = mock_info("daniel", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let bob_addr = Addr::unchecked("daniel".to_string());
        let alice_addr = Addr::unchecked("alice".to_string());

        assert_eq!(5000 - 1000, BalancesStore::load(&deps.storage, &bob_addr));
        assert_eq!(1000, BalancesStore::load(&deps.storage, &alice_addr));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(10000),
            memo: None,
            padding: None,
        };
        let info = mock_info("daniel", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient funds"));
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "arthur".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let info = mock_info("arthur", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let result = ViewingKey::check(&deps.storage, "arthur", key.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "anonymous".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let info = mock_info("anonymous", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey { status: Success }).unwrap(),
        );

        // Set valid VK
        let actual_vk = ViewingKeyObj("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: actual_vk.0.clone(),
            padding: None,
        };
        let info = mock_info("anonymous", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey { status: Success }).unwrap(),
        );

        let result = ViewingKey::check(&deps.storage, "anonymous", actual_vk.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_transfer_from() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "bob".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Sanity check
        let handle_msg = ExecuteMsg::TransferFrom {
            spender: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = Addr::unchecked("bob".to_string());
        let alice_canonical = Addr::unchecked("alice".to_string());

        let bob_balance = BalancesStore::load(&deps.storage, &bob_canonical);
        let alice_balance = BalancesStore::load(&deps.storage, &alice_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(alice_balance, 2000);
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 20000);
    }

    #[test]
    fn test_handle_change_admin() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "bobby".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::ChangeAdmin {
            address: Addr::unchecked("bobby".to_string()),
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = Constants::load(&deps.storage).unwrap().admin;
        assert_eq!(admin, Addr::unchecked("bobby".to_string()));
    }

    #[test]
    fn test_handle_set_contract_status() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "admin".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = ContractStatusStore::load(&deps.storage).unwrap();
        assert!(matches!(
            contract_status,
            ContractStatusLevel::StopAll { .. }
        ));
    }

    #[test]
    fn test_handle_unstake() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "butler".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            }],
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_no_reserve, mut deps_no_reserve) = init_helper_with_config(
            vec![WalletBalances {
                address: "butler".to_string(),
                unstaked: 0,
                staked: 0,
            }],
            0,
        );
        assert!(
            init_result_no_reserve.is_ok(),
            "Init failed: {}",
            init_result_no_reserve.err().unwrap()
        );

        // test when unstake enabled
        // try to unstake when contract has 0 balance
        let handle_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(1),
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps_no_reserve.as_mut(), mock_env(), info, handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Insufficient funds to unstake: balance=0, wanted=1"));

        // unstake 1000
        let handle_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("butler", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let canonical = Addr::unchecked("butler".to_string());
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 14000);

        // check pending claims
        let constants = Constants::load(&deps.storage).unwrap();
        let expires = constants.unbonding_period.after(&mock_env().block);
        let info = mock_info("butler", &[]);

        let claim_response = CLAIMS.query_claims(deps.as_ref(), &info.sender);
        assert!(
            claim_response.is_ok(),
            "Init failed: {}",
            claim_response.err().unwrap()
        );
        let claim_response = claim_response.unwrap();
        assert_eq!(claim_response.claims, vec![ClaimAmount::new(1000, expires)]);
    }

    #[test]
    fn test_token_claim() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "lebron".to_string(),
                unstaked: 5000u128,
                staked: 0,
            }],
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let mut env = mock_env();
        let canonical = Addr::unchecked("lebron".to_string());

        // stake some tokens
        let handle_msg = ExecuteMsg::Stake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("lebron", &[]);
        let handle_result = execute(deps.as_mut(), env.clone(), info, handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        // check balances
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 4000);
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 1000);

        // unstake them
        let handle_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("lebron", &[]);
        let handle_result = execute(deps.as_mut(), env.clone(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        // check balances
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 4000);
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 0);

        // check claims before expiration
        let constants = Constants::load(&deps.storage).unwrap();
        let expires = constants.unbonding_period.after(&mock_env().block);
        let info = mock_info("lebron", &[]);

        let claim_response = CLAIMS.query_claims(deps.as_ref(), &info.sender);
        assert!(
            claim_response.is_ok(),
            "Init failed: {}",
            claim_response.err().unwrap()
        );
        let claim_response = claim_response.unwrap();
        assert_eq!(claim_response.claims, vec![ClaimAmount::new(1000, expires)]);

        // query claims
        // create viewing key first
        let create_vk_msg = ExecuteMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let info = mock_info("lebron", &[]);
        let handle_response = execute(deps.as_mut(), mock_env(), info, create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };
        let info = mock_info("lebron", &[]);
        // query claim
        let query_claim_msg = QueryMsg::Claim {
            address: info.clone().sender,
            key: vk.0,
        };
        let query_response = query(deps.as_ref(), mock_env(), query_claim_msg).unwrap();
        let claims = match from_binary(&query_response).unwrap() {
            QueryAnswer::Claim { amounts, .. } => amounts,
            _ => panic!("Unexpected result from claim query"),
        };
        let constants = Constants::load(&deps.storage).unwrap();
        let expires = constants.unbonding_period.after(&mock_env().block);

        assert_eq!(
            claims,
            vec![ClaimAmount {
                amount: Uint128::new(1000),
                release_at: expires,
            }]
        );
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 4000);
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 0);

        // wait for height to unstake
        env.block.time = env.block.time.plus_seconds(10000000); // no idea how to convert constants.unbonding_period to seconds

        // execute claims
        let handle_msg = ExecuteMsg::Claim {};
        let info = mock_info("lebron", &[]);
        let handle_response = execute(deps.as_mut(), env.clone(), info, handle_msg);

        assert!(ensure_success(handle_response.unwrap()));
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 5000);
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 0);
    }

    #[test]
    fn test_handle_stake() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "excis".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            }],
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test when stake enabled
        let handle_msg = ExecuteMsg::Stake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("excis", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let canonical = Addr::unchecked("excis".to_string());
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 4000);
        assert_eq!(StakedBalancesStore::load(&deps.storage, &canonical), 16000);
    }

    #[test]
    fn test_handle_admin_commands() {
        let admin_err = "Admin commands can only be run from admin address".to_string();
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "lestat".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            }],
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButUnstake,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let change_admin_msg = ExecuteMsg::ChangeAdmin {
            address: Addr::unchecked("not_admin".to_string()),
            padding: None,
        };
        let info = mock_info("not_admin", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, change_admin_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));
    }

    #[test]
    fn test_handle_pause_with_withdrawals() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "natachatte".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            }],
            20000,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButUnstake,
            padding: None,
        };
        let info = mock_info("admin", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let transfer_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("account".to_string()),
            amount: Uint128::new(123),
            memo: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, transfer_msg);
        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(5000),
        };
        let info = mock_info("natachatte", &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, withdraw_msg);

        assert!(
            handle_result.is_ok(),
            "Withdraw failed: {}",
            handle_result.err().unwrap()
        );
    }

    #[test]
    fn test_handle_pause_all() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "francis".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };

        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let transfer_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("account".to_string()),
            amount: Uint128::new(123),
            memo: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, transfer_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(5000),
        };
        let info = mock_info("francis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, withdraw_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );
    }

    // Query tests

    #[test]
    fn test_authenticated_queries() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "giannis".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
            key: "no_vk_yet".to_string(),
        };
        let info = mock_info("giannis", &[]);
        let query_result = query(deps.as_ref(), mock_env(), no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = ExecuteMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let handle_response =
            execute(deps.as_mut(), mock_env(), info.clone(), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
            key: vk.0,
        };

        let query_response = query(deps.as_ref(), mock_env(), query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance {
                amount,
                staked_amount,
            } => amount + staked_amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128::new(20000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
            key: "wrong_vk".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), wrong_vk_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );
    }

    #[test]
    fn test_query_token_info() {
        let (_init_result, deps) = init_helper(vec![WalletBalances {
            address: "giannis".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        let query_msg = QueryMsg::TokenInfo {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenInfo {
                name,
                symbol,
                decimals,
                total_supply,
            } => {
                assert_eq!(name, "stoken".to_string());
                assert_eq!(symbol, "TOKEN".to_string());
                assert_eq!(decimals, 0);
                assert_eq!(total_supply, Uint128::new(20000));
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_config() {
        let (_init_result, deps) = init_helper(vec![]);
        let query_msg = QueryMsg::TokenConfig {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenConfig {
                decimals,
                unbonding_period,
            } => {
                assert_eq!(unbonding_period, WEEK);
                assert_eq!(decimals, 0u8);
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_balance() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "michael".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let info = mock_info("michael", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info.clone(), handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey { status: Success }).unwrap(),
        );

        let query_msg = QueryMsg::Balance {
            address: Addr::unchecked("michael".to_string()),
            key: "wrong_key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: Addr::unchecked("michael".to_string()),
            key: "key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance {
                amount,
                staked_amount,
            } => amount + staked_amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128::new(20000));
    }

    #[test]
    fn test_query_transfer_history() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "jean".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let info = mock_info("jean", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: None,
            padding: None,
        };
        let info = mock_info("jean", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("banana".to_string()),
            amount: Uint128::new(500),
            memo: None,
            padding: None,
        };
        let info = mock_info("jean", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("mango".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("jean", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info.clone(), handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("jean".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 0,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert!(transfers.is_empty());

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("jean".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("jean".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 2,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 2);

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("jean".to_string()),
            key: "key".to_string(),
            page: Some(1),
            page_size: 2,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 1);
    }

    #[test]
    fn test_query_transaction_history() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![WalletBalances {
                address: "bob".to_string(),
                unstaked: 10000u128,
                staked: 15000u128,
            }],
            1000,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Unstake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Stake {
            amount: Uint128::new(1000),
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: Some("my transfer message #1".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("banana".to_string()),
            amount: Uint128::new(500),
            memo: Some("my transfer message #2".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("mango".to_string()),
            amount: Uint128::new(2500),
            memo: Some("my transfer message #3".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info.clone(), handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransactionHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };

        use crate::transaction_history::{RichTx, TxAction};
        let expected_transfers = [
            RichTx {
                id: 5,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("mango".to_string()),
                },
                coins: Coin {
                    denom: "TOKEN".to_string(),
                    amount: Uint128::new(2500),
                },
                memo: Some("my transfer message #3".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 4,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("banana".to_string()),
                },
                coins: Coin {
                    denom: "TOKEN".to_string(),
                    amount: Uint128::new(500),
                },
                memo: Some("my transfer message #2".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 3,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("alice".to_string()),
                },
                coins: Coin {
                    denom: "TOKEN".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: Some("my transfer message #1".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 2,
                action: TxAction::Stake {},
                coins: Coin {
                    denom: "TOKEN".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 1,
                action: TxAction::Unstake {},
                coins: Coin {
                    denom: "TOKEN".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];

        assert_eq!(transfers, expected_transfers);
    }

    #[test]
    fn test_execute_register_merkle_root() {
        let (init_result, mut deps) = init_helper(vec![WalletBalances {
            address: "francisco".to_string(),
            unstaked: 5000u128,
            staked: 15000u128,
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let env = mock_env();
        let info = mock_info("not_admin", &[]);

        let expiration = Expiration::AtTime(Timestamp::from_seconds(1000));
        let start = Expiration::AtTime(Timestamp::from_seconds(100));
        let merkle_root =
            "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37".to_string();

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root,
            total_amount: Uint128::new(10000),
            expiration,
            start,
        };

        // from unauthorized address
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone());
        let error = extract_error_msg(res);
        assert!(error.contains("Admin commands can only be run from admin address"));

        // from admin address
        let info = mock_info("admin", &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::RegisterMerkleRoot {
                stage: 1,
                expiration,
                start,
                merkle_root: "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37"
                    .to_string(),
                airdrop_source_wallet: "airdrop_source_wallet".to_string()
            })
            .unwrap(),
        );

        let query_result = query(deps.as_ref(), env.clone(), QueryMsg::LatestStage {});
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();

        assert_eq!(
            to_binary(&query_answer).unwrap(),
            to_binary(&QueryAnswer::AirdropStage { stage: 1 }).unwrap(),
        );

        let query_result = query(deps.as_ref(), env, QueryMsg::MerkleRoot { stage: 1 });
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();

        match query_answer {
            QueryAnswer::MerkleRoot {
                stage,
                start,
                merkle_root,
                total_amount,
                expiration,
            } => {
                assert_eq!(
                    merkle_root,
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37".to_string()
                );
                assert_eq!(stage, 1u8);
                assert_eq!(total_amount, Uint128::new(10000));
                assert_eq!(start, Expiration::AtTime(Timestamp::from_seconds(100)));
                assert_eq!(
                    expiration,
                    Expiration::AtTime(Timestamp::from_seconds(1000))
                );
            }
            _ => panic!("unexpected"),
        }
    }

    #[derive(Deserialize, Debug)]
    struct Encoded {
        account: String,
        amount: Uint128,
        root: String,
        proofs: Vec<String>,
    }

    #[derive(Deserialize, Debug)]
    struct Proof {
        account: String,
        amount: Uint128,
        proofs: Vec<String>,
    }

    #[derive(Deserialize, Debug)]
    struct MultipleData {
        root: String,
        accounts: Vec<Proof>,
    }

    #[test]
    fn test_claim_airdrop() {
        let (test_data, mut deps) = init_helper_with_airdrop(5000);
        let test_data: Encoded = from_slice(test_data.as_slice()).unwrap();
        let env = mock_env();
        let info = mock_info("admin", &[]);

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: Duration::Time(1000).after(&env.block),
            start: Duration::Time(0).after(&env.block),
            total_amount: Uint128::new(5000),
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg.clone()).unwrap();

        let msg = ExecuteMsg::ClaimAirdrop {
            stage: 1u8,
            amount: test_data.amount,
            proof: test_data.proofs.clone(),
        };

        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        let unwrapped_result: ExecuteAnswer = from_binary(&res.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::Claim {
                status: Success,
                amount: test_data.amount.u128()
            })
            .unwrap(),
        );

        // Check total claimed on stage 1
        let total_claimed = AirdropStagesTotalAmountCaimed::load(deps.as_mut().storage, 1);
        assert_eq!(total_claimed, test_data.amount.u128());

        // Check address is claimed
        let claimed_amount =
            AirdropsClaimed::get(deps.as_mut().storage, 1, test_data.account.to_string()).unwrap();
        assert_eq!(test_data.amount.u128(), claimed_amount);

        // contract address has less
        let contract_balance = BalancesStore::load(
            &deps.storage,
            &Addr::unchecked("airdrop_source_wallet".to_string()),
        );
        assert_eq!(4900u128, contract_balance);

        let msg = ExecuteMsg::ClaimAirdrop {
            stage: 1u8,
            amount: test_data.amount,
            proof: test_data.proofs,
        };
        // check error on double claim
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        let error = extract_error_msg(res);
        assert_eq!(error, "Already claimed amount 100");

        // Second test
        let test_data_2 = "{
          \"account\": \"wasm1uwcjkghqlz030r989clzqs8zlaujwyphx0yumy\",
          \"amount\": \"14\",
          \"root\": \"a5587bd4d158618b83badf57b1a4206f86e33407e18797ef690c931d73b36232\",
          \"proofs\": [
            \"a714186eaedddde26b08b9afda38cf62fdf88d68e3aa0d5a4b55033487fe14a1\",
            \"1eb08e61c40d5ba334f3c32f3f136e714f0841e5d53af6b78ec94e3b29a01e74\",
            \"fe570ffb0015447c01bffdcd266fe4ee21a23eb6b499461b9ced5a03c6a9b2f0\",
            \"fa0224da936bcebd0f018a46ba15a5a9fc2d637f72f7c14b31aeffd8964983b5\"
          ]}"
        .as_bytes();
        let test_data_2: Encoded = from_slice(test_data_2).unwrap();

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data_2.root,
            expiration: Duration::Time(10000).after(&env.block),
            start: Duration::Time(1001).after(&env.block),
            total_amount: Uint128::new(14),
        };

        let info = mock_info("admin", &[]);
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // wait for airdrop start height
        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(1002);

        let msg = ExecuteMsg::ClaimAirdrop {
            stage: 2u8,
            amount: test_data_2.amount,
            proof: test_data_2.proofs,
        };

        let info = mock_info(test_data_2.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env, info.clone(), msg.clone()).unwrap();
        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::Claim {
                status: Success,
                amount: test_data_2.amount.u128()
            })
            .unwrap(),
        );

        // Check total claimed on stage 1
        let total_claimed = AirdropStagesTotalAmountCaimed::load(deps.as_ref().storage, 1);
        assert_eq!(total_claimed, test_data.amount.u128());

        // Check total claimed on stage 2
        let total_claimed = AirdropStagesTotalAmountCaimed::load(deps.as_ref().storage, 2);
        assert_eq!(total_claimed, test_data_2.amount.u128());
    }

    #[test]
    #[ignore]
    fn test_claim_airdrop_multiple_users() {
        let (test_data, mut deps) = init_helper_airdrop_multiple_users(21663);
        let mut env = mock_env();

        // Check total claimed before claiming anything
        let total_claimed = AirdropStagesTotalAmountCaimed::load(deps.as_ref().storage, 1);
        assert_eq!(total_claimed, 0);

        // wait for airdrop start height
        env.block.time = env.block.time.plus_seconds(1002);

        // Loop accounts and claim
        for account in test_data.accounts.iter() {
            let msg = ExecuteMsg::ClaimAirdrop {
                amount: account.amount,
                stage: 1u8,
                proof: account.proofs.clone(),
            };

            let info = mock_info(account.account.as_str(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
            assert_eq!(
                to_binary(&unwrapped_result).unwrap(),
                to_binary(&ExecuteAnswer::Claim {
                    status: Success,
                    amount: account.amount.u128()
                })
                .unwrap(),
            );
        }

        // Check total claimed after all claims
        let total_claimed = AirdropStagesTotalAmountCaimed::load(deps.as_ref().storage, 1);
        assert_eq!(total_claimed, 21_663);

        // Check history from command
        let claimed_msg = ExecuteMsg::GetAllClaimed {};
        // when not admin
        let info = mock_info("roberto", &[]);
        let query_result = execute(deps.as_mut(), mock_env(), info.clone(), claimed_msg.clone());
        let error = extract_error_msg(query_result);
        assert!(error.contains(
            "This is an admin command. Admin commands can only be run from readonly admin address"
        ));

        // when admin_readonly
        let info = mock_info("admin_readonly", &[]);
        let query_response =
            execute(deps.as_mut(), mock_env(), info.clone(), claimed_msg.clone()).unwrap();
        let claimed_balances = match from_binary(&query_response.data.unwrap()).unwrap() {
            ExecuteAnswer::GetAllClaimed { result } => result,
            _ => panic!("Unexpected result from claim query"),
        };
        assert_eq!(4, claimed_balances.len());
    }

    #[test]
    fn test_claim_invalid_airdrop() {
        let (test_data, mut deps) = init_helper_with_airdrop(10000);
        let test_data: Encoded = from_slice(test_data.as_slice()).unwrap();
        let mut env = mock_env();
        let info = mock_info("admin", &[]);

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: Duration::Time(100).after(&env.block),
            start: Duration::Time(100).after(&env.block),
            total_amount: Uint128::new(10000),
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = ExecuteMsg::ClaimAirdrop {
            stage: 1u8,
            amount: test_data.amount,
            proof: test_data.proofs,
        };

        let info = mock_info(test_data.account.as_str(), &[]);

        // Can't withdraw not started stage
        let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone());
        let error = extract_error_msg(handle_result);
        assert!(error.contains("airdrop stage is not live yet"));

        // wait for airdrop start height - 1
        env.block.time = env.block.time.plus_seconds(99);

        let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone());
        let error = extract_error_msg(handle_result);
        assert!(error.contains("airdrop stage is not live yet"));

        // wait for airdrop expiration height + 1
        env.block.time = env.block.time.plus_seconds(101);

        // Can't withdraw expired stage
        let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone());
        let error = extract_error_msg(handle_result);
        assert!(error.contains("airdrop stage has expired."));
    }

    #[test]
    fn test_withdraw_airdrop_unclaimed() {
        let (test_data, mut deps) = init_helper_with_airdrop(5000);
        let test_data: Encoded = from_slice(test_data.as_slice()).unwrap();
        let mut env = mock_env();
        let info = mock_info("admin", &[]);
        let withdraw_to = Addr::unchecked("francisco".to_string());

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: Duration::Time(1001).after(&env.block),
            start: Duration::Time(100).after(&env.block),
            total_amount: Uint128::new(5000),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let withdraw_unclaimed_msg = ExecuteMsg::WithdrawUnclaimed {
            stage: 1u8,
            address: withdraw_to.to_string(),
        };

        // Can't withdraw not started stage
        let handle_result = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            withdraw_unclaimed_msg.clone(),
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Airdrop has not started"));

        // wait for airdrop to start
        env.block.time = env.block.time.plus_seconds(101);

        // Can't withdraw not expired stage
        let handle_result = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            withdraw_unclaimed_msg.clone(),
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Airdrop has not expired"));

        // wait for airdrop expiration height - 1
        env.block.time = env.block.time.plus_seconds(899);

        // Can't withdraw not expired stage
        let handle_result = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            withdraw_unclaimed_msg.clone(),
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Airdrop has not expired"));

        // one user claim it's share
        let claim_msg = ExecuteMsg::ClaimAirdrop {
            stage: 1u8,
            amount: test_data.amount,
            proof: test_data.proofs,
        };
        let user = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), user.clone(), claim_msg).unwrap();
        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::Claim {
                status: Success,
                amount: test_data.amount.u128()
            })
            .unwrap(),
        );

        // wait for airdrop expiration height
        env.block.time = env.block.time.plus_seconds(1);

        // Can withdraw expired stage
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            withdraw_unclaimed_msg.clone(),
        )
        .unwrap();
        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::WithdrawUnclaimed {
                amount: 4900u128,
                status: Success
            })
            .unwrap(),
        );

        // check balances
        let user_balance = BalancesStore::load(&deps.storage, &user.sender);
        let withdraw_to_balance = BalancesStore::load(&deps.storage, &withdraw_to);
        let contract_balance = BalancesStore::load(
            &deps.storage,
            &Addr::unchecked("cosmos2contract".to_string()),
        );
        assert_eq!(100u128, user_balance);
        assert_eq!(4900u128, withdraw_to_balance);
        assert_eq!(0, contract_balance);
    }

    #[test]
    fn test_is_airdrop_claimed() {
        let (test_data, mut deps) = init_helper_with_airdrop(15000);
        let test_data: Encoded = from_slice(test_data.as_slice()).unwrap();
        let env = mock_env();
        let info = mock_info("admin", &[]);
        let expiration = Duration::Time(1000).after(&env.block);
        let start = Duration::Time(100).after(&env.block);

        let merkle: StdResult<ExecuteMsg> = from_binary(&Binary::from(
            r#"{"register_merkle_root": {"merkle_root": "d1979d149b036f112d41c818f1d74dc52905b22bcb6e18466fb61154ee6b6001", "expiration": {"at_time":"1665927597000000000"}, "start": {"at_time":"1664727597000000000"}, "total_amount": "21220"}}"#.as_bytes(),
        ));

        match merkle.unwrap() {
            ExecuteMsg::RegisterMerkleRoot {
                merkle_root,
                expiration,
                start,
                total_amount,
            } => {
                assert_eq!(
                    "d1979d149b036f112d41c818f1d74dc52905b22bcb6e18466fb61154ee6b6001",
                    merkle_root
                );
                assert_eq!(
                    Expiration::AtTime(Timestamp::from_seconds(1665927597)).as_seconds(),
                    expiration.as_seconds()
                );
                assert_eq!(
                    Expiration::AtTime(Timestamp::from_seconds(1664727597)).as_seconds(),
                    start.as_seconds()
                );
                assert_eq!(21220u128, total_amount.u128());
            }
            _ => {
                panic!("Can deserialize")
            }
        }

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration,
            start,
            total_amount: Uint128::new(15000),
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // create viewing key
        let handle_msg = ExecuteMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let info = mock_info("wasm1k9hwzxs889jpvd7env8z49gad3a3633vg350tq", &[]);
        let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let query_is_claim_msg = QueryMsg::IsAirdropClaimed {
            key: key.0,
            address: info.clone().sender,
            stage: 1,
        };
        let query_response = query(deps.as_ref(), mock_env(), query_is_claim_msg.clone()).unwrap();
        let (claimed, amount, exp, start_exp) = match from_binary(&query_response).unwrap() {
            QueryAnswer::AirdropClaimed {
                claimed,
                amount,
                expiration,
                start,
            } => (claimed, amount, expiration, start),
            _ => panic!("Unexpected result from claim query"),
        };
        assert_eq!(false, claimed);
        assert_eq!(0, amount);
        assert_eq!(expiration.as_seconds(), exp.as_seconds());
        assert_eq!(start.as_seconds(), start_exp.as_seconds());

        // claim it
        // wait for airdrop start height
        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(101);

        let msg = ExecuteMsg::ClaimAirdrop {
            stage: 1u8,
            amount: test_data.amount,
            proof: test_data.proofs,
        };

        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::Claim {
                status: Success,
                amount: test_data.amount.u128()
            })
            .unwrap(),
        );

        // recheck is_claimed
        let query_response = query(deps.as_ref(), env, query_is_claim_msg).unwrap();
        let (claimed, amount, exp, start_exp) = match from_binary(&query_response).unwrap() {
            QueryAnswer::AirdropClaimed {
                claimed,
                amount,
                expiration,
                start,
            } => (claimed, amount, expiration, start),
            _ => panic!("Unexpected result from claim query"),
        };
        assert_eq!(true, claimed);
        assert_eq!(test_data.amount.u128(), amount);
        assert_eq!(expiration.as_seconds(), exp.as_seconds());
        assert_eq!(start.as_seconds(), start_exp.as_seconds());
    }

    #[test]
    fn test_replace_merkle_root() {
        let (test_data, mut deps) = init_helper_with_airdrop(15000);
        let test_data: Encoded = from_slice(test_data.as_slice()).unwrap();
        let env = mock_env();
        let info = mock_info("admin", &[]);

        let expiration = Duration::Time(100).after(&env.block);
        let start = Duration::Time(10).after(&env.block);

        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root.clone(),
            expiration,
            start,
            total_amount: Uint128::new(1500),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        let unwrapped_result: ExecuteAnswer = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::RegisterMerkleRoot {
                stage: 1,
                expiration,
                start,
                merkle_root: test_data.root.clone(),
                airdrop_source_wallet: "airdrop_source_wallet".to_string()
            })
            .unwrap(),
        );

        // replace root
        let expiration = Duration::Time(222).after(&env.block);
        let start = Duration::Time(111).after(&env.block);

        let msg = ExecuteMsg::ReplaceMerkleRoot {
            merkle_root: test_data.root.clone(),
            expiration,
            start,
            total_amount: Uint128::new(15000),
            stage: 1u8,
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let (stage, exp, st, root, airdrop_source_wallet) =
            match from_binary(&res.data.unwrap()).unwrap() {
                ExecuteAnswer::RegisterMerkleRoot {
                    stage,
                    expiration,
                    start,
                    merkle_root,
                    airdrop_source_wallet,
                } => (stage, expiration, start, merkle_root, airdrop_source_wallet),
                _ => panic!("Unexpected result from handle"),
            };

        assert_eq!(1, stage);
        assert_eq!(expiration, exp);
        assert_eq!(start, st);
        assert_eq!(test_data.root, root);
        assert_eq!("airdrop_source_wallet", airdrop_source_wallet);
    }

    #[test]
    #[ignore]
    fn test_get_all_token_balances() {
        let init_balances = vec![
            WalletBalances {
                address: "michael".to_string(),
                unstaked: 5000u128,
                staked: 15000u128,
            },
            WalletBalances {
                address: "josé".to_string(),
                unstaked: 2345u128,
                staked: 5432u128,
            },
            WalletBalances {
                address: "jean-pierre".to_string(),
                unstaked: 1111u128,
                staked: 1111u128,
            },
            WalletBalances {
                address: "raoul".to_string(),
                unstaked: 3333u128,
                staked: 4444u128,
            },
            WalletBalances {
                address: "antonio".to_string(),
                unstaked: 5555u128,
                staked: 6666u128,
            },
        ];
        let (init_result, mut deps) = init_helper(init_balances.clone());
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::GetAll {};

        // when not admin
        let info = mock_info("michael", &[]);
        let query_result = execute(deps.as_mut(), mock_env(), info, execute_msg.clone());
        let error = extract_error_msg(query_result);
        assert!(error.contains(
            "This is an admin command. Admin commands can only be run from readonly admin address"
        ));

        // when admin
        let info = mock_info("admin_readonly", &[]);
        let res = execute(deps.as_mut(), mock_env(), info, execute_msg).unwrap();
        let result = match from_binary(&res.data.unwrap()).unwrap() {
            ExecuteAnswer::GetAll { result } => (result),
            _ => panic!("Unexpected result from handle"),
        };

        assert_eq!(init_balances, result);
    }
}
