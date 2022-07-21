// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use sui_core::{
    authority_aggregator::AuthorityAggregator, authority_client::NetworkAuthorityClient,
};
use sui_types::{
    base_types::{ObjectID, ObjectRef},
    crypto::EmptySignInfo,
    messages::{TransactionEffects, TransactionEnvelope},
    object::{Object, ObjectRead, Owner},
};

use futures::FutureExt;
use sui_quorum_driver::QuorumDriverHandler;
use sui_types::{
    base_types::SuiAddress,
    crypto::{KeyPair},
    messages::{
        ExecuteTransactionRequest, ExecuteTransactionRequestType, ExecuteTransactionResponse,
        Transaction,
    },
};

use test_utils::messages::make_transfer_sui_transaction;
use tracing::log::error;

pub const MAX_GAS_TO_TRANSFER: u64 = 1_000_000_000;

pub type Gas = (ObjectRef, Owner);

pub trait Payload: Send + Sync {
    fn make_new_payload(&self, new_object: ObjectRef, new_gas: ObjectRef) -> Box<dyn Payload>;
    fn make_transaction(&self) -> TransactionEnvelope<EmptySignInfo>;
    fn get_object_id(&self) -> ObjectID;
}

pub type UpdatedAndNewlyMinted = (ObjectRef, ObjectRef);

pub async fn transfer_sui_for_testing(
    gas: Gas,
    keypair: &KeyPair,
    value: u64,
    address: SuiAddress,
    client: &AuthorityAggregator<NetworkAuthorityClient>,
) -> Option<UpdatedAndNewlyMinted> {
    let tx = make_transfer_sui_transaction(gas.0, address, Some(value), gas.1.get_owner_address().unwrap(), keypair);
    let quorum_driver_handler = QuorumDriverHandler::new(client.clone());
    let qd = quorum_driver_handler.clone_quorum_driver();
    let new_object = qd
        .execute_transaction(ExecuteTransactionRequest {
            transaction: tx.clone(),
            request_type: ExecuteTransactionRequestType::WaitForEffectsCert,
        })
        .map(move |res| match res {
            Ok(ExecuteTransactionResponse::EffectsCert(result)) => {
                let (_, effects) = *result;
                let minted = effects.effects.created.get(0).unwrap().0;
                let updated = effects
                    .effects
                    .mutated
                    .iter()
                    .find(|(k, _)| k.0 == gas.0 .0)
                    .unwrap()
                    .0;
                Some((updated, minted))
            }
            Ok(resp) => {
                error!("unexpected_response: {:?}", resp);
                None
            }
            Err(err) => {
                error!("unexpected_response: {:?}", err);
                None
            }
        })
        .await;
    new_object
}

pub async fn get_latest(
    object_id: ObjectID,
    aggregator: &AuthorityAggregator<NetworkAuthorityClient>,
) -> Object {
    // Read latest test gas object
    match aggregator.get_object_info_execute(object_id).await.unwrap() {
        ObjectRead::Exists(_, object, _) => Some(object),
        _ => None,
    }
    .unwrap()
}

pub async fn submit_transaction(
    transaction: Transaction,
    aggregator: &AuthorityAggregator<NetworkAuthorityClient>,
) -> Option<TransactionEffects> {
    let qd = QuorumDriverHandler::new(aggregator.clone());
    if let ExecuteTransactionResponse::EffectsCert(result) = qd
        .clone_quorum_driver()
        .execute_transaction(ExecuteTransactionRequest {
            transaction,
            request_type: ExecuteTransactionRequestType::WaitForEffectsCert,
        })
        .await
        .unwrap()
    {
        let (_, effects) = *result;
        Some(effects.effects)
    } else {
        None
    }
}

#[async_trait]
pub trait StressTestCtx<T: Payload + ?Sized>: Send + Sync {
    async fn make_test_payloads(
        &self,
        client: &AuthorityAggregator<NetworkAuthorityClient>,
    ) -> Vec<Box<T>>;
}