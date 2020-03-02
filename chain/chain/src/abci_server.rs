//!  Start the peg abci server.

use crate::state_machine::{initialize, run};
use crate::Action;
use abci2::messages::abci::*;
use failure::bail;
use merk::Merk;
use nomic_primitives::transaction::Transaction;
use orga::abci::{ABCIStateMachine, Application};
use orga::Result as OrgaResult;
use orga::{merkstore::MerkStore, Store};
use std::collections::BTreeMap;
use std::path::Path;

struct App;

impl Application for App {
    fn init_chain(
        &self,
        store: &mut dyn Store,
        req: RequestInitChain,
    ) -> OrgaResult<ResponseInitChain> {
        let mut validators = BTreeMap::<Vec<u8>, u64>::new();
        for validator in req.get_validators() {
            let pub_key = validator.get_pub_key().get_data().to_vec();
            let power = validator.get_power() as u64;
            validators.insert(pub_key, power);
        }

        write_validators(store, validators);
        initialize(store);

        Ok(ResponseInitChain::new())
    }

    fn check_tx(&self, store: &mut dyn Store, req: RequestCheckTx) -> OrgaResult<ResponseCheckTx> {
        let tx = serde_json::from_slice::<Transaction>(req.get_tx());
        let mut validators = read_validators(store);

        match tx {
            Ok(tx) => match run(store, Action::Transaction(tx), &mut validators) {
                Ok(execution_result) => {
                    // TODO: Don't write validators back to store if they haven't changed
                    write_validators(store, validators);
                    Ok(Default::default())
                }

                Err(e) => bail!("error executing tx (check_tx)"),
            },

            Err(e) => bail!("error deserializing tx (check_tx)"),
        }
    }

    fn deliver_tx(
        &self,
        store: &mut dyn Store,
        req: RequestDeliverTx,
    ) -> OrgaResult<ResponseDeliverTx> {
        let tx = serde_json::from_slice::<Transaction>(req.get_tx());
        let mut validators = read_validators(store);
        match tx {
            Ok(tx) => match run(store, Action::Transaction(tx), &mut validators) {
                Ok(execution_result) => {
                    write_validators(store, validators);
                    Ok(Default::default())
                }

                Err(e) => bail!("error executing tx (deliver_tx)"),
            },
            Err(e) => bail!("error deserializing tx (deliver_tx)"),
        }
    }

    fn end_block(
        &self,
        store: &mut dyn Store,
        req: RequestEndBlock,
    ) -> OrgaResult<ResponseEndBlock> {
        let validators = read_validators(store);
        let mut validator_updates: Vec<ValidatorUpdate> = Vec::new();
        for (pub_key_bytes, power) in validators {
            let mut validator_update = ValidatorUpdate::new();
            let mut pub_key = PubKey::new();
            pub_key.set_data(pub_key_bytes);
            pub_key.set_field_type(String::from("ed25519"));
            validator_update.set_pub_key(pub_key);
            validator_update.set_power(power as i64);
            validator_updates.push(validator_update);
        }

        let mut response = ResponseEndBlock::new();

        response.set_validator_updates(validator_updates.into());
        Ok(response)
    }
}

fn write_validators(store: &mut dyn Store, validators: BTreeMap<Vec<u8>, u64>) {
    let validator_map_bytes =
        bincode::serialize(&validators).expect("Failed to serialize validator map");
    store.put(b"validators".to_vec(), validator_map_bytes);
}
fn read_validators(store: &mut dyn Store) -> BTreeMap<Vec<u8>, u64> {
    let validator_map_bytes = store
        .get(b"validators")
        .expect("Failed to read validator map bytes from store")
        .expect("Validator map was not written to store");
    let validators: Result<BTreeMap<Vec<u8>, u64>, bincode::Error> =
        bincode::deserialize(&validator_map_bytes);
    validators.expect("Failed to deserialize validator map")
}

pub fn start<P: AsRef<Path>>(nomic_home: P) {
    let merk_path = nomic_home.as_ref().join("merk.db");
    let mut merk = Merk::open(merk_path).expect("Failed to open Merk database");
    let store = MerkStore::new(&mut merk);
    ABCIStateMachine::new(App, store)
        .listen("127.0.0.1:26658")
        .unwrap();
}
