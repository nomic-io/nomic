//!  Start the peg abci server.

use abci2::messages::abci::*;
use error_chain::bail;
use merk::Merk;
use nomic_chain::state_machine::{initialize, run};
use nomic_chain::Action;
use nomic_primitives::transaction::Transaction;
use orga::abci::{ABCIStateMachine, Application};
use orga::Result as OrgaResult;
use orga::{MapStore, Store};

struct App;

impl Application for App {
    fn init_chain(
        &self,
        store: &mut dyn Store,
        req: RequestInitChain,
    ) -> OrgaResult<ResponseInitChain> {
        println!("init chain: {:?}", req);
        initialize(store);

        Ok(ResponseInitChain::new())
    }

    fn check_tx(&self, store: &mut dyn Store, req: RequestCheckTx) -> OrgaResult<ResponseCheckTx> {
        let tx = serde_json::from_slice::<Transaction>(req.get_tx());

        match tx {
            Ok(tx) => match run(store, Action::Transaction(tx)) {
                Ok(execution_result) => Ok(Default::default()),

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

        match tx {
            Ok(tx) => match run(store, Action::Transaction(tx)) {
                Ok(execution_result) => Ok(Default::default()),

                Err(e) => bail!("error executing tx (deliver_tx)"),
            },
            Err(e) => bail!("error deserializing tx (deliver_tx)"),
        }
    }
}

pub fn main() {
    let store = MapStore::new();
    ABCIStateMachine::new(App, store, 0)
        .listen("127.0.0.1:26658")
        .unwrap();
}
