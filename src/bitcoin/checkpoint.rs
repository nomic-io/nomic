use orga::{
    state::State,
    encoding::{Encode, Decode},
    call::Call,
    query::Query,
    client::Client,
    Result,
    Error,
    collections::{Deque, Ref, ChildMut},
};
use super::{
    adapter::Adapter,
    threshold_sig::{ThresholdSig, Pubkey, Signature},
    signatory::SignatorySet,
    header_queue::HeaderQueue,
};
use bitcoin::hashes::Hash;
use bitcoin::Txid;

#[derive(Debug, Encode, Decode)]
pub enum CheckpointStatus {
    Building,
    Signing,
    Complete,
}

impl Default for CheckpointStatus {
    fn default() -> Self {
        Self::Building
    }
}

// TODO: make it easy to derive State for simple types like this
impl State for CheckpointStatus {
    type Encoding = Self;

    fn create(_: orga::store::Store, data: Self) -> Result<Self> {
        Ok(data)
    }

    fn flush(self) -> Result<Self> {
        Ok(self)
    }
}

impl Query for CheckpointStatus {
    type Query = ();

    fn query(&self, _: ()) -> Result<()> {
        Ok(())
    }
}

impl Call for CheckpointStatus {
    type Call = ();

    fn call(&mut self, _: ()) -> Result<()> {
        Ok(())
    }
}

impl<U: Send + Clone> Client<U> for CheckpointStatus {
    type Client = orga::client::PrimitiveClient<Self, U>;

    fn create_client(parent: U) -> Self::Client {
        orga::client::PrimitiveClient::new(parent)
    }
}

#[derive(State, Call, Query, Client)]
pub struct Input {
    pub txid: Adapter<Txid>,
    pub vout: u32,
    pub script_pubkey: (), // TODO
    pub sig: ThresholdSig,
}

#[derive(State, Call, Query, Client)]
pub struct Output {
    pub amount: u64,
    pub script: Vec<u8>,
}

#[derive(State, Call, Query, Client)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub inputs: Deque<Input>,
    pub outputs: Deque<Output>,
    sig: ThresholdSig,
    pub sig_set: SignatorySet,
}

#[derive(State, Call, Query, Client)]
pub struct CheckpointQueue {
    queue: Deque<Checkpoint>,
    index: u64,
}

pub struct CompletedCheckpoint<'a>(Ref<'a, Checkpoint>);
pub struct SigningCheckpoint<'a>(Ref<'a, Checkpoint>);

impl<'a, U: Clone> Client<U> for SigningCheckpoint<'a> {
    type Client = ();

    fn create_client(_: U) {}
}

impl<'a> Query for SigningCheckpoint<'a> {
    type Query = ();

    fn query(&self, _: ()) -> Result<()> { Ok(()) }
}

pub struct SigningCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);
pub struct BuildingCheckpoint<'a>(Ref<'a, Checkpoint>);
pub struct BuildingCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl CheckpointQueue {
    pub fn get(&self, index: u64) -> Result<Ref<'_, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get(index)?.unwrap())
    }

    pub fn get_mut(&mut self, index: u64) -> Result<ChildMut<'_, u64, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get_mut(index)?.unwrap())
    }

    fn get_deque_index(&self, index: u64) -> Result<u64> {
        let start = self.index + 1 - self.queue.len();
        if index > self.index || index < start {
            Err(Error::App("Index out of bounds".to_string()))
        } else {
            Ok(index - start)
        }
    }

    #[query]
    pub fn index(&self) -> u64 {
        self.index
    }

    #[query]
    pub fn all(&self) -> Result<Vec<(u64, Ref<'_, Checkpoint>)>> {
        // TODO: return iterator
        // TODO: use Deque iterator

        let mut out = Vec::with_capacity(self.queue.len() as usize);

        for i in 0..self.queue.len() {
            let index = self.index - i;
            let checkpoint = self.queue.get(index)?.unwrap();
            out.push((index, checkpoint));
        }

        Ok(out)
    }

    #[query]
    pub fn completed(&self) -> Result<Vec<CompletedCheckpoint<'_>>> {
        // TODO: return iterator
        // TODO: use Deque iterator
        
        let mut out = vec![];

        for i in 0..self.queue.len() {
            let checkpoint = self.queue.get(i)?.unwrap();

            if !matches!(checkpoint.status, CheckpointStatus::Complete) {
                break;
            }

            out.push(CompletedCheckpoint(checkpoint));
        }

        Ok(out)
    }

    #[query]
    pub fn signing(&self) -> Result<Option<SigningCheckpoint<'_>>> {
        if self.queue.len() < 2 {
            return Ok(None);
        }

        let second = self.get(self.index - 1)?;
        if !matches!(second.status, CheckpointStatus::Signing) {
            return Ok(None);
        }

        Ok(Some(SigningCheckpoint(second)))
    }

    pub fn signing_mut(&mut self) -> Result<Option<SigningCheckpointMut>> {
        if self.queue.len() < 2 {
            return Ok(None);
        }

        let second = self.get_mut(self.index - 1)?;
        if !matches!(second.status, CheckpointStatus::Signing) {
            return Ok(None);
        }

        Ok(Some(SigningCheckpointMut(second)))
    }

    pub fn building(&self) -> Result<BuildingCheckpoint> {
        let last = self.get(self.index)?;
        Ok(BuildingCheckpoint(last))
    }

    pub fn building_mut(&mut self) -> Result<BuildingCheckpointMut> {
        let last = self.get_mut(self.index)?;
        Ok(BuildingCheckpointMut(last))
    }

    pub fn start_signing(&mut self) -> Result<()> {
        if self.signing()?.is_some() {
            return Err(Error::App("Previous checkpoint is still being signed".to_string()));
        }

        let mut building = self.building_mut()?;
        building.0.status = CheckpointStatus::Signing;

        self.push_building()
    }

    pub fn push_building(&mut self) -> Result<()> {
        let index = self.index;
        if !self.queue.is_empty() {
            self.index += 1;
        }

        self.queue.push_back(Default::default())?;
        let mut building = self.building_mut()?;

        building.0.sig_set = SignatorySet::from_validator_ctx(index)?;

        Ok(())
    }

    // #[call]
    // TODO: should have N signatures (1 per spent input of checkpoint)
    pub fn sign_checkpoint(&mut self, pubkey: Pubkey, sig: Signature) -> Result<()> {
        let mut signing = self.signing_mut()?
            .ok_or_else(|| Error::App("No checkpoint to be signed".to_string()))?;

        signing.0.sig.sign(pubkey, sig)?;

        if signing.0.sig.done() {
            // TODO: move this block into its own method
            
            signing.0.status = CheckpointStatus::Complete;
            // let reserve_out = signing.0.reserve_output()?;
            
            let mut building = self.building_mut()?;
            building.0.inputs.push_back(Default::default())?;
            let mut reserve_in = building.0.inputs.get_mut(0)?.unwrap();

            // reserve_in.txid = reserve_out.txid;
            reserve_in.vout = 0;
            // TODO: reserve_in.script_pubkey = InputType::Reserve;
            // TODO: reserve_in.sig.set_up(sig_set)?;
        }

        Ok(())
    }

    #[query]
    pub fn active_sigset(&self) -> Result<SignatorySet> {
        Ok(self.building()?.0.sig_set.clone())
    }
}
