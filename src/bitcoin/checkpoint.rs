use super::{
    adapter::Adapter,
    header_queue::HeaderQueue,
    signatory::SignatorySet,
    threshold_sig::{LengthVec, Pubkey, Signature, ThresholdSig},
    ConsensusKey, Xpub,
};
use crate::error::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use derive_more::{Deref, DerefMut};
use orga::{
    call::Call,
    client::Client,
    coins::Address,
    collections::{ChildMut, Deque, Map, Ref},
    context::GetContext,
    encoding::{Decode, Encode},
    plugins::{Signer, Time},
    query::Query,
    state::State,
    Error as OrgaError, Result as OrgaResult,
};

pub const CHECKPOINT_INTERVAL: u64 = 60 * 10;
pub const MAX_INPUTS: u64 = 50;
pub const MAX_OUTPUTS: u64 = 200;

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

    fn create(_: orga::store::Store, data: Self) -> OrgaResult<Self> {
        Ok(data)
    }

    fn flush(self) -> OrgaResult<Self> {
        Ok(self)
    }
}

impl Query for CheckpointStatus {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

impl Call for CheckpointStatus {
    type Call = ();

    fn call(&mut self, _: ()) -> OrgaResult<()> {
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
    pub sigset_index: u32,
    pub dest: Address,
    pub amount: u64,
    pub sigs: ThresholdSig,
}

pub type Output = Adapter<bitcoin::TxOut>;

#[derive(State, Call, Query, Client)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub inputs: Deque<Input>,
    signed_inputs: u16,
    pub outputs: Deque<Output>,
    pub sigset: SignatorySet,
}

impl Checkpoint {
    pub fn create_time(&self) -> u64 {
        self.sigset.create_time()
    }
}

#[derive(State, Call, Query, Client)]
pub struct CheckpointQueue {
    queue: Deque<Checkpoint>,
    index: u32,
}

#[derive(Deref)]
pub struct CompletedCheckpoint<'a>(Ref<'a, Checkpoint>);

#[derive(Deref)]
pub struct SigningCheckpoint<'a>(Ref<'a, Checkpoint>);

impl<'a, U: Clone> Client<U> for SigningCheckpoint<'a> {
    type Client = ();

    fn create_client(_: U) {}
}

impl<'a> Query for SigningCheckpoint<'a> {
    type Query = ();

    fn query(&self, _: ()) -> OrgaResult<()> {
        Ok(())
    }
}

#[derive(Deref, DerefMut)]
pub struct SigningCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl<'a> SigningCheckpointMut<'a> {
    pub fn done(&self) -> bool {
        self.signed_inputs as u64 == self.inputs.len()
    }

    pub fn advance(self) -> Result<()> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Complete;

        Ok(())
    }
}

#[derive(Deref)]
pub struct BuildingCheckpoint<'a>(Ref<'a, Checkpoint>);

#[derive(Deref, DerefMut)]
pub struct BuildingCheckpointMut<'a>(ChildMut<'a, u64, Checkpoint>);

impl<'a> BuildingCheckpointMut<'a> {
    pub fn push_input(
        &mut self,
        txid: Txid,
        vout: u32,
        sigset: &SignatorySet,
        dest: Address,
        amount: u64,
    ) -> Result<()> {
        // TODO: need a better way to initialize state types from values?
        self.inputs.push_back((
            Adapter::new(txid),
            vout,
            sigset.index(),
            dest.into(),
            amount,
            <ThresholdSig as State>::Encoding::default(),
        ))?;

        // TODO: populate thresholdsig state

        Ok(())
    }

    pub fn advance(self) -> Result<(SigningCheckpointMut<'a>, Vec<Input>, Vec<Output>)> {
        let mut checkpoint = self.0;

        checkpoint.status = CheckpointStatus::Signing;

        let mut child_inputs = vec![];
        let mut child_outputs = vec![];

        let reserve_out = bitcoin::TxOut {
            value: 0, // will be updated after counting inputs and fees
            script_pubkey: checkpoint.sigset.output_script(Address::NULL)?,
        };
        checkpoint.outputs.push_front(Adapter::new(reserve_out))?;

        // TODO: move excess inputs/outputs to child
        // TODO: set reserve based on inputs/outputs
        // TODO: estimate size, deduct estimated fee from reserve
        // TODO: populate signing messages (sighash for each input)

        // child_inputs.push(Input {
        //     amount: ,
        //     dest: Address::NULL,
        //     sigset_index: checkpoint.sigset.index(),
        //     txid: ,
        //     vout: ,
        // });

        Ok((
            SigningCheckpointMut(checkpoint),
            child_inputs,
            child_outputs,
        ))
    }
}

impl CheckpointQueue {
    #[query]
    pub fn get(&self, index: u32) -> Result<Ref<'_, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get(index as u64)?.unwrap())
    }

    pub fn get_mut(&mut self, index: u32) -> Result<ChildMut<'_, u64, Checkpoint>> {
        let index = self.get_deque_index(index)?;
        Ok(self.queue.get_mut(index as u64)?.unwrap())
    }

    fn get_deque_index(&self, index: u32) -> Result<u32> {
        let start = self.index + 1 - (self.queue.len() as u32);
        if index > self.index || index < start {
            Err(OrgaError::App("Index out of bounds".to_string()).into())
        } else {
            Ok(index - start)
        }
    }

    #[query]
    pub fn index(&self) -> u32 {
        self.index
    }

    #[query]
    pub fn all(&self) -> Result<Vec<(u32, Ref<'_, Checkpoint>)>> {
        // TODO: return iterator
        // TODO: use Deque iterator

        let mut out = Vec::with_capacity(self.queue.len() as usize);

        for i in 0..self.queue.len() {
            let index = self.index - (i as u32);
            let checkpoint = self.queue.get(index as u64)?.unwrap();
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

    pub fn maybe_step(&mut self, sig_keys: &Map<ConsensusKey, Xpub>) -> Result<()> {
        #[cfg(feature = "full")]
        {
            if self.signing()?.is_some() {
                return Ok(());
            }

            if !self.queue.is_empty() {
                let now = self
                    .context::<Time>()
                    .ok_or_else(|| OrgaError::App("No time context".to_string()))?
                    .seconds as u64;
                let elapsed = now - self.building()?.create_time();
                if elapsed < CHECKPOINT_INTERVAL {
                    return Ok(());
                }
            }

            if self.maybe_push(sig_keys)?.is_none() {
                return Ok(());
            }

            if self.index > 0 {
                let second = self.get_mut(self.index - 1)?;
                BuildingCheckpointMut(second).advance()?;
            }
        }

        Ok(())
    }

    fn maybe_push(
        &mut self,
        sig_keys: &Map<ConsensusKey, Xpub>,
    ) -> Result<Option<BuildingCheckpointMut>> {
        #[cfg(not(feature = "full"))]
        unimplemented!();

        #[cfg(feature = "full")]
        {
            let sigset = SignatorySet::from_validator_ctx(self.index, sig_keys)?;

            if sigset.possible_vp() == 0 {
                return Ok(None);
            }

            if !sigset.has_quorum() {
                return Ok(None);
            }

            if !self.queue.is_empty() {
                self.index += 1;
            }

            self.queue.push_back(Default::default())?;
            let mut building = self.building_mut()?;

            building.sigset = sigset;

            Ok(Some(building))
        }
    }

    #[call]
    pub fn sign(&mut self, pubkey: Pubkey, sigs: LengthVec<u16, Signature>) -> Result<()> {
        let mut signing = self
            .signing_mut()?
            .ok_or_else(|| Error::Orga(OrgaError::App("No checkpoint to be signed".to_string())))?;

        let mut sig_index = 0;
        for i in 0..signing.inputs.len() {
            let mut input = signing.inputs.get_mut(i)?.unwrap();

            if !input.sigs.contains_key(pubkey)? {
                continue;
            }

            if input.sigs.done() {
                sig_index += 1;
                continue;
            }

            if sig_index > sigs.len() {
                return Err(OrgaError::App("Not enough signatures supplied".to_string()).into());
            }

            let sig = sigs[sig_index];
            sig_index += 1;

            input.sigs.sign(pubkey, sig)?;

            if input.sigs.done() {
                signing.signed_inputs += 1;
            }
        }

        if sig_index != sigs.len() {
            return Err(OrgaError::App("Excess signatures supplied".to_string()).into());
        }

        if signing.done() {
            signing.advance()?;
        }

        Ok(())
    }

    #[query]
    pub fn active_sigset(&self) -> Result<SignatorySet> {
        Ok(self.building()?.sigset.clone())
    }

    pub fn sigset(&self, index: u32) -> Result<SignatorySet> {
        Ok(self.get(index)?.sigset.clone())
    }
}
