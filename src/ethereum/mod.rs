use alloy_core::{
    primitives::keccak256,
    sol_types::{sol, SolValue},
};
use bitcoin::secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use bitcoin::Script;
use orga::encoding::LengthString;
use orga::query::MethodQuery;
use std::collections::BTreeSet;
use std::u64;

use ed::{Decode, Encode};
use orga::{
    coins::{Address, Coin, Give, Take},
    collections::{ChildMut, Deque, Map, Ref},
    describe::Describe,
    encoding::LengthVec,
    migrate::Migrate,
    orga,
    query::FieldQuery,
    state::State,
    store::Store,
    Error,
};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

use crate::app::Identity;
use crate::bitcoin::signatory::derive_pubkey;
use crate::bitcoin::{Adapter, Xpub};
use crate::{
    app::Dest,
    bitcoin::{
        exempt_from_fee,
        signatory::SignatorySet,
        threshold_sig::{Pubkey, Signature, ThresholdSig},
        Nbtc,
    },
    error::Result,
};

#[cfg(feature = "ethereum-full")]
sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    bridge_contract,
    "src/ethereum/contracts/Nomic.json",
);
#[cfg(feature = "ethereum-full")]
use bridge_contract::{LogicCallArgs, ValsetArgs};

#[cfg(feature = "ethereum-full")]
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    babylon_contract,
    "src/ethereum/contracts/Babylon.json",
);

// TODO: message ttl/pruning
// TODO: multi-token support
// TODO: call fees
// TODO: bounceback on failed transfers
// TODO: fallback to address on failed contract calls

pub mod consensus;
#[cfg(feature = "full")]
pub mod signer;

pub const VALSET_INTERVAL: u64 = 60 * 60 * 24;
/// Gas price in microsats.
pub const GAS_PRICE: u64 = 160_000;
pub const APPROX_TRANSFER_GAS: u64 = 80_000;
pub const APPROX_CALL_GAS: u64 = 100_000;

pub const WHITELISTED_RELAYER_ADDR: &str = "nomic124j0ky0luh9jzqh9w2dk77cze9v0ckdupk50ny";

#[orga]
pub struct Ethereum {
    pub networks: Map<u32, Network>,
}

#[orga]
impl Ethereum {
    pub fn step(&mut self, active_sigset: &SignatorySet) -> Result<()> {
        let ids: Vec<_> = self
            .networks
            .iter()?
            .map(|e| Ok(*e?.0))
            .collect::<Result<_>>()?;
        for id in ids {
            let mut net = self.networks.get_mut(id)?.unwrap();
            net.step(active_sigset)?;
        }

        Ok(())
    }

    pub fn take_pending(&mut self) -> Result<Vec<(Dest, Coin<Nbtc>, Identity)>> {
        let ids: Vec<_> = self
            .networks
            .iter()?
            .map(|e| Ok(*e?.0))
            .collect::<Result<_>>()?;
        let mut pending = vec![];
        for id in ids {
            let mut net = self.networks.get_mut(id)?.unwrap();
            pending.extend(net.take_pending()?);
        }
        Ok(pending)
    }

    #[call]
    pub fn relay_return(
        &mut self,
        network: u32,
        connection: Address,
        consensus_proof: (),
        account_proof: (),
        // TODO: storage_proofs: LengthVec<u16, (LengthVec<u8, u8>, u64)>,
        returns: LengthVec<u16, (u64, LengthString<u16>, u64, [u8; 20])>, /* TODO: don't include
                                                                           * data, just
                                                                           * state proof */
    ) -> Result<()> {
        exempt_from_fee()?;

        let mut net = self
            .networks
            .get_mut(network)?
            .ok_or_else(|| Error::App("network not found".to_string()))?;
        let mut conn = net
            .connections
            .get_mut(connection)?
            .ok_or_else(|| Error::App("connection not found".to_string()))?;

        conn.relay_return(network, consensus_proof, account_proof, returns)
    }

    #[call]
    pub fn sign(
        &mut self,
        network: u32,
        connection: Address,
        msg_index: u64,
        pubkey: Pubkey,
        sig: Signature,
    ) -> Result<()> {
        exempt_from_fee()?;

        let mut net = self
            .networks
            .get_mut(network)?
            .ok_or_else(|| Error::App("network not found".to_string()))?;
        let mut conn = net
            .connections
            .get_mut(connection)?
            .ok_or_else(|| Error::App("connection not found".to_string()))?;

        conn.sign(msg_index, pubkey, sig)
    }

    pub fn create_connection(
        &mut self,
        chain_id: u32,
        bridge_contract: Address,
        token_contract: Address,
        valset: SignatorySet,
    ) -> Result<()> {
        let mut network = self
            .networks
            .get_mut(chain_id)?
            .ok_or_else(|| Error::App(format!("Network with chain ID {} not found", chain_id)))?;

        if network.connections.contains_key(bridge_contract)? {
            return Err(Error::App(format!(
                "Connection with bridge contract address {} already exists",
                bridge_contract
            ))
            .into());
        }

        let connection = Connection::new(chain_id, bridge_contract, token_contract, valset);

        network.connections.insert(bridge_contract, connection)?;

        Ok(())
    }

    #[query]
    pub fn to_sign(&self, xpub: Xpub) -> Result<ToSign> {
        let mut to_sign = vec![];
        let secp = Secp256k1::new();

        for net in self.networks.iter()? {
            let (_, net) = net?;
            for conn in net.connections.iter()? {
                let (_, conn) = conn?;

                // skip invalid connections
                if conn.message_index != conn.outbox.len() {
                    continue;
                }

                for (msg_index, msg) in conn.outbox.iter()?.enumerate() {
                    let msg = msg?;
                    let msg_index = (msg_index + 1) as u64;

                    let pubkey = derive_pubkey(&secp, xpub, msg.sigset_index)?;
                    if conn.needs_sig(msg_index, pubkey.into())? {
                        to_sign.push((
                            net.id,
                            conn.bridge_contract,
                            msg_index,
                            msg.sigset_index,
                            msg.sigs.message,
                            msg.msg.clone(),
                        ));
                    }
                }
            }
        }

        Ok(to_sign)
    }

    pub fn network(&self, network: u32) -> Result<Ref<Network>> {
        Ok(self
            .networks
            .get(network)?
            .ok_or_else(|| Error::App("Unknown network".to_string()))?)
    }

    pub fn network_mut(&mut self, network: u32) -> Result<ChildMut<u32, Network>> {
        Ok(self
            .networks
            .get_mut(network)?
            .ok_or_else(|| Error::App("Unknown network".to_string()))?)
    }

    // TODO: we shouldn't need these:
    #[query]
    pub fn token_contract(&self, network: u32, connection: Address) -> Result<Address> {
        Ok(self
            .networks
            .get(network)?
            .unwrap()
            .connections
            .get(connection)?
            .unwrap()
            .token_contract)
    }
    #[query]
    pub fn message_index(&self, network: u32, connection: Address) -> Result<u64> {
        Ok(self
            .networks
            .get(network)?
            .unwrap()
            .connections
            .get(connection)?
            .unwrap()
            .message_index)
    }
    #[query]
    pub fn return_index(&self, network: u32, connection: Address) -> Result<u64> {
        Ok(self
            .networks
            .get(network)?
            .unwrap()
            .connections
            .get(connection)?
            .unwrap()
            .return_index)
    }
    #[query]
    pub fn signed(&self, network: u32, connection: Address, msg_index: u64) -> Result<bool> {
        Ok(self
            .networks
            .get(network)?
            .unwrap()
            .connections
            .get(connection)?
            .unwrap()
            .get(msg_index)?
            .sigs
            .signed())
    }
    #[query]
    pub fn msd(
        &self,
        network: u32,
        connection: Address,
        msg_index: u64,
    ) -> Result<([u8; 32], Sigs, OutMessageArgs)> {
        let net = self.networks.get(network)?.unwrap();
        let conn = net.connections.get(connection)?.unwrap();
        let msg = conn.get(msg_index)?;
        Ok((msg.sigs.message, conn.get_sigs(msg_index)?, msg.msg.clone()))
    }
}
type ToSign = Vec<(u32, Address, u64, u32, [u8; 32], OutMessageArgs)>;
type Sigs = Vec<(Pubkey, Option<Signature>)>;

#[orga]
pub struct Network {
    pub id: u32,
    pub connections: Map<Address, Connection>, // TODO: use an eth address type
}

#[orga]
impl Network {
    pub fn step(&mut self, active_sigset: &SignatorySet) -> Result<()> {
        let addrs: Vec<_> = self
            .connections
            .iter()?
            .map(|e| Ok(*e?.0))
            .collect::<Result<_>>()?;
        for addr in addrs {
            let mut conn = self.connections.get_mut(addr)?.unwrap();
            conn.step(active_sigset)?;
        }

        Ok(())
    }

    pub fn take_pending(&mut self) -> Result<Vec<(Dest, Coin<Nbtc>, Identity)>> {
        let addrs: Vec<_> = self
            .connections
            .iter()?
            .map(|e| Ok(*e?.0))
            .collect::<Result<_>>()?;
        let mut pending = vec![];
        for addr in addrs {
            let mut conn = self.connections.get_mut(addr)?.unwrap();
            pending.extend(conn.take_pending()?);
        }
        Ok(pending)
    }

    pub fn connection(&self, connection: Address) -> Result<Ref<Connection>> {
        Ok(self
            .connections
            .get(connection)?
            .ok_or_else(|| Error::App("Unknown connection".to_string()))?)
    }

    pub fn connection_mut(&mut self, connection: Address) -> Result<ChildMut<Address, Connection>> {
        Ok(self
            .connections
            .get_mut(connection)?
            .ok_or_else(|| Error::App("Unknown connection".to_string()))?)
    }
}

#[orga]
pub struct Connection {
    pub chain_id: u32,
    pub bridge_contract: Address,
    pub token_contract: Address,
    pub valset_interval: u64,

    pub message_index: u64,
    pub batch_index: u64,
    pub valset_index: u64,
    pub return_index: u64,

    pub emergency_disbursal_total: u64,
    pub emergency_disbursal_balances: Map<Adapter<Script>, u64>,

    pub outbox: Deque<OutMessage>,
    pub pending: Deque<(Dest, Coin<Nbtc>, Identity)>,
    pub coins: Coin<Nbtc>,
    pub valset: SignatorySet,
}

#[orga]
impl Connection {
    pub fn new(
        chain_id: u32,
        bridge_contract: Address,
        token_contract: Address,
        mut valset: SignatorySet,
    ) -> Self {
        valset.normalize_vp(u32::MAX as u64);
        Self {
            chain_id,
            bridge_contract,
            token_contract,
            outbox: Deque::new(),
            message_index: 1,
            batch_index: 0,
            valset_index: 0,
            return_index: 0,
            coins: Coin::default(),
            valset_interval: VALSET_INTERVAL,
            valset,
            pending: Deque::new(),
            emergency_disbursal_balances: Map::new(),
            emergency_disbursal_total: 0,
        }
    }

    // TODO: method to return pending nbtc transfers

    pub fn step(&mut self, active_sigset: &SignatorySet) -> Result<()> {
        if active_sigset.create_time - self.valset.create_time >= self.valset_interval
            && self.valset.index != active_sigset.index
        {
            self.update_valset(active_sigset.clone())?;
        }

        Ok(())
    }

    pub fn validate_transfer(&self, dest: Address, amount: u64) -> Result<()> {
        let fee_amount = APPROX_TRANSFER_GAS * GAS_PRICE;
        if amount < fee_amount {
            return Err(Error::App("Insufficient funds for fee".to_string()).into());
        }

        if dest == Address::NULL {
            return Err(Error::App("Invalid Ethereum address".to_string()).into());
        }

        Ok(())
    }

    pub fn transfer(&mut self, dest: Address, coins: Coin<Nbtc>) -> Result<()> {
        let amount: u64 = coins.amount.into();
        self.validate_transfer(dest, amount)?;

        let fee_amount = APPROX_TRANSFER_GAS * GAS_PRICE;
        let amount = amount - fee_amount;

        // TODO: batch transfers
        let transfer = Transfer {
            dest,
            amount,
            fee_amount,
        };
        let transfers = vec![transfer].try_into().unwrap();
        let timeout = u64::MAX; // TODO: set based on current ethereum height, or let user specify

        self.coins.give(coins)?;
        self.batch_index += 1;
        self.push_outbox(OutMessageArgs::Batch {
            transfers,
            timeout,
            batch_index: self.batch_index,
        })?;

        Ok(())
    }

    pub fn validate_contract_call(
        &self,
        max_gas: u64,
        fallback_address: Address,
        amount: u64,
    ) -> Result<()> {
        if fallback_address == Address::NULL {
            return Err(Error::App("Invalid Ethereum address".to_string()).into());
        }

        let fee_amount = (APPROX_CALL_GAS + max_gas) * GAS_PRICE;
        if amount < fee_amount {
            return Err(Error::App("Insufficient funds for fee".to_string()).into());
        }

        Ok(())
    }

    pub fn call_contract(
        &mut self,
        // TODO: ethaddress type
        contract_address: [u8; 20],
        data: LengthVec<u16, u8>,
        max_gas: u64,
        // TODO: ethaddress type
        fallback_address: [u8; 20],
        coins: Coin<Nbtc>,
    ) -> Result<()> {
        let transfer_amount: u64 = coins.amount.into();
        self.validate_contract_call(max_gas, fallback_address.into(), transfer_amount)?;

        let fee_amount = (APPROX_CALL_GAS + max_gas) * GAS_PRICE;
        let transfer_amount = transfer_amount - fee_amount;

        self.coins.give(coins)?;
        self.push_outbox(OutMessageArgs::ContractCall {
            contract_address,
            data,
            max_gas,
            fallback_address,
            transfer_amount,
            fee_amount,
            message_index: self.message_index + if self.outbox.is_empty() { 0 } else { 1 },
        })
    }

    fn update_valset(&mut self, mut new_valset: SignatorySet) -> Result<()> {
        new_valset.normalize_vp(u32::MAX as u64);
        self.valset_index += 1;
        self.push_outbox(OutMessageArgs::UpdateValset(
            self.valset_index,
            new_valset.clone(),
        ))?;
        self.valset = new_valset;

        Ok(())
    }

    fn push_outbox(&mut self, msg: OutMessageArgs) -> Result<()> {
        let hash = self.message_hash(&msg);
        let mut sigs = ThresholdSig::from_sigset(&self.valset)?;
        sigs.threshold = u32::MAX as u64 * 2 / 3;
        sigs.set_message(hash);
        let sigset_index = self.valset.index;

        if !self.outbox.is_empty() {
            self.message_index += 1;
        }
        self.outbox.push_back(OutMessage {
            sigs,
            msg,
            sigset_index,
        })?;

        Ok(())
    }

    pub fn take_pending(&mut self) -> Result<Vec<(Dest, Coin<Nbtc>, Identity)>> {
        let mut pending = Vec::new();
        while let Some(entry) = self.pending.pop_front()? {
            pending.push(entry.into_inner());
        }
        Ok(pending)
    }

    #[call]
    pub fn sign(&mut self, msg_index: u64, pubkey: Pubkey, sig: Signature) -> Result<()> {
        exempt_from_fee()?;

        let mut msg = self.get_mut(msg_index)?;
        msg.sigs.sign(pubkey, sig)?;
        Ok(())
    }

    pub fn relay_return(
        &mut self,
        network: u32,
        _consensus_proof: (),
        _account_proof: (),
        // TODO: storage_proofs: LengthVec<u16, (LengthVec<u8, u8>, u64)>,
        returns: LengthVec<u16, (u64, LengthString<u16>, u64, [u8; 20])>, /* TODO: don't include
                                                                           * data, just
                                                                           * state proof */
    ) -> Result<()> {
        exempt_from_fee()?;

        #[cfg(not(test))]
        {
            // TODO: remove whitelisted relaying once we have proper proof verification
            let signer = orga::context::Context::resolve::<orga::plugins::Signer>()
                .ok_or_else(|| Error::Signer("No Signer context available".into()))?
                .signer
                .ok_or_else(|| Error::Coins("Call must be signed".into()))?;
            if signer.to_string().as_str() != WHITELISTED_RELAYER_ADDR {
                return Err(orga::Error::App(
                    "Only whitelisted relayers can relay returns".to_string(),
                )
                .into());
            }
        }

        if returns.len() == 0 {
            return Err(orga::Error::App("Returns must not be empty".to_string()).into());
        }

        // TODO: validate consensus proof
        // TODO: validate state proofs (account proof, storage proofs)

        // TODO: validate return entry indexes
        for (_, dest, amount, sender_addr) in returns.iter().cloned() {
            let coins = self.coins.take(amount)?;
            let sender_id = Identity::EthAccount {
                network,
                connection: self.bridge_contract.bytes(),
                address: sender_addr,
            };
            match dest.parse() {
                Ok(dest) => self.pending.push_back((dest, coins, sender_id))?,
                Err(e) => {
                    log::debug!("failed to parse dest: {}, {}", dest.as_str(), e);
                    self.transfer(sender_addr.into(), coins)?;
                }
            }
            self.return_index += 1;
        }

        // TODO: push return queue clear message

        Ok(())
    }

    pub fn adjust_emergency_disbursal_balance(
        &mut self,
        script: Adapter<Script>,
        difference: i64,
    ) -> Result<()> {
        let total_coins: u64 = self.coins.amount.into();
        if (self.emergency_disbursal_total as i128).saturating_add(difference as i128)
            > total_coins as i128
        {
            return Err(Error::App(
                "Exceeded balance in emergency disbursal distribution".to_string(),
            )
            .into());
        }

        let mut balance = self
            .emergency_disbursal_balances
            .entry(script)?
            .or_default()?;

        let add = |a: u64, b: i64| {
            let a = a as i128;
            let b = b as i128;
            let sum = a.saturating_add(b);
            if sum < 0 || sum > u64::MAX as i128 {
                return Err(Error::App("Balance overflow".to_string()));
            }
            Ok(sum as u64)
        };

        *balance = add(*balance, difference)?;
        self.emergency_disbursal_total = add(self.emergency_disbursal_total, difference)?;

        Ok(())
    }

    #[query]
    pub fn get(&self, msg_index: u64) -> Result<Ref<OutMessage>> {
        let index = self.abs_index(msg_index)?;
        Ok(self.outbox.get(index)?.unwrap())
    }

    pub fn get_mut(&mut self, msg_index: u64) -> Result<ChildMut<u64, OutMessage>> {
        let index = self.abs_index(msg_index)?;
        Ok(self.outbox.get_mut(index)?.unwrap())
    }

    #[query]
    pub fn abs_index(&self, msg_index: u64) -> Result<u64> {
        let start_index = self.message_index + 1 - self.outbox.len();
        if self.outbox.is_empty() || msg_index > self.message_index || msg_index < start_index {
            return Err(Error::App("message index out of bounds".to_string()).into());
        }

        Ok(msg_index - start_index)
    }

    fn message_hash(&self, msg: &OutMessageArgs) -> [u8; 32] {
        sighash(match msg {
            OutMessageArgs::Batch {
                transfers,
                timeout,
                batch_index,
            } => batch_hash(
                self.chain_id,
                self.bridge_contract,
                *batch_index,
                transfers,
                self.token_contract,
                timeout,
            ),
            OutMessageArgs::ContractCall {
                contract_address,
                data,
                max_gas,
                fallback_address,
                transfer_amount,
                fee_amount,
                message_index,
            } => call_hash(
                self.chain_id,
                self.bridge_contract.into(),
                self.token_contract.into(),
                *contract_address,
                data,
                *message_index,
                *transfer_amount,
                *fee_amount,
            ),
            OutMessageArgs::UpdateValset(index, valset) => {
                checkpoint_hash(self.chain_id, self.bridge_contract, valset, *index)
            }
        })
    }

    // TODO: remove, this is a hack due to enum state issues in client
    #[query]
    pub fn needs_sig(&self, msg_index: u64, pubkey: Pubkey) -> Result<bool> {
        Ok(self.get(msg_index)?.sigs.needs_sig(pubkey)?)
    }

    #[query]
    pub fn get_sigs(&self, msg_index: u64) -> Result<Vec<(Pubkey, Option<Signature>)>> {
        let sigs = &self.get(msg_index)?.sigs;
        let data: BTreeSet<_> = sigs
            .sigs
            .iter()?
            .map(|entry| {
                let (pubkey, share) = entry?;
                Ok((share.power, pubkey, share.sig))
            })
            .collect::<Result<_>>()?;
        Ok(data
            .into_iter()
            .rev()
            .map(|(_, pk, sig)| (*pk, sig))
            .collect())
    }
}

#[orga]
#[derive(Debug)]
pub struct OutMessage {
    pub sigset_index: u32,
    pub sigs: ThresholdSig,
    pub msg: OutMessageArgs,
}

#[derive(Encode, Decode, Debug, Clone, Serialize)]
pub enum OutMessageArgs {
    Batch {
        transfers: LengthVec<u16, Transfer>,
        timeout: u64,
        batch_index: u64,
    },
    ContractCall {
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        contract_address: [u8; 20],
        data: LengthVec<u16, u8>,
        max_gas: u64,
        // TODO: ethaddress type
        #[serde(with = "SerHex::<StrictPfx>")]
        fallback_address: [u8; 20],
        transfer_amount: u64, // TODO: this shouldn't be necessary
        fee_amount: u64,
        message_index: u64,
    },
    UpdateValset(u64, SignatorySet),
}

impl FieldQuery for OutMessageArgs {
    fn field_query(&self, _query: Self::FieldQuery) -> orga::Result<()> {
        Ok(())
    }
}
impl MethodQuery for OutMessageArgs {
    fn method_query(&self, _query: Self::MethodQuery) -> orga::Result<()> {
        Ok(())
    }
}
impl Default for OutMessageArgs {
    fn default() -> Self {
        // TODO: shouldn't need default for all state types
        Self::Batch {
            transfers: Default::default(),
            timeout: Default::default(),
            batch_index: Default::default(),
        }
    }
}
impl State for OutMessageArgs {
    fn attach(&mut self, _store: Store) -> orga::Result<()> {
        Ok(())
    }
    fn field_keyop(_field_name: &str) -> Option<orga::describe::KeyOp> {
        None
    }
    fn flush<W: std::io::Write>(self, out: &mut W) -> orga::Result<()> {
        Ok(self.encode_into(out)?)
    }
    fn load(_store: Store, bytes: &mut &[u8]) -> orga::Result<Self> {
        Ok(Self::decode(bytes)?)
    }
}
impl Migrate for OutMessageArgs {
    fn migrate(_src: Store, _dest: Store, bytes: &mut &[u8]) -> orga::Result<Self> {
        Ok(Self::decode(bytes)?)
    }
}
impl Describe for OutMessageArgs {
    fn describe() -> orga::describe::Descriptor {
        <()>::describe()
    }
}

pub fn call_hash(
    chain_id: u32,
    bridge_contract: [u8; 20],
    token_contract: [u8; 20],
    dest_contract: [u8; 20],
    data: &[u8],
    nonce_id: u64,
    transfer_amount: u64,
    fee_amount: u64,
) -> [u8; 32] {
    let bytes = (
        uint256(chain_id as u64),
        addr_to_bytes32(bridge_contract.into()),
        bytes32(b"logicCall").unwrap(),
        vec![transfer_amount],
        vec![addr_to_bytes32(token_contract.into())],
        vec![fee_amount],
        vec![addr_to_bytes32(token_contract.into())],
        addr_to_bytes32(dest_contract.into()),
        data,
        u64::MAX,
        uint256(nonce_id),
        uint256(1),
    )
        .abi_encode_params();

    keccak256(bytes).0
}

#[cfg(feature = "ethereum-full")]
#[allow(clippy::too_many_arguments)]
pub fn logic_call_args(
    transfer_amount: u64,
    fee_amount: u64,
    token_contract: [u8; 20],
    dest_contract: [u8; 20],
    data: &[u8],
    max_gas: u64,
    fallback_address: [u8; 20],
    nonce_id: u64,
) -> LogicCallArgs {
    LogicCallArgs {
        transferAmounts: vec![alloy_core::primitives::U256::from(transfer_amount)],
        transferTokenContracts: vec![alloy_core::primitives::Address::from_slice(&token_contract)],
        feeAmounts: vec![alloy_core::primitives::U256::from(fee_amount)],
        feeTokenContracts: vec![alloy_core::primitives::Address::from_slice(&token_contract)],
        logicContractAddress: alloy_core::primitives::Address::from_slice(&dest_contract),
        fallbackAddress: alloy_core::primitives::Address::from_slice(&fallback_address),
        maxGas: alloy_core::primitives::U256::from(max_gas),
        payload: alloy_core::primitives::Bytes::from(data.to_vec()),
        timeOut: alloy_core::primitives::U256::from(u64::MAX),
        invalidationId: alloy_core::primitives::FixedBytes::from(uint256(nonce_id)), /* TODO: set
                                                                                      * in msg */
        invalidationNonce: alloy_core::primitives::U256::from(1),
    }
}

#[orga]
#[derive(Debug, Clone)]
pub struct Transfer {
    pub dest: Address,
    pub amount: u64,
    pub fee_amount: u64,
}

pub fn checkpoint_hash(
    chain_id: u32,
    bridge_contract: Address,
    valset: &SignatorySet,
    valset_index: u64,
) -> [u8; 32] {
    let bytes = (
        uint256(chain_id as u64),
        addr_to_bytes32(bridge_contract),
        bytes32(b"checkpoint").unwrap(),
        uint256(valset_index),
        valset
            .eth_addresses()
            .iter()
            .cloned()
            .map(addr_to_bytes32)
            .collect::<Vec<_>>(),
        valset
            .signatories
            .iter()
            .map(|s| s.voting_power)
            .collect::<Vec<_>>(),
        [0u8; 20],
        [0u8; 32],
    )
        .abi_encode_params();
    keccak256(bytes).0
}

pub fn batch_hash(
    chain_id: u32,
    bridge_contract: Address,
    batch_index: u64,
    transfers: &LengthVec<u16, Transfer>,
    token_contract: Address,
    timeout: &u64,
) -> [u8; 32] {
    let dests = transfers
        .iter()
        .map(|t| addr_to_bytes32(t.dest))
        .collect::<Vec<_>>();
    let amounts = transfers.iter().map(|t| t.amount).collect::<Vec<_>>();
    let fees = transfers.iter().map(|t| t.fee_amount).collect::<Vec<_>>();

    let bytes = (
        uint256(chain_id as u64),
        addr_to_bytes32(bridge_contract),
        bytes32(b"transactionBatch").unwrap(),
        amounts,
        dests,
        fees,
        batch_index,
        addr_to_bytes32(token_contract),
        timeout,
    )
        .abi_encode_params();

    keccak256(bytes).0
}

pub fn sighash(message: [u8; 32]) -> [u8; 32] {
    let mut bytes = b"\x19Ethereum Signed Message:\n32".to_vec();
    bytes.extend_from_slice(&message);

    keccak256(bytes).0
}

pub fn to_eth_sig(
    sig: &bitcoin::secp256k1::ecdsa::Signature,
    pubkey: &PublicKey,
    msg: &Message,
) -> (u8, [u8; 32], [u8; 32]) {
    let secp = Secp256k1::new();

    let rs = sig.serialize_compact();

    let mut recid = None;
    for i in 0..=1 {
        let sig =
            RecoverableSignature::from_compact(&rs, RecoveryId::from_i32(i).unwrap()).unwrap();
        let pk = secp.recover_ecdsa(msg, &sig).unwrap();
        if pk == *pubkey {
            recid = Some(i);
            break;
        }
    }
    let v = recid.unwrap() as u8 + 27;

    let mut r = [0; 32];
    r.copy_from_slice(&rs[0..32]);

    let mut s = [0; 32];
    s.copy_from_slice(&rs[32..]);

    (v, r, s)
}

pub fn bytes32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 32 {
        return Err(Error::App("bytes too long".to_string()).into());
    }

    let mut padded = [0; 32];
    padded[..bytes.len()].copy_from_slice(bytes);
    Ok(padded)
}

pub fn uint256(n: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    bytes
}

pub fn addr_to_bytes32(addr: Address) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[12..].copy_from_slice(&addr.bytes());
    bytes
}

impl SignatorySet {
    pub fn eth_addresses(&self) -> Vec<Address> {
        self.signatories
            .iter()
            .map(|s| {
                let pk = PublicKey::from_slice(s.pubkey.as_slice()).unwrap();
                let mut uncompressed = [0; 64];
                uncompressed.copy_from_slice(&pk.serialize_uncompressed()[1..]);
                Address::from_pubkey_eth(uncompressed)
            })
            .collect()
    }

    pub fn normalize_vp(&mut self, total: u64) {
        let adjust = |n: u64| (n as u128 * total as u128 / self.present_vp as u128) as u64;

        for s in self.signatories.iter_mut() {
            s.voting_power = adjust(s.voting_power);
        }
        self.possible_vp = adjust(self.possible_vp);
        self.present_vp = total;
    }

    #[cfg(feature = "ethereum-full")]
    pub fn to_abi(&self, nonce: u64) -> ValsetArgs {
        ValsetArgs {
            valsetNonce: alloy_core::primitives::U256::from(nonce),
            validators: self
                .eth_addresses()
                .iter()
                .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
                .collect(),
            powers: self
                .signatories
                .iter()
                .map(|s| alloy_core::primitives::U256::from(s.voting_power))
                .collect(),
            rewardToken: alloy_core::primitives::Address::default(),
            rewardAmount: alloy_core::primitives::U256::default(),
        }
    }
}

#[cfg(feature = "ethereum-full")]
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    token_contract,
    "src/ethereum/contracts/CosmosERC20.json",
);

#[cfg(all(test, feature = "ethereum-full"))]
mod tests {
    use alloy_core::sol_types::SolEvent;
    use alloy_node_bindings::Anvil;
    use alloy_provider::ProviderBuilder;
    use bitcoin::{
        secp256k1::{Message, Secp256k1, SecretKey},
        util::bip32::{ExtendedPrivKey, ExtendedPubKey},
    };
    use orga::{coins::Symbol, context::Context, plugins::Paid};

    use crate::bitcoin::{
        signatory::{derive_pubkey, Signatory},
        threshold_sig::Pubkey,
    };

    use super::*;

    #[test]
    fn checkpoint_fixture() {
        let secp = Secp256k1::new();

        let privkey = SecretKey::from_slice(&bytes32(b"test").unwrap()).unwrap();
        let pubkey = privkey.public_key(&secp);

        let valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        assert_eq!(
            hex::encode(checkpoint_hash(123, [123; 20].into(), &valset, 0)),
            "61fe378d7a8aac20d5882ff4696d9c14c0db93b583fcd25f0616ce5187efae69",
        );

        let valset2 = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_001,
            }],
            create_time: 0,
            present_vp: 10_000_000_001,
            possible_vp: 10_000_000_001,
        };

        let updated_checkpoint = checkpoint_hash(123, [123; 20].into(), &valset2, 1);
        assert_eq!(
            hex::encode(updated_checkpoint),
            "0b73bc9926c210f36673973a0ecb0a5f337ca1c7f99ba44ecf3624c891a8ab2b",
        );

        let valset_update_sighash = sighash(updated_checkpoint);
        let msg = Message::from_slice(&valset_update_sighash).unwrap();
        let sig = secp.sign_ecdsa(&msg, &privkey);
        let vrs = to_eth_sig(&sig, &pubkey, &msg);

        assert_eq!(vrs.0, 27);
        assert_eq!(
            hex::encode(vrs.1),
            "060215a246c6439b1ba1cf29577936ef20912e9e97b44326fd063b22221f69d8",
        );
        assert_eq!(
            hex::encode(vrs.2),
            "24d9924b969a742b877831a43b14e0ea88886308ecf0e37ee70a096346966a43",
        );
    }

    #[test]
    fn indices() {
        let secp = Secp256k1::new();

        let privkey = SecretKey::from_slice(&bytes32(b"test").unwrap()).unwrap();
        let pubkey = privkey.public_key(&secp);

        let valset = SignatorySet {
            index: 10,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        let mut ethereum = Connection::new(123, Address::NULL, Address::NULL, valset);
        assert_eq!(ethereum.batch_index, 0);
        assert_eq!(ethereum.valset_index, 0);
        assert_eq!(ethereum.message_index, 1);
        assert_eq!(ethereum.outbox.len(), 0);

        let valset2 = SignatorySet {
            index: 11,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_001,
            }],
            create_time: 1_000_000_000,
            present_vp: 10_000_000_001,
            possible_vp: 10_000_000_001,
        };
        ethereum.step(&valset2).unwrap();
        assert_eq!(ethereum.batch_index, 0);
        assert_eq!(ethereum.valset_index, 1);
        assert_eq!(ethereum.message_index, 1);
        assert_eq!(ethereum.outbox.len(), 1);

        let valset2 = SignatorySet {
            index: 12,
            signatories: vec![Signatory {
                pubkey: pubkey.into(),
                voting_power: 10_000_000_002,
            }],
            create_time: 2_000_000_000,
            present_vp: 10_000_000_002,
            possible_vp: 10_000_000_002,
        };
        ethereum.step(&valset2).unwrap();
        assert_eq!(ethereum.batch_index, 0);
        assert_eq!(ethereum.valset_index, 2);
        assert_eq!(ethereum.message_index, 2);
        assert_eq!(ethereum.outbox.len(), 2);
    }

    #[test]
    fn ss_normalize_vp() {
        let mut valset = SignatorySet {
            index: 0,
            signatories: vec![
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 10,
                },
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 20,
                },
                Signatory {
                    pubkey: Pubkey::new([2; 33]).unwrap(),
                    voting_power: 30,
                },
            ],
            create_time: 0,
            present_vp: 60,
            possible_vp: 60,
        };

        valset.normalize_vp(6);
        assert_eq!(valset.signatories[0].voting_power, 1);
        assert_eq!(valset.signatories[1].voting_power, 2);
        assert_eq!(valset.signatories[2].voting_power, 3);
        assert_eq!(valset.possible_vp, 6);
        assert_eq!(valset.present_vp, 6);

        valset.normalize_vp(u32::MAX as u64);
        assert_eq!(valset.signatories[0].voting_power, 715_827_882);
        assert_eq!(valset.signatories[1].voting_power, 1_431_655_765);
        assert_eq!(valset.signatories[2].voting_power, 2_147_483_647);
        assert_eq!(valset.possible_vp, u32::MAX as u64);
        assert_eq!(valset.present_vp, u32::MAX as u64);
    }

    #[ignore]
    #[tokio::test]
    #[serial_test::serial]
    async fn valset_update() {
        Context::add(Paid::default());

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        let bridge_addr = {
            let decoded = hex::decode("5FbDB2315678afecb367f032d93F642f64180aa3").unwrap();
            let mut data = [0; 20];
            data.copy_from_slice(decoded.as_slice());
            Address::from(data)
        };
        // TODO: token contract
        let mut conn = Connection::new(123, bridge_addr, bridge_addr, valset);
        let valset = conn.valset.clone();

        let new_valset = SignatorySet {
            index: 1,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 1).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 1_000_000_000,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };
        conn.update_valset(new_valset).unwrap();
        let new_valset = conn.valset.clone();
        assert_eq!(conn.outbox.len(), 1);
        assert_eq!(conn.message_index, 1);

        let msg = conn.get(1).unwrap().sigs.message;
        let sig = crate::bitcoin::signer::sign(&Secp256k1::signing_only(), &xpriv, &[(msg, 0)])
            .unwrap()[0];
        let pubkey = derive_pubkey(&secp, xpub.into(), 0).unwrap();
        conn.sign(1, pubkey.into(), sig).unwrap();
        assert!(conn.get(1).unwrap().sigs.signed());

        let anvil = Anvil::new().try_spawn().unwrap();
        let rpc_url = anvil.endpoint().parse().unwrap();
        let provider = ProviderBuilder::new().on_http(rpc_url);

        let contract = bridge_contract::deploy(
            provider,
            alloy_core::primitives::Address::from_slice(&[0; 20]),
            valset
                .eth_addresses()
                .iter()
                .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
                .collect(),
            valset
                .signatories
                .iter()
                .map(|s| alloy_core::primitives::U256::from(s.voting_power))
                .collect(),
        )
        .await
        .unwrap();

        let sigs: Vec<_> = conn
            .get(1)
            .unwrap()
            .sigs
            .sigs()
            .unwrap()
            .into_iter()
            .map(|(pk, sig)| {
                let (v, r, s) = to_eth_sig(
                    &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                    &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                    &Message::from_slice(&msg).unwrap(),
                );
                bridge_contract::Signature {
                    v,
                    r: r.into(),
                    s: s.into(),
                }
            })
            .collect();

        dbg!(contract
            .updateValset(new_valset.to_abi(1), valset.to_abi(0), sigs.clone())
            .into_transaction_request());
        dbg!(contract
            .updateValset(new_valset.to_abi(1), valset.to_abi(0), sigs)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());

        Context::remove::<Paid>();
    }

    #[test]
    fn create_connection() -> Result<()> {
        let mut ethereum = Ethereum::default();

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };

        let bridge_contract = Address::NULL;
        let token_contract = Address::NULL;
        let chain_id = 1337;

        ethereum.networks.insert(
            chain_id,
            Network {
                id: chain_id,
                connections: Default::default(),
            },
        )?;

        ethereum.create_connection(chain_id, bridge_contract, token_contract, valset.clone())?;

        let other_token_contract = Address::from([123; 20]);

        // a connection can't be created for the same chain id and bridge contract
        assert!(ethereum
            .create_connection(chain_id, bridge_contract, other_token_contract, valset)
            .is_err());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    #[serial_test::serial]
    async fn transfer() {
        Context::add(Paid::default());

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let mut valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };
        valset.normalize_vp(u32::MAX as u64);

        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_anvil_with_wallet();

        let contract = bridge_contract::deploy(
            provider,
            alloy_core::primitives::Address::from_slice(&[0; 20]),
            valset
                .eth_addresses()
                .iter()
                .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
                .collect(),
            valset
                .signatories
                .iter()
                .map(|s| alloy_core::primitives::U256::from(s.voting_power))
                .collect(),
        )
        .await
        .unwrap();

        let receipt = dbg!(contract
            .deployERC20(
                "usat".to_string(),
                "nBTC".to_string(),
                "nBTC".to_string(),
                14,
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());
        let mut token_contract_addr = None;
        for log in receipt.inner.logs().into_iter() {
            let res = bridge_contract::ERC20DeployedEvent::decode_log_data(log.data(), true);
            if let Ok(e) = res {
                token_contract_addr = Some(e._tokenContract);
                println!("{}", e._tokenContract);
            }
        }

        let mut ethereum = Connection::new(
            123,
            contract.address().0 .0.into(),
            token_contract_addr.unwrap().0 .0.into(),
            valset,
        );
        println!(
            "{} {}",
            hex::encode(ethereum.valset.eth_addresses()[0].bytes()),
            ethereum.valset.signatories[0].voting_power
        );

        ethereum
            .transfer(anvil.addresses()[0].0 .0.into(), Nbtc::mint(1_000_000))
            .unwrap();
        assert_eq!(ethereum.outbox.len(), 1);
        assert_eq!(ethereum.batch_index, 1);
        assert_eq!(ethereum.message_index, 1);

        let msg = ethereum.get(1).unwrap().sigs.message;
        let data = ethereum.get(1).unwrap().msg.clone();
        let sig = crate::bitcoin::signer::sign(&Secp256k1::signing_only(), &xpriv, &[(msg, 0)])
            .unwrap()[0];
        let pubkey = derive_pubkey(&secp, xpub.into(), 0).unwrap();
        ethereum.sign(1, pubkey.into(), sig).unwrap();
        assert!(ethereum.get(1).unwrap().sigs.signed());

        let sigs: Vec<_> = ethereum
            .get(1)
            .unwrap()
            .sigs
            .sigs()
            .unwrap()
            .into_iter()
            .map(|(pk, sig)| {
                let (v, r, s) = to_eth_sig(
                    &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                    &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                    &Message::from_slice(&msg).unwrap(),
                );
                bridge_contract::Signature {
                    v,
                    r: r.into(),
                    s: s.into(),
                }
            })
            .collect();

        //submitBatch(currentValset, sigs, amounts, destinations, fees, batchNonce,
        // tokenContract, batchTimeout)
        if let OutMessageArgs::Batch {
            transfers,
            timeout,
            batch_index,
        } = data
        {
            dbg!(contract
                .submitBatch(
                    ethereum.valset.to_abi(ethereum.valset_index),
                    sigs.clone(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.amount))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::Address::from_slice(&t.dest.bytes()))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.fee_amount))
                        .collect(),
                    alloy_core::primitives::U256::from(batch_index),
                    alloy_core::primitives::Address::from_slice(&ethereum.token_contract.bytes()),
                    alloy_core::primitives::U256::from(timeout),
                )
                .into_transaction_request());
            dbg!(contract
                .submitBatch(
                    ethereum.valset.to_abi(ethereum.valset_index),
                    sigs,
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.amount))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::Address::from_slice(&t.dest.bytes()))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.fee_amount))
                        .collect(),
                    alloy_core::primitives::U256::from(batch_index),
                    alloy_core::primitives::Address::from_slice(&ethereum.token_contract.bytes()),
                    alloy_core::primitives::U256::from(timeout),
                )
                .send()
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap());
        } else {
            unreachable!();
        };

        Context::remove::<Paid>();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn contract_call() {
        Context::add(Paid::default());

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let mut valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };
        valset.normalize_vp(u32::MAX as u64);

        let _anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_anvil_with_wallet();

        let contract = bridge_contract::deploy(
            provider,
            alloy_core::primitives::Address::from_slice(&[0; 20]),
            valset
                .eth_addresses()
                .iter()
                .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
                .collect(),
            valset
                .signatories
                .iter()
                .map(|s| alloy_core::primitives::U256::from(s.voting_power))
                .collect(),
        )
        .await
        .unwrap();

        let receipt = dbg!(contract
            .deployERC20(
                "usat".to_string(),
                "nBTC".to_string(),
                "nBTC".to_string(),
                14,
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());
        let mut token_contract_addr = None;
        for log in receipt.inner.logs().into_iter() {
            let res = bridge_contract::ERC20DeployedEvent::decode_log_data(log.data(), true);
            if let Ok(e) = res {
                token_contract_addr = Some(e._tokenContract);
                println!("{}", e._tokenContract);
            }
        }
        let token_contract_addr = token_contract_addr.unwrap().0 .0.into();

        let mut ethereum = Connection::new(
            123,
            contract.address().0 .0.into(),
            token_contract_addr,
            valset,
        );

        ethereum
            .call_contract(
                token_contract_addr.into(),
                bytes32(hex::decode("73b20547").unwrap().as_slice())
                    .unwrap()
                    .to_vec()
                    .try_into()
                    .unwrap(),
                10_000,
                [123; 20],
                Nbtc::mint(18_000_000_000),
            )
            .unwrap();
        assert_eq!(ethereum.outbox.len(), 1);
        assert_eq!(ethereum.message_index, 1);

        let msg = ethereum.get(1).unwrap().sigs.message;
        let data = ethereum.get(1).unwrap().msg.clone();
        let sig = crate::bitcoin::signer::sign(&Secp256k1::signing_only(), &xpriv, &[(msg, 0)])
            .unwrap()[0];
        let pubkey = derive_pubkey(&secp, xpub.into(), 0).unwrap();
        ethereum.sign(1, pubkey.into(), sig).unwrap();
        assert!(ethereum.get(1).unwrap().sigs.signed());

        let sigs: Vec<_> = ethereum
            .get(1)
            .unwrap()
            .sigs
            .sigs()
            .unwrap()
            .into_iter()
            .map(|(pk, sig)| {
                let (v, r, s) = to_eth_sig(
                    &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                    &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                    &Message::from_slice(&msg).unwrap(),
                );
                bridge_contract::Signature {
                    v,
                    r: r.into(),
                    s: s.into(),
                }
            })
            .collect();

        if let OutMessageArgs::ContractCall {
            contract_address,
            data,
            transfer_amount,
            message_index,
            max_gas,
            fee_amount,
            fallback_address,
        } = data
        {
            dbg!(contract
                .submitLogicCall(
                    ethereum.valset.to_abi(ethereum.valset_index),
                    sigs,
                    logic_call_args(
                        transfer_amount,
                        fee_amount,
                        token_contract_addr.into(),
                        contract_address,
                        data.as_slice(),
                        max_gas,
                        fallback_address,
                        message_index
                    ),
                )
                .send()
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap());
        } else {
            unreachable!();
        };

        Context::remove::<Paid>();
    }

    #[ignore]
    #[tokio::test]
    #[serial_test::serial]
    async fn return_queue() {
        Context::add(Paid::default());

        let secp = Secp256k1::new();

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Regtest, &[0]).unwrap();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);

        let mut valset = SignatorySet {
            index: 0,
            signatories: vec![Signatory {
                pubkey: derive_pubkey(&secp, xpub.into(), 0).unwrap().into(),
                voting_power: 10_000_000_000,
            }],
            create_time: 0,
            present_vp: 10_000_000_000,
            possible_vp: 10_000_000_000,
        };
        valset.normalize_vp(u32::MAX as u64);

        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_anvil_with_wallet();

        let contract = bridge_contract::deploy(
            &provider,
            alloy_core::primitives::Address::from_slice(&[0; 20]),
            valset
                .eth_addresses()
                .iter()
                .map(|a| alloy_core::primitives::Address::from_slice(&a.bytes()))
                .collect(),
            valset
                .signatories
                .iter()
                .map(|s| alloy_core::primitives::U256::from(s.voting_power))
                .collect(),
        )
        .await
        .unwrap();

        let receipt = dbg!(contract
            .deployERC20(
                "usat".to_string(),
                "nBTC".to_string(),
                "nBTC".to_string(),
                14,
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());
        let mut token_contract_addr = None;
        for log in receipt.inner.logs().into_iter() {
            let res = bridge_contract::ERC20DeployedEvent::decode_log_data(log.data(), true);
            if let Ok(e) = res {
                token_contract_addr = Some(e._tokenContract);
                println!("{}", e._tokenContract);
            }
        }
        let token_contract_addr = token_contract_addr.unwrap().0 .0.into();

        let mut ethereum = Connection::new(
            123,
            contract.address().0 .0.into(),
            token_contract_addr,
            valset,
        );

        ethereum
            .transfer(anvil.addresses()[0].0 .0.into(), Nbtc::mint(1_000_000))
            .unwrap();
        assert_eq!(ethereum.outbox.len(), 1);
        assert_eq!(ethereum.batch_index, 1);
        assert_eq!(ethereum.message_index, 1);
        assert_eq!(ethereum.coins.amount, 1_000_000);

        let msg = ethereum.get(1).unwrap().sigs.message;
        let data = ethereum.get(1).unwrap().msg.clone();
        let sig = crate::bitcoin::signer::sign(&Secp256k1::signing_only(), &xpriv, &[(msg, 0)])
            .unwrap()[0];
        let pubkey = derive_pubkey(&secp, xpub.into(), 0).unwrap();
        ethereum.sign(1, pubkey.into(), sig).unwrap();
        assert!(ethereum.get(1).unwrap().sigs.signed());

        let sigs: Vec<_> = ethereum
            .get(1)
            .unwrap()
            .sigs
            .sigs()
            .unwrap()
            .into_iter()
            .map(|(pk, sig)| {
                let (v, r, s) = to_eth_sig(
                    &bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig.0).unwrap(),
                    &bitcoin::secp256k1::PublicKey::from_slice(pk.as_slice()).unwrap(),
                    &Message::from_slice(&msg).unwrap(),
                );
                bridge_contract::Signature {
                    v,
                    r: r.into(),
                    s: s.into(),
                }
            })
            .collect();

        if let OutMessageArgs::Batch {
            transfers,
            timeout,
            batch_index,
        } = data
        {
            dbg!(contract
                .submitBatch(
                    ethereum.valset.to_abi(ethereum.valset_index),
                    sigs,
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.amount))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::Address::from_slice(&t.dest.bytes()))
                        .collect(),
                    transfers
                        .iter()
                        .map(|t| alloy_core::primitives::U256::from(t.fee_amount))
                        .collect(),
                    alloy_core::primitives::U256::from(batch_index),
                    alloy_core::primitives::Address::from_slice(&ethereum.token_contract.bytes()),
                    alloy_core::primitives::U256::from(timeout),
                )
                .send()
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap());
        } else {
            unreachable!();
        };

        let token_contract_client = token_contract::new(
            alloy_core::primitives::Address::from_slice(&token_contract_addr.bytes()),
            &provider,
        );

        dbg!(token_contract_client
            .approve(
                alloy_core::primitives::Address::from_slice(&ethereum.bridge_contract.bytes()),
                alloy_core::primitives::U256::from(u64::MAX),
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());

        dbg!(contract
            .sendToNomic(
                alloy_core::primitives::Address::from_slice(&ethereum.token_contract.bytes()),
                Address::from_pubkey([0; 33]).to_string(),
                alloy_core::primitives::U256::from(500_000),
            )
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap());

        assert_eq!(ethereum.return_index, 0);
        // TODO
        ethereum
            .relay_return(
                123,
                (),
                (),
                vec![(
                    0,
                    Dest::NativeAccount {
                        address: Address::from_pubkey([0; 33]),
                    }
                    .to_string()
                    .try_into()
                    .unwrap(),
                    500_000,
                    [0; 20],
                )]
                .try_into()
                .unwrap(),
            )
            .unwrap();
        assert_eq!(ethereum.return_index, 1);
        assert_eq!(ethereum.coins.amount, 500_000);

        Context::remove::<Paid>();
    }
}
