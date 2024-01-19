use crate::{
    bitcoin::{
        signatory::{derive_pubkey, Signatory, SignatorySet},
        threshold_sig::{Pubkey, VersionedPubkey},
        Nbtc, Xpub,
    },
    error::Result,
};

#[cfg(feature = "full")]
use crate::app::{InnerApp, Nom};
#[cfg(feature = "full")]
use orga::{
    client::{AppClient, Wallet},
    macros::build_call,
};

use bitcoin::{
    secp256k1::Secp256k1,
    util::bip32::{ChildNumber, ExtendedPubKey, Fingerprint},
};
use ibc::{
    applications::transfer::context::TokenTransferValidationContext,
    clients::ics07_tendermint,
    core::{
        ics02_client::consensus_state::ConsensusState, ics23_commitment::commitment::CommitmentRoot,
    },
};
use ics23::ExistenceProof;
use orga::{
    abci::prost::Adapter,
    collections::Map,
    cosmrs::proto,
    encoding::{Decode, Encode, LengthVec},
    ibc::ibc_rs::{self as ibc},
    ibc::{
        ibc_rs::{core::ics24_host::identifier::PortId, Height},
        Client, ClientId, Ibc,
    },
    orga, Error as OrgaError,
};
use proto::traits::{Message, MessageExt};
#[cfg(feature = "full")]
use tendermint_rpc::HttpClient;

pub const MAX_SIGSET_SIZE: usize = 40;
pub const RECOVERY_THRESHOLD: (u64, u64) = (2, 3);

#[orga]
pub struct Cosmos {
    pub chains: Map<ClientId, Chain>,
}

#[orga]
impl Cosmos {
    #[query]
    pub fn op_key_present(&self, client_id: ClientId, cons_key: LengthVec<u8, u8>) -> Result<bool> {
        if let Some(chain) = self.chains.get(client_id)? {
            Ok(chain.op_keys_by_cons.contains_key(cons_key)?)
        } else {
            Ok(false)
        }
    }

    pub fn build_outputs(&self, ibc: &Ibc, index: u32) -> Result<Vec<bitcoin::TxOut>> {
        let mut outputs = vec![];

        for entry in self.chains.iter()? {
            let (client_id, chain) = entry?;
            let Some(client) = ibc.ctx.clients.get(client_id.clone())? else {
                log::debug!("Warning: client not found");
                continue;
            };

            let sigset_res = chain.to_sigset(index, &client);
            let Ok(Some(sigset)) = sigset_res else {
                log::debug!(
                    "Warning: failed to build sigset ({})",
                    sigset_res.err().map(|e| e.to_string()).unwrap_or_default(),
                );
                continue;
            };

            if !sigset.has_quorum() {
                continue;
            }
            let mut total_usats = 0;
            let connection_ids = ibc.ctx.query_client_connections(client_id.clone())?;
            for connection_id in connection_ids {
                let channels = ibc.ctx.query_connection_channels(connection_id.clone())?;
                for channel in channels {
                    if channel.port_id != ibc.transfer().get_port().unwrap().to_string() {
                        continue;
                    }
                    let port_id: PortId = channel
                        .port_id
                        .parse()
                        .map_err(|_| crate::error::Error::Ibc("Invalid port".to_string()))?;
                    let channel_id = channel
                        .channel_id
                        .parse()
                        .map_err(|_| crate::error::Error::Ibc("Invalid channel id".to_string()))?;

                    let escrow_address = ibc
                        .transfer()
                        .get_escrow_account(&port_id, &channel_id)
                        .map_err(|e| crate::error::Error::Ibc(e.to_string()))?;
                    let balance: u64 = ibc
                        .transfer()
                        .symbol_balance::<Nbtc>(escrow_address)
                        .map_err(|e| crate::error::Error::Ibc(e.to_string()))?
                        .into();
                    total_usats += balance;
                }
            }
            outputs.push(bitcoin::TxOut {
                value: total_usats / 1_000_000,
                script_pubkey: sigset.output_script(&[0], RECOVERY_THRESHOLD)?,
            })
        }

        Ok(outputs)
    }

    pub fn relay_op_key(
        &mut self,
        ibc: &Ibc,
        client_id: ClientId,
        height: (u64, u64),
        cons_key: LengthVec<u8, u8>,
        op_addr: Proof,
        acc: Proof,
    ) -> Result<()> {
        let client = ibc
            .ctx
            .clients
            .get(client_id.clone())?
            .ok_or_else(|| OrgaError::Ibc("Client not found".to_string()))?;

        if client.client_type()? != ics07_tendermint::client_type() {
            return Err(OrgaError::Ibc("Only supported for Tendermint clients".to_string()).into());
        }

        let epoch_height = Height::new(height.0, height.1)
            .map_err(|_| OrgaError::Ibc("Invalid height".to_string()))?;
        let cons_state = client
            .consensus_states
            .get(epoch_height.into())?
            .ok_or_else(|| OrgaError::Ibc("No consensus state for given height".to_string()))?;
        let root = cons_state.root();

        let cons_addr = tmhash(cons_key.as_slice());

        let header = client.last_header()?;
        let val = header.validator_set.validator(
            cons_addr
                .to_vec()
                .try_into()
                .map_err(|_| OrgaError::App("Could not convert consensus address".to_string()))?,
        );
        if val.is_none() {
            return Err(OrgaError::App(
                "Consensus key is not in most recent validator set".to_string(),
            )
            .into());
        }

        op_addr.verify(root, "staking")?;
        acc.verify(root, "acc")?;

        if op_addr.key()? != &vec![&[0x22, 0x14], cons_addr.as_slice()].concat() {
            return Err(OrgaError::App(
                "Operator address proof does not match consensus address".to_string(),
            )
            .into());
        }

        if acc.key()? != &vec![&[0x01], op_addr.value()?.as_slice()].concat() {
            return Err(OrgaError::App(
                "Account proof does not match operator address".to_string(),
            )
            .into());
        }

        let any = proto::Any::decode(acc.value()?.as_slice())
            .map_err(|_| OrgaError::App("Failed to decode account protobuf".to_string()))?;
        let acc = proto::cosmos::auth::v1beta1::BaseAccount::from_any(&any)
            .map_err(|_| OrgaError::App("Invalid account".to_string()))?;

        let op_key_any = acc
            .pub_key
            .ok_or_else(|| OrgaError::App("Expected public key".to_string()))?;
        let op_key = Pubkey::try_from_slice(
            proto::cosmos::crypto::secp256k1::PubKey::from_any(&op_key_any)
                .map_err(|_| OrgaError::App("Invalid public key".to_string()))?
                .key
                .as_slice(),
        )?
        .into();

        let mut chain = self.chains.entry(client_id)?.or_default()?;
        if let Some(existing_key) = chain.op_keys_by_cons.get(cons_key.clone())? {
            if *existing_key == op_key {
                return Err(OrgaError::App("Operator key already relayed".to_string()).into());
            }
        }
        chain.op_keys_by_cons.insert(cons_key, op_key)?;

        Ok(())
    }
}

pub fn tmhash(bytes: &[u8]) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();

    let mut output = [0; 20];
    output.copy_from_slice(&hash[..20]);
    output
}

#[derive(Debug)]
pub struct Proof {
    pub inner: Adapter<ics23::CommitmentProof>,
    pub outer: Adapter<ics23::CommitmentProof>,
}

impl Encode for Proof {
    fn encode_into<W: std::io::Write>(&self, dest: &mut W) -> ed::Result<()> {
        let mut inner_bytes = vec![];
        self.inner.encode_into(&mut inner_bytes)?;
        let inner: LengthVec<u16, u8> = inner_bytes
            .try_into()
            .map_err(|_| ed::Error::UnexpectedByte(55))?;
        inner.encode_into(dest)?;

        let mut outer_bytes = vec![];
        self.outer.encode_into(&mut outer_bytes)?;
        let outer: LengthVec<u16, u8> = outer_bytes
            .try_into()
            .map_err(|_| ed::Error::UnexpectedByte(56))?;
        outer.encode_into(dest)?;

        Ok(())
    }
    fn encoding_length(&self) -> ed::Result<usize> {
        let mut len = 4;
        len += self.inner.encoding_length()?;
        len += self.outer.encoding_length()?;

        Ok(len)
    }
}

impl Decode for Proof {
    fn decode<R: std::io::Read>(mut input: R) -> ed::Result<Self> {
        let inner: LengthVec<u16, u8> = Decode::decode(&mut input)?;
        let inner = Adapter::decode(inner.as_slice())?;

        let outer: LengthVec<u16, u8> = Decode::decode(input)?;
        let outer = Adapter::decode(outer.as_slice())?;

        Ok(Proof { inner, outer })
    }
}

impl orga::encoding::Terminated for Proof {}

impl Proof {
    pub fn verify(&self, root: &CommitmentRoot, store: &str) -> Result<()> {
        let inner_root = &self.outer_proof()?.value;
        if !ics23::verify_membership::<ics23::HostFunctionsManager>(
            &self.outer,
            &ics23::tendermint_spec(),
            &root.clone().into_vec(),
            store.as_bytes(),
            inner_root,
        ) {
            return Err(OrgaError::Ibc("Invalid outer proof".to_string()).into());
        }

        if !ics23::verify_membership::<ics23::HostFunctionsManager>(
            &self.inner,
            &ics23::iavl_spec(),
            inner_root,
            self.key()?,
            self.value()?,
        ) {
            return Err(OrgaError::Ibc("Invalid inner proof".to_string()).into());
        }

        Ok(())
    }

    pub fn key(&self) -> Result<&Vec<u8>> {
        Ok(&self.inner_proof()?.key)
    }

    pub fn value(&self) -> Result<&Vec<u8>> {
        Ok(&self.inner_proof()?.value)
    }

    pub fn outer_proof(&self) -> Result<&ExistenceProof> {
        let proof = &self
            .outer
            .proof
            .as_ref()
            .ok_or_else(|| OrgaError::Ibc("Expected proof".to_string()))?;
        if let ics23::commitment_proof::Proof::Exist(proof) = proof {
            Ok(proof)
        } else {
            Err(OrgaError::Ibc("Expected existence proof".to_string()).into())
        }
    }

    pub fn inner_proof(&self) -> Result<&ExistenceProof> {
        let proof = &self
            .inner
            .proof
            .as_ref()
            .ok_or_else(|| OrgaError::Ibc("Expected proof".to_string()))?;
        if let ics23::commitment_proof::Proof::Exist(proof) = proof {
            Ok(proof)
        } else {
            Err(OrgaError::Ibc("Expected existence proof".to_string()).into())
        }
    }
}

#[orga]
pub struct Chain {
    pub op_keys_by_cons: Map<LengthVec<u8, u8>, VersionedPubkey>,
}

#[orga]
impl Chain {
    pub fn to_sigset(&self, index: u32, client: &Client) -> Result<Option<SignatorySet>> {
        // vals are already sorted by voting power
        let vals = &client.last_header()?.validator_set;

        let mut sigset = SignatorySet {
            index,
            ..Default::default()
        };

        let secp = Secp256k1::new();
        for val in vals.validators() {
            sigset.possible_vp += val.power();

            let Some(cons_key) = val.pub_key.ed25519().map(|v| v.as_bytes().to_vec()) else {
                continue;
            };
            let op_key = match self.op_keys_by_cons.get(cons_key.try_into()?)? {
                None => continue,
                Some(op_key) => op_key,
            };
            let op_key = match bitcoin::secp256k1::PublicKey::from_slice(op_key.as_slice()) {
                Ok(op_key) => op_key,
                Err(err) => {
                    log::debug!("Warning: invalid operator key: {}", err);
                    continue;
                }
            };

            let xpub = ExtendedPubKey {
                network: bitcoin::Network::Bitcoin,
                child_number: ChildNumber::Normal { index: 0 },
                chain_code: [0; 32].as_slice().into(),
                depth: 0,
                parent_fingerprint: Fingerprint::default(),
                public_key: op_key,
            };
            let xpub = Xpub::new(xpub);

            let sig_key = derive_pubkey(&secp, xpub, index)?;

            if sigset.signatories.len() < MAX_SIGSET_SIZE {
                sigset.signatories.push(Signatory {
                    voting_power: val.power(),
                    pubkey: sig_key.into(),
                });
                sigset.present_vp += val.power();
            }
        }

        Ok(Some(sigset))
    }
}

#[cfg(feature = "full")]
pub async fn relay_op_keys<
    W: Wallet,
    F: Fn() -> AppClient<InnerApp, InnerApp, orga::tendermint::client::HttpClient, Nom, W>,
>(
    app_client: F,
    client_id: ClientId,
    rpc_url: &str,
) -> orga::Result<()> {
    use tendermint_rpc::Client as RpcClient;
    let latest_height: Height = (app_client)()
        .query(|app: InnerApp| {
            Ok(app
                .ibc
                .ctx
                .clients
                .get(client_id.clone())?
                .ok_or_else(|| OrgaError::Ibc("Client not found".to_string()))?
                .client_state
                .get(Default::default())?
                .ok_or_else(|| OrgaError::Ibc("Client state not found".to_string()))?
                .inner
                .latest_height)
        })
        .await?;

    let latest_height_rev = latest_height.revision_number();
    let latest_height: u32 = latest_height.revision_height().try_into().unwrap();

    let rpc_client = HttpClient::new(rpc_url).unwrap();
    let res = rpc_client
        .validators(latest_height, tendermint_rpc::Paging::All)
        .await?;

    for validator in res.validators.iter() {
        let client_id = client_id.clone();
        let cons_addr_bytes = validator.address.as_bytes().to_vec();
        let Some(cons_key) = validator.pub_key.ed25519().map(|v| v.as_bytes().to_vec()) else {
            continue;
        };
        let already_relayed = (app_client)()
            .query(|app: InnerApp| {
                Ok(app
                    .cosmos
                    .op_key_present(client_id.clone(), cons_key.clone().try_into().unwrap())?)
            })
            .await?;

        if already_relayed {
            continue;
        }
        let query_path = "/store/staking/key".to_string();
        let query_data = [vec![0x22, 0x14], cons_addr_bytes].concat();
        let res = rpc_client
            .abci_query(
                Some(query_path),
                query_data,
                Some((latest_height - 1).into()),
                true,
            )
            .await?;

        if res.proof.is_none() {
            return Err(OrgaError::App("No proof".to_string()));
        }
        if res.proof.as_ref().unwrap().ops.len() != 2 {
            return Err(OrgaError::App("Invalid proof op len".to_string()));
        }
        let op_addr_proof = Proof {
            inner: Decode::decode(res.proof.as_ref().unwrap().ops[0].data.as_slice())?,
            outer: Decode::decode(res.proof.as_ref().unwrap().ops[1].data.as_slice())?,
        };

        let query_path = "/store/acc/key".to_string();
        let query_data = [vec![1], res.value].concat();
        let res = rpc_client
            .abci_query(
                Some(query_path),
                query_data,
                Some((latest_height - 1).into()),
                true,
            )
            .await?;

        if res.proof.is_none() {
            return Err(OrgaError::App("No proof".to_string()));
        }
        if res.proof.as_ref().unwrap().ops.len() != 2 {
            return Err(OrgaError::App("Invalid proof op len".to_string()));
        }
        let base_account_proof = Proof {
            inner: Decode::decode(res.proof.as_ref().unwrap().ops[0].data.as_slice())?,
            outer: Decode::decode(res.proof.as_ref().unwrap().ops[1].data.as_slice())?,
        };
        if let Err(e) = (app_client)()
            .call(
                move |app| {
                    build_call!(app.relay_op_key(
                        client_id.clone(),
                        (latest_height_rev, latest_height.into()),
                        cons_key.clone().try_into().unwrap(),
                        op_addr_proof,
                        base_account_proof
                    ))
                },
                |app| build_call!(app.app_noop()),
            )
            .await
        {
            log::warn!("{}", e);
        } else {
            log::info!("Relayed an operator key");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use orga::{
        encoding::Decode,
        ibc::{ibc_rs::core::ics24_host::identifier::ClientId, Client},
    };

    use super::*;

    #[test]
    fn proof_ok() {
        let client_type = ibc::clients::ics07_tendermint::client_type();
        let client_id = ClientId::new(client_type.clone(), 123).unwrap();
        let height = Height::new(1, 234).unwrap();

        let mut client = Client::default();
        client.set_client_type(client_type);
        let cons_state = ibc::clients::ics07_tendermint::consensus_state::ConsensusState::new(
            CommitmentRoot::from_bytes(
                hex::decode("A692D537A95AC8B901044896E08767AACF441C0AD42AA08E770954787E108AB3")
                    .unwrap()
                    .as_slice(),
            ),
            orga::cosmrs::tendermint::Time::now(),
            Default::default(),
        );
        client
            .consensus_states
            .insert(height.into(), cons_state.into())
            .unwrap();

        let mut ibc = Ibc::default();
        ibc.ctx
            .clients
            .insert(client_id.clone().into(), client)
            .unwrap();

        let mut cosmos = Cosmos::default();
        let _ = cosmos
            .relay_op_key(
                &ibc,
                client_id.into(),
                (1, 234),
                base64::decode("6Nz09YGHzwWxjczG0IhK4Iv0qY2IcX0P/5KitvRXTUc=").unwrap().try_into().unwrap(),
                Proof {
                    inner: Adapter::decode(base64::decode("CooIChYiFMtaY7kej07o25NZQsviVyRjZHngEhTHwgHWY7VtdFjS8dOHOvpv48dXIRoOCAEYASABKgYAAoj3ogIiLggBEgcCBOak/wUgGiEg/L1P7GcEuAt3tWRMFWuAByiQOCRfXnUNvEZHra38kJoiLggBEgcECOak/wUgGiEg3EDxcvi9JC0yAf241+2BROtpz5w/5j72yZ0b4seIXnkiLAgBEigGEL6yoAYg0BUoS2+JjpUm5XfRVqSnImiMe1qcEecJIX48EbmKX20gIi4IARIHCiL8ivMIIBohIJkybuqRRK7SORDUUoky0CMQN3ZZcGRMlBNIWy5Q0i9nIiwIARIoDEq2pcMKIMqzR4D/tncYMpo3qmfmgOlCHycmmyeVbrT6NlgenKxJICIvCAESCA6OAbalwwogGiEgkQCG5HDE7E8+8RNhMBMq8cH0kWmwDrpGOHq1FulPIJgiLQgBEikQjAK2pcMKIPTCfRUi6SVx86EhMwk949typyo8Z+iVHUlr9Rn1D/SbICItCAESKRKoBJCd3AogthJ/IOstJ3Zc2/nWrYg5SY+Qn6dOqBOsJHlArD31jXYgIi0IARIpFIII2oDrCiAsKD2shFKzD9W7p0tTNw/LujIokFa5qnzngHQjh7M28CAiLQgBEikWiAzagOsKIK3xzs2buQxaZb8DcnmDM1OitMSRf+sm+NmzWDiRrRCTICIvCAESCBrWINqA6wogGiEgIk+JGIW+f5vtxYfDYbQv2Ga+K5Ipvl97H9YZ1+puwZ4iLwgBEggeiFPagOsKIBohIJUgd94DqMrR/bi2efHTQRGibmR78e8cZCaJP/RxuOV9IjAIARIJILy7AdqA6wogGiEgeKF9HJJXBOwwnSNfL7MpqCb+JsIUg2KyflFXod6OekciMAgBEgki3PsC2oDrCiAaISAzAk8YSIRO/BuDwcKBEYLubWfOYJ9P6hTovGooMoj9CCIwCAESCSb2+AbagOsKIBohIMX9NlOKH/b3pE4MXvYWNG1f1xrSJpsXd+3kA+8DTLvoIjAIARIJKKygENqA6wogGiEgKNh4fkcXz1b8I39xWpib6pdD2/VWQB335Tu84OsRryEiMAgBEgkqvI0e2oDrCiAaISC1QPv55tP9XUwzqPOY8IY+xlwyZQut2WXeBZ1XhH2BSSIwCAESCSyAjzjagOsKIBohIIzAX+VFI5PHeynHrorJSzZZaT1tIGoxcIdmL0rMsv6gIjAIARIJLqDMX9qA6wogGiEg4gy4OvLAtrVsUuZLRvA33edcEZnUY5hXQDPSc/gCc5UiMQgBEgoy1LnKAfKA6wogGiEgCfupskTR5uwBVIHCP1MmErwkxdpH4aHHtpzPfVyaeAw=").unwrap().as_slice()).unwrap(),
                    outer: Adapter::decode(base64::decode("CqYCCgdzdGFraW5nEiCUX//ov+S4Hz6HL9602rQ8O0up3EiHV1aUK0+d1Ie/iRoJCAEYASABKgEAIicIARIBARogblpHZ8qVV72aZFAB+TnkB4ZbaVcYQW9rm9tGXp1+6LYiJQgBEiEB2deWtCLjoYYrzc5agnNNqmFPt8nCsoJf7srWHc0OflYiJwgBEgEBGiB3afjCU6KtMVi72g/j0CF5GSQuDKydnca3WYr2qhIbqyIlCAESIQHWUu++vHDx0Ny/FCwlSIh9KlqSHzn5JqCoZNNg1aQHmiIlCAESIQFiHWPnyzFNkFEYmPsI1U1KCIlDjVnysJmHiKttB/OkvSInCAESAQEaIIo6bH1T1ByqB6pctqTyYll7xHtlOBpNvSj9jlPRr/iZ").unwrap().as_slice()).unwrap(),
                },
                Proof {
                    inner: Adapter::decode(base64::decode("Cr8JChUBx8IB1mO1bXRY0vHThzr6b+PHVyESoAEKIC9jb3Ntb3MuYXV0aC52MWJldGExLkJhc2VBY2NvdW50EnwKK29zbW8xY2xwcXI0bnJrNGtoZ2t4ajc4ZmN3d2g2ZGwzdXc0ZXBhc212bmoSRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiECfTKs7KDPbeiIlBmDreAlJuDieStaYcELTb/oCbagOtIY04EBIN4EGg4IARgBIAEqBgACrPjiCiIuCAESBwIErPjiCiAaISC0zYtnKGgp+Fv6/zgK448FNF9nDpE7Wo6+nVNC7eZucyIsCAESKAQGrPjiCiApnLHdr9XrhX0pwIf12puCc+/UcxyISysjLYfyAE+g8yAiLggBEgcGDqz44gogGiEg08ANiRA+u4kL76ki+qtngG3I9Nz6yTeQMa7zp2BO/UgiLAgBEigIFqz44gogQIDbNxIkW40Xj/nOdMOHucM1LelWR//LUYBwaLp5cMEgIi4IARIHCi6s+OIKIBohIBwZipWqbjqW3BRTIuWUrsLvNjCVYU0Iej96K/TLIwLDIi4IARIHDmjy8OoKIBohIP0s1I4EEp3oUMRg6p5+8IU766ZIWQC1fcuZ7M/X3uBUIi8IARIIEMAB8vDqCiAaISCm86iVzVfOI9oodrX7CgbywsDnbySVmfCrybTlTn2iUiIvCAESCBKwAvLw6gogGiEgeUq0y9PKbuZTKsWyQ4H+M7cCZ1gEoDCMFmBzV21dtoEiLwgBEggU1ATy8OoKIBohIOA6LqLAeTdMTJ7alfZ6utZuNJc/vt77kFiFPdbK2GNDIi8IARIIFogK8P/qCiAaISBIw6nPmGUFaeoGOWqRZIXzFvhulSNO9ZyWMHGhesEqpiItCAESKRjWEvD/6gogn9RapcSUmK7mPMniCrDBR9iisvL5xW+KcBxjc7QfxoMgIi0IARIpHMwn8P/qCiCW9uYUBQtWKOXynudhCczCPtV1LUR5zg/hG3fFVarsrSAiLwgBEggewFLw/+oKIBohIAKXW737Ep/LhYonaNPJ6MBzrdF/scK8OFILuyQsTgfcIi4IARIqIOKmAfD/6gognwoyjnbx7OU0hRNpSp+RAXjPXZhWw/JDqyEfg7KmPGQgIi4IARIqIqbJAvD/6gogHl+WnXBgJ6z8ExXQnr1bmTHnC7yGYbeblqBJABF3EesgIi4IARIqJNj1A+6A6woghKduU6A3QoG+nQNZpTgSfsKGovHS8kj5y+yTsGW9mL4gIjAIARIJJpr7B+6A6wogGiEgwssoO2m7jvdHerv3Ah+O/g8IUxUUgSx9mo8Ji5OZ+/8iMAgBEgko3vYP8IDrCiAaISCM6PqvM+y5Q6+WEmiYiRA2WwmEldM93Eru30gXz8Z6dCIwCAESCSqgsBzygOsKIBohIBmf2EZ/NMCXPmKI18qG92WrNAG+oRsNuXVou8uuQgtMIi4IARIqLJTVMfKA6wogTdUhfBcz6GwMd/yPFyDmuVg6mTVk7FHgzYOXwXNBK1AgIi4IARIqLojecfKA6wogIDIgKffpUBAC9R+CNUilqvMl3aNsgCGUx0nA18O1LzYg").unwrap().as_slice()).unwrap(),
                    outer: Adapter::decode(base64::decode("CqgCCgNhY2MSINEZyJuXGHO9e/7l/BfXyBtNNC1HqaZKWT+WwaRRdm1/GgkIARgBIAEqAQAiJwgBEgEBGiAmJLjLmjFGlQWG6FHRZabBsgRdIizlSVHmg5e8tDXZuyInCAESAQEaILD8zTSz99z8mtIXkoaP1C2nNqMxaadLnIUZqVJl1HhIIicIARIBARoghLjWH7uYlwxi7EtxUYVVeqOV/S7f8LUsmw8AJgdXQHMiJwgBEgEBGiBh6RCHqEWFxCM8X9CEU09AT1ABL3nEmlm+8N0EIRK0JyInCAESAQEaIHaa3mquD4HY2k9dzHkolr9no/ksOfpo92MKSeGX2gFrIicIARIBARogijpsfVPUHKoHqly2pPJiWXvEe2U4Gk29KP2OU9Gv+Jk=").unwrap().as_slice()).unwrap(),
                },
            );
    }
}
