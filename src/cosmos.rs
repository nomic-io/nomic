use crate::{bitcoin::threshold_sig::Pubkey, error::Result};
use ibc::{
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
    encoding::LengthVec,
    ibc::ibc_rs::{self as ibc},
    ibc::{ibc_rs::Height, ClientId, Ibc},
    orga, Error as OrgaError,
};
use proto::traits::{Message, MessageExt};

#[orga]
pub struct Cosmos {
    pub chains: Map<ClientId, Chain>,
}

#[orga]
impl Cosmos {
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

        // TODO: verify consensus key is in validator set

        op_addr.verify(root, "staking")?;
        acc.verify(root, "acc")?;

        let calc_op_addr = tmhash(cons_key.as_slice());
        if op_addr.key()? != &vec![&[0x22, 0x14], calc_op_addr.as_slice()].concat() {
            return Err(OrgaError::App(
                "Consensus address does not match consensus key".to_string(),
            )
            .into());
        }

        if acc.key()? != &vec![&[0x01], op_addr.value()?.as_slice()].concat() {
            return Err(
                OrgaError::App("Account does not match operator address".to_string()).into(),
            );
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
        )?;

        let mut chain = self.chains.entry(client_id)?.or_default()?;
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

pub struct Proof {
    pub inner: Adapter<ics23::CommitmentProof>,
    pub outer: Adapter<ics23::CommitmentProof>,
}

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
        let proof = self
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
        let proof = self
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
    pub op_keys_by_cons: Map<LengthVec<u8, u8>, Pubkey>,
}

#[orga]
impl Chain {
    pub fn to_btc_script(&self) -> Result<bitcoin::Script> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use orga::{
        encoding::Decode,
        ibc::{
            ibc_rs::core::{
                ics02_client::client_type::ClientType, ics24_host::identifier::ClientId,
            },
            Client,
        },
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
            .insert(height.clone().into(), cons_state.into())
            .unwrap();

        let mut ibc = Ibc::default();
        ibc.clients
            .insert(client_id.clone().into(), client)
            .unwrap();

        let mut cosmos = Cosmos::default();
        cosmos
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
            )
            .unwrap();
    }
}
