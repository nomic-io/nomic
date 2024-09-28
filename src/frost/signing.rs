use ed::{Decode, Encode};
use frost_secp256k1_tr::keys::PublicKeyPackage;
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{aggregate, Signature, SigningTarget};
use frost_secp256k1_tr::{round1::SigningCommitments, SigningPackage};
use frost_secp256k1_tr::{Error as FrostError, SigningParameters};
use orga::query::Query;
use orga::Error;
use serde::{Deserialize, Serialize};

use orga::{collections::Map, encoding::LengthVec, orga, Result};

use super::{assemble_by_identifier, Adapter, Config};

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, Encode, Decode,
)]
pub enum SigningState {
    #[default]
    Round1,
    Round2,
    Complete,
}

impl Query for SigningState {
    type Query = ();

    fn query(&self, _query: Self::Query) -> Result<()> {
        Ok(())
    }
}

#[orga]
pub struct Signing {
    config: Config,
    message: LengthVec<u16, u8>,
    commitments: Map<(u32, u16), Adapter<SigningCommitments>>,
    commitments_len: u16,
    pub(crate) signing_package: Option<Adapter<SigningPackage>>,
    sig_shares: Map<(u32, u16), Adapter<SignatureShare>>,
    sig_shares_len: u16,
    pub signature: Option<Adapter<Signature>>,
    pub iteration: u32,
    pub iteration_start_seconds: i64,
}

impl Signing {
    pub fn new(config: Config, message: LengthVec<u16, u8>, now: i64) -> Self {
        Self {
            config,
            message,
            iteration_start_seconds: now,
            ..Default::default()
        }
    }

    pub fn advance_with_timeout(&mut self, now: i64, timeout: i64) -> Result<()> {
        if now > self.iteration_start_seconds + timeout && self.state() != SigningState::Complete {
            self.next_iteration(now)?;
        }

        Ok(())
    }

    pub fn next_iteration(&mut self, now: i64) -> Result<()> {
        self.iteration += 1;
        self.commitments_len = 0;
        self.sig_shares_len = 0;
        self.signing_package = None;
        self.iteration_start_seconds = now;

        Ok(())
    }

    pub fn requires_action_from(&self, participant: u16) -> Result<bool> {
        if self.state() == SigningState::Round1 {
            return Ok(!self
                .commitments
                .contains_key((self.iteration, participant))?);
        }
        if self.state() == SigningState::Round2 {
            return Ok(!self
                .sig_shares
                .contains_key((self.iteration, participant))?);
        }

        Ok(false)
    }

    pub fn state(&self) -> SigningState {
        if self.commitments_len < self.config.threshold {
            return SigningState::Round1;
        }
        if self.sig_shares_len < self.config.threshold {
            return SigningState::Round2;
        }

        SigningState::Complete
    }

    pub fn submit_commitments(
        &mut self,
        iteration: u32,
        participant: u16,
        commitments: Adapter<SigningCommitments>,
    ) -> Result<()> {
        if self.state() != SigningState::Round1 {
            return Err(Error::App("Not in round 1".to_string()));
        }
        if iteration != self.iteration {
            return Err(Error::App("Invalid iteration".to_string()));
        }
        if self.commitments.contains_key((iteration, participant))? {
            return Err(Error::App("Commitment already submitted".to_string()));
        }

        self.commitments
            .insert((iteration, participant), commitments)?;
        self.commitments_len += 1;

        if self.state() == SigningState::Round2 {
            self.build_signing_package()?;
        }

        Ok(())
    }

    pub fn submit_sig_share(
        &mut self,
        iteration: u32,
        participant: u16,
        share: Adapter<SignatureShare>,
        pubkey_package: &PublicKeyPackage,
    ) -> Result<()> {
        if self.state() != SigningState::Round2 {
            return Err(Error::App("Not in round 2".to_string()));
        }
        if self.sig_shares.contains_key((iteration, participant))? {
            return Err(Error::App("Signature share already submitted".to_string()));
        }

        if !self.commitments.contains_key((iteration, participant))? {
            return Err(Error::App(
                "Participant not included in this round".to_string(),
            ));
        }

        self.sig_shares.insert((iteration, participant), share)?;
        self.sig_shares_len += 1;
        if self.state() == SigningState::Complete {
            self.aggregate_signature(pubkey_package)?;
        }

        Ok(())
    }

    fn build_signing_package(&mut self) -> Result<()> {
        let mut commitments = vec![];
        if self.signing_package.is_some() {
            return Err(Error::App("Signing package already built".to_string()));
        }

        for entry in self.commitments.iter()? {
            let (k, v) = entry?;
            if k.0 != self.iteration {
                continue;
            }
            commitments.push((k.1, v.inner));
        }
        let commitments = assemble_by_identifier(commitments.into_iter());
        let sig_params = SigningParameters {
            tapscript_merkle_root: None,
        };

        let sig_target = SigningTarget::new(self.message.as_slice(), sig_params);
        let signing_package = SigningPackage::new(commitments, sig_target);
        self.signing_package.replace(Adapter {
            inner: signing_package,
        });

        Ok(())
    }

    fn aggregate_signature(&mut self, pubkey_package: &PublicKeyPackage) -> Result<()> {
        let Some(Adapter {
            inner: signing_package,
        }) = &self.signing_package
        else {
            return Err(Error::App("Signing package not built".to_string()));
        };

        if self.signature.is_some() {
            return Err(Error::App("Signature already aggregated".to_string()));
        }

        let mut sig_shares = vec![];
        for entry in self.sig_shares.iter()? {
            let (k, v) = entry?;
            if k.0 != self.iteration {
                continue;
            }
            sig_shares.push((k.1, v.inner));
        }

        let sig_shares = assemble_by_identifier(sig_shares.into_iter());

        let signature = match aggregate(signing_package, &sig_shares, pubkey_package) {
            Ok(signature) => signature,
            Err(FrostError::InvalidSignatureShare { culprit }) => {
                return Err(Error::App(format!(
                    "Invalid signature share from {:?}",
                    culprit
                )));
            }
            Err(e) => return Err(Error::App(format!("Failed to aggregate signature: {}", e))),
        };

        self.signature.replace(Adapter { inner: signature });

        Ok(())
    }
}
