use super::{Adapter, Config, Encrypted};
use crate::bitcoin::threshold_sig::Pubkey;
use ed::{Decode, Encode};
use frost_secp256k1_tr::keys::{dkg::*, PublicKeyPackage};
use orga::encoding::LengthVec;
use orga::query::Query;
use orga::{collections::Map, orga};
use orga::{Error, Result};
use serde::{Deserialize, Serialize};

/// The state of the DKG process for a group.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, Encode, Decode,
)]
pub enum DkgState {
    /// The group's participants need to complete
    /// [`frost_secp256k1_tr::keys::dkg::part1`].
    #[default]
    Round1,
    /// The group's participants need to complete
    /// [`frost_secp256k1_tr::keys::dkg::part2`].
    Round2,
    /// The group's participants need to complete
    /// [`frost_secp256k1_tr::keys::dkg::part3`] and attest to the public key
    /// package.
    Attesting,
    /// The DKG process is complete and a group public key is available.
    Complete,
}

impl Query for DkgState {
    type Query = ();

    fn query(&self, _query: Self::Query) -> Result<()> {
        Ok(())
    }
}

/// The state of the DKG process for a group.
#[orga]
pub struct Dkg {
    /// The number of participants in the group.
    participants: u16,
    /// The round 1 packages submitted by participants.
    round1: Map<u16, Adapter<round1::Package>>,
    round1_pubkeys: Map<u16, Pubkey>,
    /// The number of round 1 packages submitted by participants.
    round1_len: u16,
    /// The round 2 packages submitted by participants.
    round2: Map<u16, Map<u16, Encrypted<Adapter<round2::Package>>>>,
    /// The number of round 2 packages submitted by participants.
    round2_len: u16,
    /// The group public key, if the DKG process is complete.
    group_pubkey: Option<Adapter<PublicKeyPackage>>,
    /// The participants who have attested to the public key package.
    attested: Map<u16, ()>,
    /// The number of participants who have attested to the public key package.
    attested_len: u16,
}

impl Dkg {
    /// Creates a new [`Dkg`] from the provided [`Config`].
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            participants: config.total_shares(),
            ..Default::default()
        })
    }

    /// Returns the current state of the DKG process.
    pub fn state(&self) -> DkgState {
        if self.round1_len < self.participants {
            return DkgState::Round1;
        }

        if self.round2_len < self.participants {
            return DkgState::Round2;
        }

        if self.attested_len < self.participants {
            return DkgState::Attesting;
        }

        DkgState::Complete
    }

    /// Submits a round 1 package for the provided participant.
    pub fn submit_round1(
        &mut self,
        participant: u16,
        package: Adapter<round1::Package>,
        comm_pubkey: Pubkey,
    ) -> Result<()> {
        if self.state() != DkgState::Round1 {
            return Err(Error::App("Round 1 already complete".to_string()));
        }
        if self.round1.contains_key(participant)? {
            return Err(Error::App("Round 1 package already submitted".to_string()));
        }
        self.round1.insert(participant, package)?;
        self.round1_pubkeys.insert(participant, comm_pubkey)?;
        self.round1_len += 1;

        Ok(())
    }

    /// Submits round 2 packages for the provided participant.
    pub fn submit_round2(
        &mut self,
        participant: u16,
        packages: LengthVec<u16, (u16, Encrypted<Adapter<round2::Package>>)>,
    ) -> Result<()> {
        if self.state() != DkgState::Round2 {
            return Err(Error::App("Not currently in round 2".to_string()));
        }
        if self.round2.contains_key(participant)? {
            return Err(Error::App("Round 2 packages already submitted".to_string()));
        }

        let mut map = self.round2.entry(participant)?.or_default()?;

        let packages: Vec<_> = packages.into();
        for (receiver, package) in packages {
            map.insert(receiver, package)?;
        }
        self.round2_len += 1;

        Ok(())
    }

    /// Attests to the public key package for the provided participant.
    ///
    /// Since 100% participation is required for the DKG process to complete
    /// successfully, this method will fail if the participant has already
    /// attested to a different [`PublicKeyPackage`] than the one provided.
    pub fn attest_pubkey_package(
        &mut self,
        participant: u16,
        package: Adapter<PublicKeyPackage>,
    ) -> Result<()> {
        if self.attested.contains_key(participant)? {
            return Err(Error::App("Participant already attested".to_string()));
        }
        if let Some(Adapter { inner }) = &self.group_pubkey {
            if inner != &package.inner {
                return Err(Error::App(
                    "Participants computed different pubkeys".to_string(),
                ));
            }
        } else {
            self.group_pubkey = Some(package);
        }

        self.attested_len += 1;

        Ok(())
    }

    /// Returns the group public key, if the DKG process is complete.
    pub fn group_pubkey(&self) -> Result<Option<Adapter<PublicKeyPackage>>> {
        if self.state() == DkgState::Complete {
            Ok(self.group_pubkey.clone())
        } else {
            Ok(None)
        }
    }

    /// Returns the round 1 packages submitted by participants.
    pub fn round1_packages(&self) -> Result<Vec<(u16, (round1::Package, Pubkey))>> {
        let mut packages = vec![];
        for i in 0..self.participants {
            let package = self
                .round1
                .get(i)?
                .ok_or(Error::App("Round 1 package not found".to_string()))?;
            let comm_pubkey = self
                .round1_pubkeys
                .get(i)?
                .ok_or(Error::App("Communication public key not found".to_string()))?;
            packages.push((i, (package.inner.clone(), *comm_pubkey)));
        }

        Ok(packages)
    }

    /// Returns the round 2 packages submitted by participants intended for
    /// delivery to the provided participant index (`receiver`).
    pub fn round2_packages(
        &self,
        receiver: u16,
    ) -> Result<Vec<(u16, Encrypted<Adapter<round2::Package>>)>> {
        let mut packages = vec![];
        for sender in 0..self.participants {
            if let Some(package_bundle) = self.round2.get(sender)? {
                if let Some(package) = package_bundle.get(receiver)? {
                    packages.push((sender, package.clone()));
                }
            }
        }

        Ok(packages)
    }

    /// Returns whether the provided participant is required to take some action
    /// in the DKG process.
    pub fn requires_action_from(&self, participant: u16) -> Result<bool> {
        match self.state() {
            DkgState::Round1 => self.absent(participant),
            DkgState::Round2 => Ok(!self.round2.contains_key(participant)?),
            DkgState::Attesting => Ok(!self.attested.contains_key(participant)?),
            DkgState::Complete => Ok(false),
        }
    }

    /// Returns whether the provided participant is absent from the first round
    /// of this group's DKG process.
    pub fn absent(&self, participant: u16) -> Result<bool> {
        Ok(!self.round1.contains_key(participant)?)
    }
}
