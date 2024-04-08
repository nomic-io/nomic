use super::{Adapter, Config};
use ed::{Decode, Encode};
use frost_secp256k1_tr::keys::{dkg::*, PublicKeyPackage};
use orga::encoding::LengthVec;
use orga::query::Query;
use orga::{collections::Map, orga};
use orga::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, Encode, Decode,
)]
pub enum DkgState {
    #[default]
    Round1,
    Round2,
    Attesting,
    Complete,
}

impl Query for DkgState {
    type Query = ();

    fn query(&self, _query: Self::Query) -> Result<()> {
        Ok(())
    }
}

#[orga]
pub struct Dkg {
    participants: u16,
    round1: Map<u16, Adapter<round1::Package>>,
    round1_len: u16,
    round2: Map<u16, Map<u16, Adapter<round2::Package>>>,
    round2_len: u16,
    group_pubkey: Option<Adapter<PublicKeyPackage>>,
    attested: Map<u16, ()>,
    attested_len: u16,
}

impl Dkg {
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            participants: config.total_shares(),
            ..Default::default()
        })
    }

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

    pub fn submit_round1(
        &mut self,
        participant: u16,
        package: Adapter<round1::Package>,
    ) -> Result<()> {
        if self.state() != DkgState::Round1 {
            return Err(Error::App("Round 1 already complete".to_string()));
        }
        if self.round1.contains_key(participant)? {
            return Err(Error::App("Round 1 package already submitted".to_string()));
        }
        self.round1.insert(participant, package)?;
        self.round1_len += 1;

        Ok(())
    }

    pub fn submit_round2(
        &mut self,
        participant: u16,
        packages: LengthVec<u16, (u16, Adapter<round2::Package>)>,
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

    pub fn group_pubkey(&self) -> Result<Option<Adapter<PublicKeyPackage>>> {
        if self.state() == DkgState::Complete {
            Ok(self.group_pubkey.clone())
        } else {
            Ok(None)
        }
    }

    pub fn round1_packages(&self) -> Result<Vec<(u16, round1::Package)>> {
        let mut packages = vec![];
        for i in 0..self.participants {
            if let Some(package) = self.round1.get(i)? {
                packages.push((i, package.inner.clone()));
            }
        }

        Ok(packages)
    }

    pub fn round2_packages(&self, receiver: u16) -> Result<Vec<(u16, round2::Package)>> {
        let mut packages = vec![];
        for sender in 0..self.participants {
            if let Some(package_bundle) = self.round2.get(sender)? {
                if let Some(package) = package_bundle.get(receiver)? {
                    packages.push((sender, package.inner.clone()));
                }
            }
        }

        Ok(packages)
    }

    pub fn requires_action_from(&self, participant: u16) -> Result<bool> {
        match self.state() {
            DkgState::Round1 => self.absent(participant),
            DkgState::Round2 => Ok(!self.round2.contains_key(participant)?),
            DkgState::Attesting => Ok(!self.attested.contains_key(participant)?),
            DkgState::Complete => Ok(false),
        }
    }

    pub fn absent(&self, participant: u16) -> Result<bool> {
        Ok(!self.round1.contains_key(participant)?)
    }
}
