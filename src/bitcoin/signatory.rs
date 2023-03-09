#![allow(clippy::redundant_closure_call)] // TODO: fix bitcoin-script then remove this

use crate::error::{Error, Result};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::Script;
use bitcoin_script::bitcoin_script as script;
use orga::collections::Map;
use orga::context::Context;
use orga::encoding::Encode;
use orga::orga;
use orga::plugins::Time;
#[cfg(feature = "full")]
use orga::plugins::Validators;
use orga::Error as OrgaError;

use super::threshold_sig::Pubkey;
use super::ConsensusKey;
use super::Xpub;

pub const MAX_DEPOSIT_AGE: u64 = 60 * 60 * 24 * 5;
pub const MAX_SIGNATORIES: u64 = 20;

#[orga]
#[derive(Clone, Debug, PartialOrd, PartialEq, Eq, Ord)]
pub struct Signatory {
    pub voting_power: u64,
    pub pubkey: Pubkey,
}

#[orga]
#[derive(Clone, Debug)]
pub struct SignatorySet {
    create_time: u64,
    present_vp: u64,
    possible_vp: u64,
    index: u32,
    signatories: Vec<Signatory>,
}

impl SignatorySet {
    #[cfg(feature = "full")]
    pub fn from_validator_ctx(index: u32, sig_keys: &Map<ConsensusKey, Xpub>) -> Result<Self> {
        let time: &mut Time = Context::resolve()
            .ok_or_else(|| OrgaError::App("No time context found".to_string()))?;

        let mut sigset = SignatorySet {
            create_time: time.seconds as u64,
            present_vp: 0,
            possible_vp: 0,
            index,
            signatories: vec![],
        };

        let validators: &mut Validators = Context::resolve().ok_or_else(|| {
            Error::Orga(orga::Error::App("No validator context found".to_string()))
        })?;
        let val_set = validators.current_set();
        let val_iter = val_set
            .as_ref()
            .ok_or_else(|| {
                Error::Orga(orga::Error::App(
                    "Could not access validator set".to_string(),
                ))
            })?
            .iter()?;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let derive_path = [ChildNumber::from_normal_idx(index)?];

        for entry in val_iter {
            let entry = entry?;
            let consensus_key = entry.pubkey;

            sigset.possible_vp += entry.power;

            let signatory_key = match sig_keys.get(consensus_key)? {
                Some(xpub) => xpub.derive_pub(&secp, &derive_path)?.public_key.into(),
                None => continue,
            };

            let signatory = Signatory {
                voting_power: entry.power,
                pubkey: signatory_key,
            };
            sigset.insert(signatory);
        }

        sigset.sort_and_truncate();

        Ok(sigset)
    }

    fn insert(&mut self, signatory: Signatory) {
        self.present_vp += signatory.voting_power;
        self.signatories.push(signatory);
    }

    fn sort_and_truncate(&mut self) {
        self.signatories.sort_by(|a, b| b.cmp(a));

        if self.signatories.len() as u64 > MAX_SIGNATORIES {
            for removed in self.signatories.drain(MAX_SIGNATORIES as usize..) {
                self.present_vp -= removed.voting_power;
            }
        }
    }

    pub fn signature_threshold(&self) -> u64 {
        ((self.present_vp as u128) * 2 / 3) as u64
    }

    pub fn quorum_threshold(&self) -> u64 {
        self.possible_vp / 2
    }

    pub fn present_vp(&self) -> u64 {
        self.present_vp
    }

    pub fn possible_vp(&self) -> u64 {
        self.possible_vp
    }

    pub fn has_quorum(&self) -> bool {
        self.present_vp >= self.quorum_threshold()
    }

    // TODO: remove this attribute, not sure why clippy is complaining when is_empty is defined
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.signatories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn redeem_script(&self, dest: &[u8]) -> Result<Script> {
        let truncation = self.get_truncation(23);

        let mut iter = self.signatories.iter();

        // first signatory
        let signatory = iter.next().ok_or_else(|| {
            OrgaError::App("Cannot create redeem script for empty signatory set".to_string())
        })?;
        let truncated_voting_power = signatory.voting_power >> truncation;
        let script = script! {
            <signatory.pubkey.as_slice()> OP_CHECKSIG
            OP_IF
                <truncated_voting_power as i64>
            OP_ELSE
                0
            OP_ENDIF
        };
        let mut bytes = script.into_bytes();

        // all other signatories
        for signatory in iter {
            let truncated_voting_power = signatory.voting_power >> truncation;
            let script = script! {
                OP_SWAP
                <signatory.pubkey.as_slice()> OP_CHECKSIG
                OP_IF
                    <truncated_voting_power as i64> OP_ADD
                OP_ENDIF
            };
            bytes.extend(&script.into_bytes());
        }

        // > threshold check
        let truncated_threshold = self.signature_threshold() >> truncation;
        let script = script! {
            <truncated_threshold as i64> OP_GREATERTHAN
        };
        bytes.extend(&script.into_bytes());

        // depositor data commitment
        let data = &dest.encode()?[..];
        let script = script!(<data> OP_DROP);
        bytes.extend(&script.into_bytes());

        Ok(bytes.into())
    }

    pub fn output_script(&self, dest: &[u8]) -> Result<Script> {
        Ok(self.redeem_script(dest)?.to_v0_p2wsh())
    }

    fn get_truncation(&self, target_precision: u32) -> u32 {
        let vp_bits = u64::BITS - self.present_vp.leading_zeros();
        vp_bits.saturating_sub(target_precision)
    }

    pub fn create_time(&self) -> u64 {
        self.create_time
    }

    pub fn deposit_timeout(&self) -> u64 {
        self.create_time + MAX_DEPOSIT_AGE
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn iter(&self) -> impl Iterator<Item = &Signatory> {
        self.signatories.iter()
    }

    pub fn est_witness_vsize(&self) -> u64 {
        self.signatories.len() as u64 * 79 + 39
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // #[test]
    // #[should_panic(expected = "Cannot build script for empty signatory set")]
    // fn redeem_script_empty() {
    //     let sigs = SignatorySet::new();
    //     sigs.redeem_script(vec![1, 2, 3]);
    // }

    // #[test]
    // fn redeem_script_fixture() {
    //     let mut signatories = SignatorySet::new();
    //     signatories.set(mock_signatory(1, 5_000_000));
    //     signatories.set(mock_signatory(2, 15_000_000));
    //     signatories.set(mock_signatory(3, 20_000_000));
    //     signatories.set(mock_signatory(4, 60_000_000));
    //     let script = redeem_script(&signatories, vec![1, 2, 3]);

    //     assert_eq!(
    //         script,
    //         script! {
    //             0x03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b OP_CHECKSIG
    //             OP_IF
    //                 3750000
    //             OP_ELSE
    //                 0
    //             OP_ENDIF

    //             OP_SWAP
    //             0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 OP_CHECKSIG
    //             OP_IF
    //                 1250000 OP_ADD
    //             OP_ENDIF

    //             OP_SWAP
    //             0x024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 OP_CHECKSIG
    //             OP_IF
    //                 937500 OP_ADD
    //             OP_ENDIF

    //             OP_SWAP
    //             0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f OP_CHECKSIG
    //             OP_IF
    //                 312500 OP_ADD
    //             OP_ENDIF

    //             4166666 OP_GREATERTHAN

    //             0x010203 OP_DROP
    //         }
    //     );

    //     assert_eq!(
    //         script.into_bytes(),
    //         vec![
    //             33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113, 8, 95, 47, 16, 225,
    //             199, 165, 147, 228, 224, 48, 239, 181, 184, 114, 28, 229, 91, 11, 172, 99, 3, 112,
    //             56, 57, 103, 0, 104, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50,
    //             39, 200, 103, 172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197, 189, 189, 203,
    //             31, 227, 55, 172, 99, 3, 208, 18, 19, 147, 104, 124, 33, 2, 77, 75, 108, 209, 54,
    //             16, 50, 202, 155, 210, 174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66,
    //             51, 116, 196, 81, 167, 37, 77, 7, 102, 172, 99, 3, 28, 78, 14, 147, 104, 124, 33,
    //             3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30,
    //             24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, 172, 99, 3, 180, 196,
    //             4, 147, 104, 3, 10, 148, 63, 160, 3, 1, 2, 3, 117
    //         ]
    //     );
    // }

    // #[test]
    // fn output_script_fixture() {
    //     let script = output_script(&mock_signatory_set(4), vec![1, 2, 3]);

    //     assert_eq!(
    //         script,
    //         bitcoin_script! {
    //             0 0x73155f74ccee5011c3c62776c15abcc0d4e19eb3e1764609cf3e90e7cb81db4a
    //         }
    //     );
    //     assert_eq!(
    //         script.into_bytes(),
    //         vec![
    //             0, 32, 115, 21, 95, 116, 204, 238, 80, 17, 195, 198, 39, 118, 193, 90, 188, 192,
    //             212, 225, 158, 179, 225, 118, 70, 9, 207, 62, 144, 231, 203, 129, 219, 74
    //         ]
    //     );
    // }

    // #[test]
    // fn truncation() {
    //     // total less than target precision (10, 4 bits)
    //     let mut signatories = SignatorySet::new();
    //     signatories.set(mock_signatory(1, 10));
    //     assert_eq!(get_truncation(&signatories, 23), 0);

    //     // total greater than target precision (100M, 27 bits)
    //     let mut signatories = SignatorySet::new();
    //     signatories.set(mock_signatory(1, 100_000_000));
    //     assert_eq!(get_truncation(&signatories, 23), 4);
    // }
}
