#![allow(clippy::redundant_closure_call)] // TODO: fix bitcoin-script then remove this
#![allow(unused_imports)] // TODO

#[cfg(feature = "full")]
use crate::error::Error;
use crate::error::Result;
use bitcoin::secp256k1::Context as SecpContext;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::Verification;
#[cfg(feature = "full")]
use bitcoin::util::bip32::ChildNumber;
use bitcoin::Script;
use bitcoin_script::bitcoin_script as script;
#[cfg(feature = "full")]
use orga::collections::Map;
#[cfg(feature = "full")]
use orga::context::Context;
use orga::encoding::Encode;
use orga::orga;
#[cfg(feature = "full")]
use orga::plugins::Time;
#[cfg(feature = "full")]
use orga::plugins::Validators;
use orga::Error as OrgaError;

use super::threshold_sig::VersionedPubkey;
use super::ConsensusKey;
use super::Xpub;

/// The maximum age of a signatory set which can still be deposited into, in
/// seconds.
///
/// Deposits which pay to this signatory set which are relayed after this
/// interval will be ignored.
pub const MAX_DEPOSIT_AGE: u64 = 60 * 60 * 24 * 5;
/// The maximum number of signatories in a signatory set.
///
/// Signatory sets will be constructed by iterating over the validator set in
/// descending order of voting power, skipping any validators which have not
/// submitted a signatory xpub.
///
/// This constant should be chosen to balance the tradeoff between the
/// decentralization of the signatory set and the size of the resulting script
/// (affecting fees).
///
/// It is expected that future versions of this protocol will use aggregated
/// signatures, allowing for more signatories to be included without making an
/// impact on script size and fees.
pub const MAX_SIGNATORIES: u64 = 20;

/// A signatory in a signatory set, consisting of a public key and voting power.
#[orga]
#[derive(Clone, Debug, PartialOrd, PartialEq, Eq, Ord)]
pub struct Signatory {
    pub voting_power: u64,
    pub pubkey: VersionedPubkey,
}

/// Deterministically derive the public key for a signatory in a signatory set,
/// based on the current signatory set index.
pub fn derive_pubkey<T>(secp: &Secp256k1<T>, xpub: Xpub, sigset_index: u32) -> Result<PublicKey>
where
    T: SecpContext + Verification,
{
    Ok(xpub
        .derive_pub(
            secp,
            &[bitcoin::util::bip32::ChildNumber::from_normal_idx(
                sigset_index,
            )?],
        )?
        .public_key)
}

/// A signatory set is a set of signers who secure a UTXO in the network
/// reserve.
///
/// Bitcoin scripts can be generated from a signatory set, which can be used to
/// create a UTXO which can be only spent by a threshold of the signatories,
/// based on voting power.
#[orga]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatorySet {
    /// The time at which this signatory set was created, in seconds.
    ///
    /// This is used to enforce that deposits can not be relayed against old
    /// signatory sets (see [`MAX_DEPOSIT_AGE`]).
    pub create_time: u64,

    /// The total voting power of the validators participating in this set. If a
    /// validator has not submitted their signatory xpub, they will not be
    /// included.
    pub present_vp: u64,

    /// The total voting power of the validator set at the time this signatory
    /// set was created. This is used to ensure a sufficient quorum of
    /// validators have submitted a signatory xpub.
    pub possible_vp: u64,

    /// The index of this signatory set.
    pub index: u32,

    /// The signatories in this set, sorted by voting power.
    pub signatories: Vec<Signatory>,
}

impl SignatorySet {
    /// Creates a signatory set based on the current validator set.
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

    /// Inserts a signatory into the set. This may cause the signatory set to be
    /// unsorted.
    #[cfg(feature = "full")]
    fn insert(&mut self, signatory: Signatory) {
        self.present_vp += signatory.voting_power;
        self.signatories.push(signatory);
    }

    /// Sorts the signatories in the set by voting power, and truncates the set
    /// to the maximum number of signatories.
    #[cfg(feature = "full")]
    fn sort_and_truncate(&mut self) {
        self.signatories.sort_by(|a, b| b.cmp(a));

        if self.signatories.len() as u64 > MAX_SIGNATORIES {
            for removed in self.signatories.drain(MAX_SIGNATORIES as usize..) {
                self.present_vp -= removed.voting_power;
            }
        }
    }

    /// The voting power threshold required to spend outputs secured by this
    /// signatory set.
    pub fn signature_threshold(&self, (numerator, denominator): (u64, u64)) -> u64 {
        ((self.present_vp as u128) * numerator as u128 / denominator as u128) as u64
    }

    /// The quorum threshold required for the signatory set to be valid.
    pub fn quorum_threshold(&self) -> u64 {
        self.possible_vp / 2
    }

    /// The total amount of voting power of validators participating in the set.
    /// Validators who have not submitted a signatory xpub are not included.
    pub fn present_vp(&self) -> u64 {
        self.present_vp
    }

    /// The total amount of voting power of the validator set at the time this
    /// signatory set was created. This is used to ensure a sufficient quorum of
    /// validators have submitted a signatory xpub.
    pub fn possible_vp(&self) -> u64 {
        self.possible_vp
    }

    /// Whether the signatory set has a sufficient quorum of validators who have
    /// submitted a signatory xpub.
    ///
    /// If this returns `false`, this signatory set should not be used to secure
    /// a UTXO.
    pub fn has_quorum(&self) -> bool {
        self.present_vp >= self.quorum_threshold()
    }

    /// The number of signatories in the set.
    // TODO: remove this attribute, not sure why clippy is complaining when is_empty is defined
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.signatories.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds a Bitcoin script which can be used to spend a UTXO secured by
    /// this signatory set.
    ///
    /// This script is essentially a weighted multisig script, where each
    /// signatory has a weight equal to their voting power. It is specified in
    /// the input witness when the UTXO is spent. The output contains a hash of
    /// this script, since it is a pay-to-witness-script-hash (P2WSH) output.
    pub fn redeem_script(&self, dest: &[u8], threshold: (u64, u64)) -> Result<Script> {
        // We will truncate voting power values to 23 bits, to reduce the amount
        // of bytes used in the resulting encoded script. In practice, this
        // should be enough precision for effective voting power threshold
        // checking. We use 23 bits since Bitcoin script reserves one bit as the
        // sign bit, making our resulting integer value use 3 bytes. The value
        // returned here is the number of bits of precision to remove from our
        // 64-bit voting power values.
        let truncation = self.get_truncation(23);

        let mut iter = self.signatories.iter();

        // First signatory
        let signatory = iter.next().ok_or_else(|| {
            OrgaError::App("Cannot create redeem script for empty signatory set".to_string())
        })?;
        let truncated_voting_power = signatory.voting_power >> truncation;
        // Push the pubkey onto the stack, check the signature against it, and
        // leave the voting power on the stack if the signature was valid,
        // otherwise leave 0 (this number will be an accumulator of voting power
        // which had valid signatures, and will be added to as we check the
        // remaining signatures).
        let script = script! {
            <signatory.pubkey.as_slice()> OP_CHECKSIG
            OP_IF
                <truncated_voting_power as i64>
            OP_ELSE
                0
            OP_ENDIF
        };
        let mut bytes = script.into_bytes();

        // All other signatories
        for signatory in iter {
            let truncated_voting_power = signatory.voting_power >> truncation;
            // Swap to move the current voting power accumulator down the stack
            // (leaving the next signature at the top of the stack), push the
            // pubkey onto the stack, check the signature against it, and add to
            // the voting power accumulator if the signature was valid.
            let script = script! {
                OP_SWAP
                <signatory.pubkey.as_slice()> OP_CHECKSIG
                OP_IF
                    <truncated_voting_power as i64> OP_ADD
                OP_ENDIF
            };
            bytes.extend(&script.into_bytes());
        }

        // Threshold check
        let truncated_threshold = self.signature_threshold(threshold) >> truncation;
        // Check that accumulator of voting power which had valid signatures
        // (now a final sum) is greater than the threshold.
        let script = script! {
            <truncated_threshold as i64> OP_GREATERTHAN
        };
        bytes.extend(&script.into_bytes());

        // Depositor data commitment
        let data = &dest.encode()?[..];
        // Add a commitment of arbitrary data so that deposits can be tied to a
        // specific destination, then remove it from the stack so that the final
        // value on the stack is the threshold check result.
        let script = script!(<data> OP_DROP);
        bytes.extend(&script.into_bytes());

        Ok(bytes.into())
    }

    /// Hashes the weighted multisig redeem script to create a P2WSH output
    /// script, which is what is used as the script pubkey in deposit outputs
    /// and reserve outputs.
    pub fn output_script(&self, dest: &[u8], threshold: (u64, u64)) -> Result<Script> {
        Ok(self.redeem_script(dest, threshold)?.to_v0_p2wsh())
    }

    /// Calculates the number of bits of precision to remove from voting power
    /// values in order to have a maximum of `target_precision` bits of
    /// precision.
    fn get_truncation(&self, target_precision: u32) -> u32 {
        let vp_bits = u64::BITS - self.present_vp.leading_zeros();
        vp_bits.saturating_sub(target_precision)
    }

    /// The time at which this signatory set was created, in seconds.
    pub fn create_time(&self) -> u64 {
        self.create_time
    }

    /// The time at which this signatory set will expire, in seconds.
    pub fn deposit_timeout(&self) -> u64 {
        self.create_time + MAX_DEPOSIT_AGE
    }

    /// The index of this signatory set.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// An iterator over the signatories in this set.
    pub fn iter(&self) -> impl Iterator<Item = &Signatory> {
        self.signatories.iter()
    }

    /// The estimated size of a witness containing the redeem script and
    /// signatures for this signatory set, in virtual bytes.
    ///
    /// This represents the worst-case, where there is a signature for each
    /// signatory. In practice, we could trim this down by removing signatures
    /// for signatories beyond the threshold, but for fee estimation we err on
    /// the side of paying too much.
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
