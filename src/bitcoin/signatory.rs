#![allow(clippy::redundant_closure_call)] // TODO: fix bitcoin-script then remove this
#![allow(unused_imports)] // TODO

use std::cmp::Ordering;

use crate::bitcoin::threshold_sig::Pubkey;
use crate::error::Error;
use crate::error::Result;
use bitcoin::blockdata::opcodes::all::{
    OP_ADD, OP_CHECKSIG, OP_DROP, OP_ELSE, OP_ENDIF, OP_GREATERTHAN, OP_IF, OP_SWAP,
};
use bitcoin::blockdata::opcodes::{self, OP_FALSE};
use bitcoin::blockdata::script::{read_scriptint, Instruction, Instructions};
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

use super::ConsensusKey;
use super::Xpub;

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
    pub pubkey: Pubkey,
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

    pub fn from_script(
        script: &bitcoin::Script,
        threshold_ratio: (u64, u64),
    ) -> Result<(Self, Vec<u8>)> {
        trait Iter<'a> = Iterator<
            Item = std::result::Result<Instruction<'a>, bitcoin::blockdata::script::Error>,
        >;

        fn take_instruction<'a>(ins: &mut impl Iter<'a>) -> Result<Instruction<'a>> {
            ins.next()
                .ok_or_else(|| orga::Error::App("Unexpected end of script".to_string()))?
                .map_err(|_| orga::Error::App("Failed to read script".to_string()).into())
        }

        fn take_bytes<'a>(ins: &mut impl Iter<'a>) -> Result<&'a [u8]> {
            let instruction = take_instruction(ins)?;

            let Instruction::PushBytes(bytes) = instruction else {
                return Err(Error::Orga(orga::Error::App(
                    "Expected OP_PUSHBYTES".to_string(),
                )));
            };

            Ok(bytes)
        }

        fn take_key<'a>(ins: &mut impl Iter<'a>) -> Result<Pubkey> {
            let bytes = take_bytes(ins)?;

            if bytes.len() != 33 {
                return Err(Error::Orga(orga::Error::App(
                    "Expected 33 bytes".to_string(),
                )));
            }

            Ok(Pubkey::try_from_slice(bytes)?)
        }

        fn take_number<'a>(ins: &mut impl Iter<'a>) -> Result<i64> {
            let bytes = take_bytes(ins)?;
            read_scriptint(bytes)
                .map_err(|_| orga::Error::App("Failed to read scriptint".to_string()).into())
        }

        fn take_op<'a>(ins: &mut impl Iter<'a>, expected_op: opcodes::All) -> Result<opcodes::All> {
            let instruction = take_instruction(ins)?;

            let op = match instruction {
                Instruction::Op(op) => op,
                Instruction::PushBytes(&[]) => OP_FALSE,
                _ => {
                    return Err(Error::Orga(orga::Error::App(format!(
                        "Expected {:?}",
                        expected_op
                    ))))
                }
            };

            if op != expected_op {
                return Err(Error::Orga(orga::Error::App(format!(
                    "Expected {:?}",
                    expected_op
                ))));
            }

            Ok(op)
        }

        fn take_first_signatory<'a>(ins: &mut impl Iter<'a>) -> Result<Signatory> {
            let pubkey = take_key(ins)?;
            take_op(ins, OP_CHECKSIG)?;
            take_op(ins, OP_IF)?;
            let voting_power = take_number(ins)?;
            take_op(ins, OP_ELSE)?;
            take_op(ins, OP_FALSE)?;
            take_op(ins, OP_ENDIF)?;

            Ok::<_, Error>(Signatory {
                pubkey,
                voting_power: voting_power as u64,
            })
        }

        fn take_nth_signatory<'a>(ins: &mut impl Iter<'a>) -> Result<Signatory> {
            take_op(ins, OP_SWAP)?;
            let pubkey = take_key(ins)?;
            take_op(ins, OP_CHECKSIG)?;
            take_op(ins, OP_IF)?;
            let voting_power = take_number(ins)?;
            take_op(ins, OP_ADD)?;
            take_op(ins, OP_ENDIF)?;

            Ok::<_, Error>(Signatory {
                pubkey,
                voting_power: voting_power as u64,
            })
        }

        fn take_threshold<'a>(ins: &mut impl Iter<'a>) -> Result<u64> {
            let threshold = take_number(ins)?;
            take_op(ins, OP_GREATERTHAN)?;
            Ok(threshold as u64)
        }

        fn take_commitment<'a>(ins: &mut impl Iter<'a>) -> Result<&'a [u8]> {
            let bytes = take_bytes(ins)?;
            take_op(ins, OP_DROP)?;
            Ok(bytes)
        }

        let mut ins = script.instructions().peekable();
        let mut sigs = vec![take_first_signatory(&mut ins)?];
        loop {
            let next = ins
                .peek()
                .ok_or_else(|| {
                    Error::Orga(orga::Error::App("Unexpected end of script".to_string()))
                })?
                .clone()
                .map_err(|_| Error::Orga(orga::Error::App("Failed to read script".to_string())))?;

            if let Instruction::Op(opcodes::all::OP_SWAP) = next {
                sigs.push(take_nth_signatory(&mut ins)?);
            } else {
                break;
            }
        }

        let expected_threshold = take_threshold(&mut ins)?;
        let commitment = take_commitment(&mut ins)?;

        assert!(ins.next().is_none());

        let total_vp: u64 = sigs.iter().map(|s| s.voting_power).sum();
        let mut sigset = Self {
            signatories: sigs,
            present_vp: total_vp,
            possible_vp: total_vp,
            create_time: 0,
            index: 0,
        };

        for _ in 0..100 {
            let actual_threshold = sigset.signature_threshold(threshold_ratio);
            match actual_threshold.cmp(&expected_threshold) {
                Ordering::Equal => break,
                Ordering::Less => {
                    sigset.present_vp += 1;
                    sigset.possible_vp += 1;
                }
                Ordering::Greater => {
                    sigset.present_vp -= 1;
                    sigset.possible_vp -= 1;
                }
            }
        }

        assert_eq!(
            sigset.signature_threshold(threshold_ratio),
            expected_threshold,
        );
        assert_eq!(&sigset.redeem_script(commitment, threshold_ratio)?, script);

        Ok((sigset, commitment.to_vec()))
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
    //
    // 0x03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b
    // OP_CHECKSIG             OP_IF
    //                 3750000
    //             OP_ELSE
    //                 0
    //             OP_ENDIF

    //             OP_SWAP
    //
    // 0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337
    // OP_CHECKSIG             OP_IF
    //                 1250000 OP_ADD
    //             OP_ENDIF

    //             OP_SWAP
    //
    // 0x024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766
    // OP_CHECKSIG             OP_IF
    //                 937500 OP_ADD
    //             OP_ENDIF

    //             OP_SWAP
    //
    // 0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
    // OP_CHECKSIG             OP_IF
    //                 312500 OP_ADD
    //             OP_ENDIF

    //             4166666 OP_GREATERTHAN

    //             0x010203 OP_DROP
    //         }
    //     );

    //     assert_eq!(
    //         script.into_bytes(),
    //         vec![
    //             33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113,
    // 8, 95, 47, 16, 225,             199, 165, 147, 228, 224, 48, 239, 181,
    // 184, 114, 28, 229, 91, 11, 172, 99, 3, 112,             56, 57, 103, 0,
    // 104, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50,
    //             39, 200, 103, 172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197,
    // 189, 189, 203,             31, 227, 55, 172, 99, 3, 208, 18, 19, 147,
    // 104, 124, 33, 2, 77, 75, 108, 209, 54,             16, 50, 202, 155, 210,
    // 174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66,
    // 51, 116, 196, 81, 167, 37, 77, 7, 102, 172, 99, 3, 28, 78, 14, 147, 104, 124,
    // 33,             3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213,
    // 170, 186, 5, 101, 215, 30,             24, 52, 96, 72, 25, 255, 156, 23,
    // 245, 233, 213, 221, 7, 143, 172, 99, 3, 180, 196,             4, 147,
    // 104, 3, 10, 148, 63, 160, 3, 1, 2, 3, 117         ]
    //     );
    // }

    // #[test]
    // fn output_script_fixture() {
    //     let script = output_script(&mock_signatory_set(4), vec![1, 2, 3]);

    //     assert_eq!(
    //         script,
    //         bitcoin_script! {
    //             0
    // 0x73155f74ccee5011c3c62776c15abcc0d4e19eb3e1764609cf3e90e7cb81db4a
    //         }
    //     );
    //     assert_eq!(
    //         script.into_bytes(),
    //         vec![
    //             0, 32, 115, 21, 95, 116, 204, 238, 80, 17, 195, 198, 39, 118,
    // 193, 90, 188, 192,             212, 225, 158, 179, 225, 118, 70, 9, 207,
    // 62, 144, 231, 203, 129, 219, 74         ]
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

    use bitcoin::hashes::hex::FromHex;

    use crate::bitcoin::{signatory::Signatory, threshold_sig::Pubkey};

    use super::SignatorySet;

    #[test]
    fn from_script() {
        let script = bitcoin::Script::from_hex("21028891f36b691a40036f2b3ecb17c13780a932503ef2c39f3faed9b95bf71ea27fac630339e0116700687c2102f6fee7ad7dc87d0a636ae1584273c849bf540f4c1780434a0430888b0c5b151cac63033c910e93687c2102d207371a1e9a588e447d91dc12a8f3479f1f9ff8da748aae04bb5d07f0737790ac630371730893687c2103713e9bb6025fa9dc3c26507762cffd2a9524ff48f1d84c6753caa581347e5e10ac63031def0793687c2103d8fc0412a866bfb14d3fbc9e1b714ca31141d0f7e211d0fa634d53dda9789ecaac6303d1f00693687c2102c7961e04206af92f4b4cf3f19b43722f301e4915a49f5ca2908d9af5ce343830ac6303496f0693687c2103205472bb87799cb9140b5d471cc045b65821a4e75591026a8411ee3ac3e27027ac6303fe500693687c2102c923df10e8141072504b1f9513ee6796dc4d748d774ce9396942b63d42d3d575ac6303ed1f0593687c21031e8124547a5f28e04652d61fab1053ba8af41b682ccecdf5fa58595add7c7d9eac6303d4a00493687c21038060738940b9b3513851aa45df9f8b9d8e3304ef5abc5f8c1928bf4f1c8601adac630347210493687c21022e1efe78c688bceb7a36bf8af0e905da65e1942b84afe31716a356a91c0d9c05ac6303c5620393687c21020598956ed409e190b763bed8ed1ec3a18138c582c761eb8a4cf60861bfb44f13ac6303b3550393687c2102c8b2e54cafced96b1438e9ee6ebddc27c4aca68f14b2199eb8b8da111b584c2cac63036c330393687c2102d8a4c0accefa93b6a8d390a81dbffa4d05cd0a844371b2bed0ba1b1b65e14300ac6303521d0393687c2102460ccc0db97b1027e4fe2ab178f015a786b6b8f016b580f495dde3230f34984cac630304060393687c2102def64dfc155e17988ea6dee5a5659e2ec0a19fce54af90ca84dcd4df53b1a222ac630341d20293687c21030c9057c92c19f749c891037379766c0642d03bd1c50e3b262fc7d954c232f4d8ac630356c30293687c21027e1ebe3dd4fbbf250a8161a8a7af19815d5c07363e220f28f81c535c3950c7cbac6303d3ab0293687c210235e1d72961cb475971e2bc437ac21f9be13c83f1aa039e64f406aae87e2b4816ac6303bdaa0293687c210295d565c8ae94d46d439b4591dcd146742f918893292c23c49d000c4023bad4ffac630308aa029368030fb34aa0010075").unwrap();

        let (sigset, commitment) = SignatorySet::from_script(&script, (2, 3)).unwrap();

        let pk = |bytes| Pubkey::new(bytes).unwrap();
        assert_eq!(
            sigset,
            SignatorySet {
                create_time: 0,
                present_vp: 7343255,
                possible_vp: 7343255,
                index: 0,
                signatories: vec![
                    Signatory {
                        voting_power: 1171513,
                        pubkey: pk([
                            2, 136, 145, 243, 107, 105, 26, 64, 3, 111, 43, 62, 203, 23, 193, 55,
                            128, 169, 50, 80, 62, 242, 195, 159, 63, 174, 217, 185, 91, 247, 30,
                            162, 127
                        ])
                    },
                    Signatory {
                        voting_power: 954684,
                        pubkey: pk([
                            2, 246, 254, 231, 173, 125, 200, 125, 10, 99, 106, 225, 88, 66, 115,
                            200, 73, 191, 84, 15, 76, 23, 128, 67, 74, 4, 48, 136, 139, 12, 91, 21,
                            28
                        ])
                    },
                    Signatory {
                        voting_power: 553841,
                        pubkey: pk([
                            2, 210, 7, 55, 26, 30, 154, 88, 142, 68, 125, 145, 220, 18, 168, 243,
                            71, 159, 31, 159, 248, 218, 116, 138, 174, 4, 187, 93, 7, 240, 115,
                            119, 144
                        ])
                    },
                    Signatory {
                        voting_power: 519965,
                        pubkey: pk([
                            3, 113, 62, 155, 182, 2, 95, 169, 220, 60, 38, 80, 119, 98, 207, 253,
                            42, 149, 36, 255, 72, 241, 216, 76, 103, 83, 202, 165, 129, 52, 126,
                            94, 16
                        ])
                    },
                    Signatory {
                        voting_power: 454865,
                        pubkey: pk([
                            3, 216, 252, 4, 18, 168, 102, 191, 177, 77, 63, 188, 158, 27, 113, 76,
                            163, 17, 65, 208, 247, 226, 17, 208, 250, 99, 77, 83, 221, 169, 120,
                            158, 202
                        ])
                    },
                    Signatory {
                        voting_power: 421705,
                        pubkey: pk([
                            2, 199, 150, 30, 4, 32, 106, 249, 47, 75, 76, 243, 241, 155, 67, 114,
                            47, 48, 30, 73, 21, 164, 159, 92, 162, 144, 141, 154, 245, 206, 52, 56,
                            48
                        ])
                    },
                    Signatory {
                        voting_power: 413950,
                        pubkey: pk([
                            3, 32, 84, 114, 187, 135, 121, 156, 185, 20, 11, 93, 71, 28, 192, 69,
                            182, 88, 33, 164, 231, 85, 145, 2, 106, 132, 17, 238, 58, 195, 226,
                            112, 39
                        ])
                    },
                    Signatory {
                        voting_power: 335853,
                        pubkey: pk([
                            2, 201, 35, 223, 16, 232, 20, 16, 114, 80, 75, 31, 149, 19, 238, 103,
                            150, 220, 77, 116, 141, 119, 76, 233, 57, 105, 66, 182, 61, 66, 211,
                            213, 117
                        ])
                    },
                    Signatory {
                        voting_power: 303316,
                        pubkey: pk([
                            3, 30, 129, 36, 84, 122, 95, 40, 224, 70, 82, 214, 31, 171, 16, 83,
                            186, 138, 244, 27, 104, 44, 206, 205, 245, 250, 88, 89, 90, 221, 124,
                            125, 158
                        ])
                    },
                    Signatory {
                        voting_power: 270663,
                        pubkey: pk([
                            3, 128, 96, 115, 137, 64, 185, 179, 81, 56, 81, 170, 69, 223, 159, 139,
                            157, 142, 51, 4, 239, 90, 188, 95, 140, 25, 40, 191, 79, 28, 134, 1,
                            173
                        ])
                    },
                    Signatory {
                        voting_power: 221893,
                        pubkey: pk([
                            2, 46, 30, 254, 120, 198, 136, 188, 235, 122, 54, 191, 138, 240, 233,
                            5, 218, 101, 225, 148, 43, 132, 175, 227, 23, 22, 163, 86, 169, 28, 13,
                            156, 5
                        ])
                    },
                    Signatory {
                        voting_power: 218547,
                        pubkey: pk([
                            2, 5, 152, 149, 110, 212, 9, 225, 144, 183, 99, 190, 216, 237, 30, 195,
                            161, 129, 56, 197, 130, 199, 97, 235, 138, 76, 246, 8, 97, 191, 180,
                            79, 19
                        ])
                    },
                    Signatory {
                        voting_power: 209772,
                        pubkey: pk([
                            2, 200, 178, 229, 76, 175, 206, 217, 107, 20, 56, 233, 238, 110, 189,
                            220, 39, 196, 172, 166, 143, 20, 178, 25, 158, 184, 184, 218, 17, 27,
                            88, 76, 44
                        ])
                    },
                    Signatory {
                        voting_power: 204114,
                        pubkey: pk([
                            2, 216, 164, 192, 172, 206, 250, 147, 182, 168, 211, 144, 168, 29, 191,
                            250, 77, 5, 205, 10, 132, 67, 113, 178, 190, 208, 186, 27, 27, 101,
                            225, 67, 0
                        ])
                    },
                    Signatory {
                        voting_power: 198148,
                        pubkey: pk([
                            2, 70, 12, 204, 13, 185, 123, 16, 39, 228, 254, 42, 177, 120, 240, 21,
                            167, 134, 182, 184, 240, 22, 181, 128, 244, 149, 221, 227, 35, 15, 52,
                            152, 76
                        ])
                    },
                    Signatory {
                        voting_power: 184897,
                        pubkey: pk([
                            2, 222, 246, 77, 252, 21, 94, 23, 152, 142, 166, 222, 229, 165, 101,
                            158, 46, 192, 161, 159, 206, 84, 175, 144, 202, 132, 220, 212, 223, 83,
                            177, 162, 34
                        ])
                    },
                    Signatory {
                        voting_power: 181078,
                        pubkey: pk([
                            3, 12, 144, 87, 201, 44, 25, 247, 73, 200, 145, 3, 115, 121, 118, 108,
                            6, 66, 208, 59, 209, 197, 14, 59, 38, 47, 199, 217, 84, 194, 50, 244,
                            216
                        ])
                    },
                    Signatory {
                        voting_power: 175059,
                        pubkey: pk([
                            2, 126, 30, 190, 61, 212, 251, 191, 37, 10, 129, 97, 168, 167, 175, 25,
                            129, 93, 92, 7, 54, 62, 34, 15, 40, 248, 28, 83, 92, 57, 80, 199, 203
                        ])
                    },
                    Signatory {
                        voting_power: 174781,
                        pubkey: pk([
                            2, 53, 225, 215, 41, 97, 203, 71, 89, 113, 226, 188, 67, 122, 194, 31,
                            155, 225, 60, 131, 241, 170, 3, 158, 100, 244, 6, 170, 232, 126, 43,
                            72, 22
                        ])
                    },
                    Signatory {
                        voting_power: 174600,
                        pubkey: pk([
                            2, 149, 213, 101, 200, 174, 148, 212, 109, 67, 155, 69, 145, 220, 209,
                            70, 116, 47, 145, 136, 147, 41, 44, 35, 196, 157, 0, 12, 64, 35, 186,
                            212, 255
                        ])
                    }
                ]
            }
        );
        assert_eq!(commitment, vec![0]);
    }
}
