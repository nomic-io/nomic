use super::{Signatory, SignatorySet};
use bitcoin_script::bitcoin_script as script;
use nomic_bitcoin::bitcoin::Script;

pub fn redeem_script(signatories: &SignatorySet, data: Vec<u8>) -> Script {
    let first_signatory_script = |signatory: &Signatory| {
        script! {
            <signatory.pubkey> OP_CHECKSIG
            OP_IF
                <signatory.voting_power as i64>
            OP_ELSE
                0
            OP_ENDIF
        }
    };

    let nth_signatory_script = |signatory: &Signatory| {
        script! {
            OP_SWAP
            <signatory.pubkey> OP_CHECKSIG
            OP_IF
                <signatory.voting_power as i64> OP_ADD
            OP_ENDIF
        }
    };

    let greater_than_script = |n: u32| {
        script! {
            <n as i64> OP_GREATERTHAN
            OP_VERIFY
        }
    };

    // put a 1 at the end so nobody can make an unspendable output
    let data_script = |data: Vec<u8>| script!(<data> 1);

    let mut iter = signatories.iter();

    let first_signatory = iter
        .next()
        .expect("Cannot build script for empty signatory set");
    let bytes = first_signatory_script(first_signatory).into_bytes();

    let mut bytes = iter.fold(bytes, |mut bytes, signatory| {
        bytes.extend(&nth_signatory_script(signatory).into_bytes());
        bytes
    });

    let two_thirds = signatories.total_voting_power() as u64 * 2 / 3;
    bytes.extend(&greater_than_script(two_thirds as u32).into_bytes());

    bytes.extend(&data_script(data).into_bytes());

    bytes.into()
}

pub fn output_script(signatories: &SignatorySet, data: Vec<u8>) -> Script {
    redeem_script(signatories, data).to_v0_p2wsh()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::*, SignatorySet};
    use bitcoin_script::bitcoin_script;

    #[test]
    #[should_panic(expected = "Cannot build script for empty signatory set")]
    fn redeem_script_empty() {
        redeem_script(&SignatorySet::new(), vec![1, 2, 3]);
    }

    #[test]
    fn redeem_script_fixture() {
        let script = redeem_script(&mock_signatory_set(4), vec![1, 2, 3]);

        assert_eq!(
            script,
            bitcoin_script! {
                0x03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b OP_CHECKSIG
                OP_IF
                    4
                OP_ELSE
                    0
                OP_ENDIF

                OP_SWAP
                0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 OP_CHECKSIG
                OP_IF
                    3 OP_ADD
                OP_ENDIF

                OP_SWAP
                0x024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 OP_CHECKSIG
                OP_IF
                    2 OP_ADD
                OP_ENDIF

                OP_SWAP
                0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f OP_CHECKSIG
                OP_IF
                    1 OP_ADD
                OP_ENDIF

                6 OP_GREATERTHAN
                OP_VERIFY

                0x010203 1
            }
        );

        assert_eq!(
            script.into_bytes(),
            vec![
                33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113, 8, 95, 47, 16, 225,
                199, 165, 147, 228, 224, 48, 239, 181, 184, 114, 28, 229, 91, 11, 172, 99, 84, 103,
                0, 104, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50, 39, 200, 103,
                172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197, 189, 189, 203, 31, 227, 55,
                172, 99, 83, 147, 104, 124, 33, 2, 77, 75, 108, 209, 54, 16, 50, 202, 155, 210,
                174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66, 51, 116, 196, 81, 167,
                37, 77, 7, 102, 172, 99, 82, 147, 104, 124, 33, 3, 27, 132, 197, 86, 123, 18, 100,
                64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23,
                245, 233, 213, 221, 7, 143, 172, 99, 81, 147, 104, 86, 160, 105, 3, 1, 2, 3, 81
            ]
        );
    }

    #[test]
    fn output_script_fixture() {
        let script = output_script(&mock_signatory_set(4), vec![1, 2, 3]);

        assert_eq!(
            script,
            bitcoin_script! {
                0 0x7d7aa8c8120655f0419912c34dbd3d8c0d1eff5e266eaacee267a3c3b5cf4f0b
            }
        );
        assert_eq!(
            script.into_bytes(),
            vec![
                0, 32, 125, 122, 168, 200, 18, 6, 85, 240, 65, 153, 18, 195, 77, 189, 61, 140, 13,
                30, 255, 94, 38, 110, 170, 206, 226, 103, 163, 195, 181, 207, 79, 11
            ]
        );
    }
}
