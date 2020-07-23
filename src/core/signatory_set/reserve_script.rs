use super::SignatorySet;
use crate::core::bitcoin::bitcoin::Script;
use bitcoin_script::bitcoin_script as script;

pub fn redeem_script(signatories: &SignatorySet, data: Vec<u8>) -> Script {
    let truncation = get_truncation(signatories, 23);

    let mut iter = signatories.iter();

    // first signatory
    let signatory = iter
        .next()
        .expect("Cannot build script for empty signatory set");
    let truncated_voting_power = signatory.voting_power >> truncation;
    let script = script! {
        <signatory.pubkey> OP_CHECKSIG
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
            <signatory.pubkey> OP_CHECKSIG
            OP_IF
                <truncated_voting_power as i64> OP_ADD
            OP_ENDIF
        };
        bytes.extend(&script.into_bytes());
    }

    // > 2/3 check
    let truncated_two_thirds = signatories.two_thirds_voting_power() >> truncation;
    let script = script! {
        <truncated_two_thirds as i64> OP_GREATERTHAN
    };
    bytes.extend(&script.into_bytes());

    // depositor data commitment
    let script = script!(<data> OP_DROP);
    bytes.extend(&script.into_bytes());

    bytes.into()
}

pub fn output_script(signatories: &SignatorySet, data: Vec<u8>) -> Script {
    redeem_script(signatories, data).to_v0_p2wsh()
}

fn get_truncation(signatories: &SignatorySet, target_precision: u32) -> u32 {
    let vp = signatories.total_voting_power();
    let vp_bits = 128 - vp.leading_zeros();
    vp_bits.saturating_sub(target_precision)
}

#[cfg(test)]
mod tests {
    use super::super::{test_utils::*, SignatorySet};
    use super::*;
    use bitcoin_script::bitcoin_script;

    #[test]
    #[should_panic(expected = "Cannot build script for empty signatory set")]
    fn redeem_script_empty() {
        redeem_script(&SignatorySet::new(), vec![1, 2, 3]);
    }

    #[test]
    fn redeem_script_fixture() {
        let mut signatories = SignatorySet::new();
        signatories.set(mock_signatory(1, 5_000_000));
        signatories.set(mock_signatory(2, 15_000_000));
        signatories.set(mock_signatory(3, 20_000_000));
        signatories.set(mock_signatory(4, 60_000_000));
        let script = redeem_script(&signatories, vec![1, 2, 3]);

        assert_eq!(
            script,
            bitcoin_script! {
                0x03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b OP_CHECKSIG
                OP_IF
                    3750000
                OP_ELSE
                    0
                OP_ENDIF

                OP_SWAP
                0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 OP_CHECKSIG
                OP_IF
                    1250000 OP_ADD
                OP_ENDIF

                OP_SWAP
                0x024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 OP_CHECKSIG
                OP_IF
                    937500 OP_ADD
                OP_ENDIF

                OP_SWAP
                0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f OP_CHECKSIG
                OP_IF
                    312500 OP_ADD
                OP_ENDIF

                4166666 OP_GREATERTHAN

                0x010203 OP_DROP
            }
        );

        assert_eq!(
            script.into_bytes(),
            vec![
                33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113, 8, 95, 47, 16, 225,
                199, 165, 147, 228, 224, 48, 239, 181, 184, 114, 28, 229, 91, 11, 172, 99, 3, 112,
                56, 57, 103, 0, 104, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50,
                39, 200, 103, 172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197, 189, 189, 203,
                31, 227, 55, 172, 99, 3, 208, 18, 19, 147, 104, 124, 33, 2, 77, 75, 108, 209, 54,
                16, 50, 202, 155, 210, 174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66,
                51, 116, 196, 81, 167, 37, 77, 7, 102, 172, 99, 3, 28, 78, 14, 147, 104, 124, 33,
                3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30,
                24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, 172, 99, 3, 180, 196,
                4, 147, 104, 3, 10, 148, 63, 160, 3, 1, 2, 3, 117
            ]
        );
    }

    #[test]
    fn output_script_fixture() {
        let script = output_script(&mock_signatory_set(4), vec![1, 2, 3]);

        assert_eq!(
            script,
            bitcoin_script! {
                0 0x73155f74ccee5011c3c62776c15abcc0d4e19eb3e1764609cf3e90e7cb81db4a
            }
        );
        assert_eq!(
            script.into_bytes(),
            vec![
                0, 32, 115, 21, 95, 116, 204, 238, 80, 17, 195, 198, 39, 118, 193, 90, 188, 192,
                212, 225, 158, 179, 225, 118, 70, 9, 207, 62, 144, 231, 203, 129, 219, 74
            ]
        );
    }

    #[test]
    fn truncation() {
        // total less than target precision (10, 4 bits)
        let mut signatories = SignatorySet::new();
        signatories.set(mock_signatory(1, 10));
        assert_eq!(get_truncation(&signatories, 23), 0);

        // total greater than target precision (100M, 27 bits)
        let mut signatories = SignatorySet::new();
        signatories.set(mock_signatory(1, 100_000_000));
        assert_eq!(get_truncation(&signatories, 23), 4);
    }
}
