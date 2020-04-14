use super::SignatorySet;
use bitcoin_script::bitcoin_script as script;
use nomic_bitcoin::bitcoin::Script;

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
        <truncated_voting_power as i64> OP_MUL
    };
    let mut bytes = script.into_bytes();

    // all other signatories
    for signatory in iter {
        let truncated_voting_power = signatory.voting_power >> truncation;
        let script = script! {
            OP_SWAP
            <signatory.pubkey> OP_CHECKSIG
            <truncated_voting_power as i64> OP_MUL
            OP_ADD
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
    let script = script!(<data> OP_SWAP);
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
                3750000 OP_MUL

                OP_SWAP
                0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337 OP_CHECKSIG
                1250000 OP_MUL
                OP_ADD

                OP_SWAP
                0x024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766 OP_CHECKSIG
                937500 OP_MUL
                OP_ADD

                OP_SWAP
                0x031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f OP_CHECKSIG
                312500 OP_MUL
                OP_ADD

                4166666 OP_GREATERTHAN

                0x010203 OP_SWAP
            }
        );

        assert_eq!(
            script.into_bytes(),
            vec![
                33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113, 8, 95, 47, 16, 225,
                199, 165, 147, 228, 224, 48, 239, 181, 184, 114, 28, 229, 91, 11, 172, 3, 112, 56,
                57, 149, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50, 39, 200, 103,
                172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197, 189, 189, 203, 31, 227, 55,
                172, 3, 208, 18, 19, 149, 147, 124, 33, 2, 77, 75, 108, 209, 54, 16, 50, 202, 155,
                210, 174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66, 51, 116, 196, 81,
                167, 37, 77, 7, 102, 172, 3, 28, 78, 14, 149, 147, 124, 33, 3, 27, 132, 197, 86,
                123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25,
                255, 156, 23, 245, 233, 213, 221, 7, 143, 172, 3, 180, 196, 4, 149, 147, 3, 10,
                148, 63, 160, 3, 1, 2, 3, 124
            ]
        );
    }

    #[test]
    fn output_script_fixture() {
        let script = output_script(&mock_signatory_set(4), vec![1, 2, 3]);

        assert_eq!(
            script,
            bitcoin_script! {
                0 0x387245be4196638702efb06eabe156e4c0e44629c446e65dd3058a4f327b0e0d
            }
        );
        assert_eq!(
            script.into_bytes(),
            vec![
                0, 32, 56, 114, 69, 190, 65, 150, 99, 135, 2, 239, 176, 110, 171, 225, 86, 228,
                192, 228, 70, 41, 196, 70, 230, 93, 211, 5, 138, 79, 50, 123, 14, 13
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
