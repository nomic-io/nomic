use super::{Signatory, SignatorySet};
use bitcoin_script::bitcoin_script as script;
use nomic_bitcoin::bitcoin::Script;

pub fn redeem_script(signatories: &SignatorySet) -> Script {
    let first_signatory_script = |signatory: &Signatory| script! {
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64>
        OP_ELSE
            0
        OP_ENDIF
    };

    let nth_signatory_script = |signatory: &Signatory| script! {
        OP_SWAP
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64> OP_ADD
        OP_ENDIF
    };

    let greater_than_script = |n: u32| script! {
        <n as i64> OP_GREATERTHAN
    };

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

    bytes.into()
}

pub fn output_script(signatories: &SignatorySet) -> Script {
    redeem_script(signatories).to_v0_p2wsh()
}

impl SignatorySet {
    pub fn to_redeem_script(&self) -> Script {
        redeem_script(self)
    }

    pub fn to_output_script(&self) -> Script {
        output_script(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::*, SignatorySet};
    use bitcoin_script::bitcoin_script;

    #[test]
    #[should_panic(expected = "Cannot build script for empty signatory set")]
    fn redeem_script_empty() {
        redeem_script(&SignatorySet::new());
    }

    #[test]
    fn redeem_script_fixture() {
        let script = mock_signatory_set(4).to_redeem_script();

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
                245, 233, 213, 221, 7, 143, 172, 99, 81, 147, 104, 86, 160
            ]
        );
    }

    #[test]
    fn output_script_fixture() {
        let script = mock_signatory_set(4).to_output_script();

        assert_eq!(
            script,
            bitcoin_script! {
                0 0xc3cc0f5ae30d5da678fc042d46fcf0c1203f8a0de604f1165ceda9e00afb50f2
            }
        );
        assert_eq!(
            script.into_bytes(),
            vec![0, 32, 195, 204, 15, 90, 227, 13, 93, 166, 120, 252, 4, 45, 70, 252, 240, 193, 32, 63, 138, 13, 230, 4, 241, 22, 92, 237, 169, 224, 10, 251, 80, 242]
        );
    }
}
