use nomic_bitcoin::bitcoin::{PublicKey, Script};
use bitcoin_script::bitcoin_script;
use failure::Error;
use super::{Signatory, SignatorySet};

type Result<T> = std::result::Result<T, Error>;

pub fn build_script(signatories: &SignatorySet) -> Script {
    let mut iter = signatories.iter();

    let first_signatory = iter.next()
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

impl SignatorySet {
    pub fn to_reserve_script(&self) -> Script {
        build_script(self)
    }
}

fn first_signatory_script(signatory: &Signatory) -> Script {
    bitcoin_script! {
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64>
        OP_ELSE
            0
        OP_ENDIF
    }        
}

fn nth_signatory_script(signatory: &Signatory) -> Script {
    bitcoin_script! {
        OP_SWAP
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64> OP_ADD
        OP_ENDIF
    }
}

fn greater_than_script(n: u32) -> Script {
    bitcoin_script!{ <n as i64> OP_GREATERTHAN }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use nomic_bitcoin::bitcoin_script::bitcoin_script;

    #[test]
    fn build_script_fixture() {
        let script = mock_signatory_set(4).to_reserve_script();

        assert_eq!(script, bitcoin_script! {
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
        });

        assert_eq!(
            script.into_bytes(),
            vec![33, 3, 70, 39, 121, 173, 74, 173, 57, 81, 70, 20, 117, 26, 113, 8, 95, 47, 16, 225, 199, 165, 147, 228, 224, 48, 239, 181, 184, 114, 28, 229, 91, 11, 172, 99, 84, 103, 0, 104, 124, 33, 2, 83, 31, 230, 6, 129, 52, 80, 61, 39, 35, 19, 50, 39, 200, 103, 172, 143, 166, 200, 60, 83, 126, 154, 68, 195, 197, 189, 189, 203, 31, 227, 55, 172, 99, 83, 147, 104, 124, 33, 2, 77, 75, 108, 209, 54, 16, 50, 202, 155, 210, 174, 185, 217, 0, 170, 77, 69, 217, 234, 216, 10, 201, 66, 51, 116, 196, 81, 167, 37, 77, 7, 102, 172, 99, 82, 147, 104, 124, 33, 3, 27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24, 52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143, 172, 99, 81, 147, 104, 86, 160]
        );
    }
}

