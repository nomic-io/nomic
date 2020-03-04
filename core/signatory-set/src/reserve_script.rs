use bitcoin::{PublicKey, Script};
use bitcoin_script::bitcoin_script;
use failure::Error;
use super::Signatory;

type Result<T> = std::result::Result<T, Error>;

pub fn build_script(signatories: Vec<Signatory>) -> Script {
    bitcoin_script!()
    // let mut last_voting_power = 
}

fn first_signatory(signatory: Signatory) -> Script {
    bitcoin_script! {
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64>
        OP_ELSE
            0
        OP_ENDIF
    }        
}

fn nth_signatory(signatory: Signatory) -> Script {
    bitcoin_script! {
        OP_SWAP
        <signatory.pubkey> OP_CHECKSIG
        OP_IF
            <signatory.voting_power as i64> OP_ADD
        OP_ENDIF
    }
}

fn greater_than(n: u32) -> Script {
    bitcoin_script!{ <n as i64> OP_GREATERTHAN }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}


// Notes
// 
// nomic_core::Bitcoin::{Bitcoin, BitcoinRPC, BitcoinScript, Reserve::{script_from_signatories}}