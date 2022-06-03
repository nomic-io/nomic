use crate::app::App;
use crate::error::Result;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use orga::abci::TendermintClient;
use rand::Rng;
use std::fs;
use std::path::Path;

pub struct Signer {
    client: TendermintClient<App>,
    xpriv: ExtendedPrivKey,
}

impl Signer {
    pub fn load_or_generate<P: AsRef<Path>>(client: TendermintClient<App>, key_path: P) -> Result<Self> {
        let path = key_path.as_ref();
        let xpriv = if path.exists() {
            println!("Loading signatory key from {}", path.display());
            let bytes = fs::read(path)?;
            let text = String::from_utf8(bytes).unwrap();
            text.trim().parse()?
        } else {
            println!("Generating signatory key at {}", path.display());
            let seed: [u8; 32] = rand::thread_rng().gen();
            // TODO: get network from somewhere
            let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed.as_slice())?;

            fs::write(path, xpriv.to_string().as_bytes())?;

            xpriv
        };

        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let xpub = ExtendedPubKey::from_private(&secp, &xpriv);
        println!("Signatory xpub:\n{}", xpub);

        Ok(Self::new(client, xpriv))
    }

    pub fn new(client: TendermintClient<App>, xpriv: ExtendedPrivKey) -> Self {
        Signer { client, xpriv }
    }

    pub async fn start(&self) -> Result<()> {
        let secp = Secp256k1::signing_only();

        let xpub = ExtendedPubKey::from_private(&secp, &self.xpriv);

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            if self.client.bitcoin.checkpoints.signing().await??.is_none() {
                continue;
            }

            let to_sign = self
                .client
                .bitcoin
                .checkpoints
                .to_sign(xpub.into())
                .await??;
            if to_sign.is_empty() {
                continue;
            }

            println!("Signing checkpoint... ({} inputs)", to_sign.len());

            let sigs: Vec<_> = to_sign
                .into_iter()
                .map(|(msg, index)| {
                    let privkey = self
                        .xpriv
                        .derive_priv(&secp, &[ChildNumber::from_normal_idx(index)?])?
                        .private_key
                        .key;

                    Ok(secp
                        .sign(&Message::from_slice(&msg[..])?, &privkey)
                        .serialize_compact())
                })
                .collect::<Result<_>>()?;

            self.client
                .clone()
                .pay_from(async move |client| {
                    client
                        .bitcoin
                        .checkpoints
                        .sign(xpub.into(), sigs.into())
                        .await
                })
                .noop()
                .await?;
            println!("Submitted signatures");
        }
    }
}
