use crate::app::{InnerApp, Nom};
use crate::bitcoin::signatory::derive_pubkey;
use crate::bitcoin::signer::Signer;
use crate::error::Result;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use log::info;
use orga::client::{AppClient, Wallet};
use orga::macros::build_call;
use orga::tendermint::client::HttpClient;

impl<W: Wallet, F> Signer<W, F>
where
    F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
{
    pub async fn start_ethereum_signing(
        &self,
        key_pairs: Vec<(ExtendedPubKey, &ExtendedPrivKey)>,
    ) -> Result<()> {
        let mut index = (self.app_client)()
            .query(|app| Ok(app.ethereum.message_index + 1 - app.ethereum.outbox.len()))
            .await?;

        info!("Starting Ethereum signer...");
        loop {
            let sigset_index = loop {
                if let Some(sigset_index) = self
                    .client()
                    .query(|app: InnerApp| {
                        if app.ethereum.message_index < index {
                            return Ok(None);
                        }
                        Ok(Some(app.ethereum.get(index)?.sigset_index))
                    })
                    .await?
                {
                    break sigset_index;
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            };

            for (xpub, xpriv) in key_pairs.iter() {
                self.try_sign_eth_message(xpub, xpriv, index, sigset_index as u64)
                    .await?;
            }

            index += 1;
        }
    }

    async fn try_sign_eth_message(
        &self,
        xpub: &ExtendedPubKey,
        xpriv: &ExtendedPrivKey,
        msg_index: u64,
        ss_index: u64,
    ) -> Result<()> {
        let secp = Secp256k1::new();
        let pubkey = derive_pubkey(&secp, xpub.into(), ss_index as u32)?;

        let res = self
            .client()
            .query(|app: InnerApp| {
                let msg = app.ethereum.get(msg_index)?;
                if app.ethereum.needs_sig(msg_index, pubkey.into())? {
                    Ok(Some((msg.msg.clone(), msg.sigs.message)))
                } else {
                    Ok(None)
                }
            })
            .await?;
        dbg!();

        let (msg, hash) = match res {
            Some(res) => res,
            None => return Ok(()),
        };
        dbg!();

        info!("Signing outgoing Ethereum message ({:?})...", msg);

        let sig = crate::bitcoin::signer::sign(
            &Secp256k1::signing_only(),
            xpriv,
            &[(hash, ss_index as u32)],
        )?[0];

        dbg!();
        (self.app_client)()
            .call(
                move |app| build_call!(app.ethereum.sign(msg_index, pubkey.into(), sig)),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        info!("Submitted Ethereum signature");

        Ok(())
    }
}
