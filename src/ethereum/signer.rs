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
        info!("Starting Ethereum signer...");

        loop {
            for (xpub, xpriv) in key_pairs.iter() {
                self.sign_eth_messages(xpub, xpriv).await?;

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    async fn sign_eth_messages(
        &self,
        xpub: &ExtendedPubKey,
        xpriv: &ExtendedPrivKey,
    ) -> Result<()> {
        let secp = Secp256k1::new();

        let to_sign = self
            .client()
            .query(|app: InnerApp| Ok(app.ethereum.to_sign(xpub.into())?))
            .await?;

        for (net_id, bridge_contract, msg_index, ss_index, hash, msg) in to_sign {
            info!(
                "Signing outgoing Ethereum message ({} {:?})...",
                net_id, msg,
            );

            let pubkey = derive_pubkey(&secp, xpub.into(), ss_index)?;

            let sig = crate::bitcoin::signer::sign(
                &Secp256k1::signing_only(),
                xpriv,
                &[(hash, ss_index)],
            )?[0];

            dbg!();
            (self.app_client)()
                .call(
                    move |app| {
                        build_call!(app.ethereum.sign(
                            net_id,
                            bridge_contract,
                            msg_index,
                            pubkey.into(),
                            sig
                        ))
                    },
                    |app| build_call!(app.app_noop()),
                )
                .await?;

            info!("Submitted Ethereum signature");
        }

        Ok(())
    }
}
