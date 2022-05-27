use super::Bitcoin;
use crate::error::{Error, Result};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use orga::call::Call;
use orga::client::{AsyncCall, AsyncQuery, Client};
use orga::query::Query;

type AppClient<T> = <Bitcoin as Client<T>>::Client;

pub struct Signer<T: Clone + Send> {
    client: AppClient<T>,
    xpriv: ExtendedPrivKey,
}

impl<T: Clone + Send> Signer<T>
where
    T: AsyncQuery<Query = <Bitcoin as Query>::Query>,
    T: for<'a> AsyncQuery<Response<'a> = &'a Bitcoin>,
    T: AsyncCall<Call = <Bitcoin as Call>::Call>,
{
    pub fn new(client: AppClient<T>, xpriv: &str) -> Result<Self> {
        let xpriv = xpriv.parse()?;
        Ok(Signer { client, xpriv })
    }

    pub async fn start(&self) -> Result<()> {
        let secp = Secp256k1::signing_only();

        let xpub = ExtendedPubKey::from_private(&secp, &self.xpriv);

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            if self.client.checkpoints.signing().await??.is_none() {
                continue;
            }

            let to_sign = self.client.checkpoints.to_sign(xpub.into()).await??;
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
                .checkpoints
                .sign(xpub.into(), sigs.into())
                .await?;
            println!("Submitted signatures");
        }

        Ok(())
    }
}
