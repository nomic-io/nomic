use super::Bitcoin;
use crate::error::{Error, Result};
use orga::call::Call;
use orga::client::{AsyncCall, AsyncQuery, Client};
use orga::query::Query;

type AppClient<T> = <Bitcoin as Client<T>>::Client;

pub struct Signer<T: Clone + Send> {
    client: AppClient<T>,
}

impl<T: Clone + Send> Signer<T>
where
    T: AsyncQuery<Query = <Bitcoin as Query>::Query>,
    T: for<'a> AsyncQuery<Response<'a> = &'a Bitcoin>,
    T: AsyncCall<Call = <Bitcoin as Call>::Call>,
{
    pub fn new(client: AppClient<T>) -> Self {
        Signer { client }
    }

    pub async fn start(&self) -> Result<()> {
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let xpriv: bitcoin::util::bip32::ExtendedPrivKey = "tprv8ZgxMBicQKsPeFt7JQzg8PeDuh99t7bBX9dsarzMgmXFsTnDuCjqX57NcjtWgjdUc2a8P9iqVju2QJTb21BB1DmADUSomdBNB5daGseyaUU".parse().unwrap();

        let xpub = bitcoin::util::bip32::ExtendedPubKey::from_private(&secp, &xpriv);

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
                    let privkey = xpriv
                        .derive_priv(
                            &secp,
                            &[bitcoin::util::bip32::ChildNumber::from_normal_idx(index)?],
                        )?
                        .private_key
                        .key;

                    Ok(secp.sign(
                        &bitcoin::secp256k1::Message::from_slice(&msg[..])?,
                        &privkey,
                    )
                    .serialize_compact())
                })
                .collect::<Result<_>>()?;

            self.client.checkpoints.sign(xpub.into(), sigs.into()).await?;
            println!("Submitted signatures");
        }

        Ok(())
    }
}
