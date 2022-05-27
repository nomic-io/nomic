use super::Bitcoin;
use crate::error::{Error, Result};
use orga::call::Call;
use orga::client::{AsyncCall, AsyncQuery, Client};
use orga::query::Query;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};
use bitcoin::secp256k1::{Message, Secp256k1};

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
        let secp = Secp256k1::signing_only();
        let xpriv: ExtendedPrivKey = "tprv8ZgxMBicQKsPcyZNa7A6H7C7Jj9WtZ8r3dfsNKDWbqpDoKfWSnB6s2aCgMqr2edfQbn12t5QyLdca6TCe6gBGhLpo7VAZNHucbG3EXv6YVE".parse().unwrap();

        let xpub = ExtendedPubKey::from_private(&secp, &xpriv);

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
                            &[ChildNumber::from_normal_idx(index)?],
                        )?
                        .private_key
                        .key;

                    Ok(secp.sign(
                        &Message::from_slice(&msg[..])?,
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
