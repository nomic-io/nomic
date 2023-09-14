use crate::app::{InnerApp, Nom};
use crate::bitcoin::checkpoint::CheckpointStatus;
use crate::bitcoin::threshold_sig::Signature;
use crate::error::Result;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use log::info;
use orga::client::{AppClient, Wallet};
use orga::coins::Address;
use orga::encoding::LengthVec;
use orga::macros::build_call;
use orga::tendermint::client::HttpClient;
use rand::Rng;
use std::fs;
use std::marker::PhantomData;
use std::path::Path;
use std::time::SystemTime;

pub struct Signer<W, F> {
    op_addr: Address,
    xpriv: ExtendedPrivKey,
    max_withdrawal_rate: f64,
    max_sigset_change_rate: f64,
    app_client: F,
    _phantom: PhantomData<W>,
}

impl<W: Wallet, F> Signer<W, F>
where
    F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
{
    pub fn load_or_generate<P: AsRef<Path>>(
        op_addr: Address,
        key_path: P,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        app_client: F,
    ) -> Result<Self> {
        let path = key_path.as_ref();
        let xpriv = if path.exists() {
            info!("Loading signatory key from {}", path.display());
            let bytes = fs::read(path)?;
            let text = String::from_utf8(bytes).unwrap();
            text.trim().parse()?
        } else {
            info!("Generating signatory key at {}", path.display());
            let seed: [u8; 32] = rand::thread_rng().gen();

            let network = if super::NETWORK == bitcoin::Network::Regtest {
                bitcoin::Network::Testnet
            } else {
                super::NETWORK
            };
            let xpriv = ExtendedPrivKey::new_master(network, seed.as_slice())?;

            fs::write(path, xpriv.to_string().as_bytes())?;

            xpriv
        };

        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv);
        dbg!("Signatory xpub:\n{}", xpub);

        Ok(Self::new(
            op_addr,
            xpriv,
            max_withdrawal_rate,
            max_sigset_change_rate,
            app_client,
        ))
    }

    pub fn new(
        op_addr: Address,
        xpriv: ExtendedPrivKey,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        app_client: F,
    ) -> Self
    where
        F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
    {
        Signer {
            op_addr,
            xpriv,
            max_withdrawal_rate,
            max_sigset_change_rate,
            app_client,
            _phantom: PhantomData,
        }
    }

    pub async fn start(mut self) -> Result<()> {
        const CHECKPOINT_WINDOW: u32 = 20;
        info!("Starting signer...");
        let secp = Secp256k1::signing_only();
        let xpub = ExtendedPubKey::from_priv(&secp, &self.xpriv);

        let mut index = (self.app_client)()
            .query(|app| {
                Ok(app.bitcoin.checkpoints.index().max(CHECKPOINT_WINDOW) - CHECKPOINT_WINDOW)
            })
            .await?;

        loop {
            self.maybe_submit_xpub(&xpub).await?;

            let signed = match self.try_sign(&xpub, index).await {
                Ok(signed) => signed,
                Err(e) => {
                    eprintln!("Signer error: {}", e);
                    false
                }
            };

            if !signed {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            } else {
                index += 1;
            }
        }
    }

    async fn maybe_submit_xpub(&mut self, xpub: &ExtendedPubKey) -> Result<()> {
        let cons_key = (self.app_client)()
            .query(|app| app.staking.consensus_key(self.op_addr))
            .await?;
        let onchain_xpub = (self.app_client)()
            .query(|app| Ok(app.bitcoin.signatory_keys.get(cons_key)?))
            .await?;

        match onchain_xpub {
            None => self.submit_xpub(xpub).await,
            Some(onchain_xpub) if onchain_xpub.inner() != xpub => Err(orga::Error::App(
                "Local xpub does not match xpub found on chain".to_string(),
            )
            .into()),
            Some(_) => Ok(()),
        }
    }

    async fn submit_xpub(&mut self, xpub: &ExtendedPubKey) -> Result<()> {
        (self.app_client)()
            .call(
                move |app| build_call!(app.bitcoin.set_signatory_key(xpub.into())),
                |app| build_call!(app.app_noop()),
            )
            .await?;
        info!("Submitted signatory key.");
        Ok(())
    }

    fn client(&self) -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W> {
        (self.app_client)()
    }

    async fn try_sign(&mut self, xpub: &ExtendedPubKey, index: u32) -> Result<bool> {
        let secp = Secp256k1::signing_only();

        let status = self
            .client()
            .query(|app| Ok(app.bitcoin.checkpoints.get(index)?.status))
            .await?;

        if matches!(status, CheckpointStatus::Building) {
            return Ok(false);
        }

        let to_sign = self
            .client()
            .query(|app| Ok(app.bitcoin.checkpoints.get(index)?.to_sign(xpub.into())?))
            .await?;

        if to_sign.is_empty() {
            return Ok(matches!(status, CheckpointStatus::Complete));
        }

        self.check_change_rates().await?;
        info!("Signing checkpoint...");
        dbg!("{} inputs", to_sign.len());

        let sigs: LengthVec<u16, Signature> = to_sign
            .into_iter()
            .map(|(msg, index)| {
                let privkey = self
                    .xpriv
                    .derive_priv(&secp, &[ChildNumber::from_normal_idx(index)?])?
                    .private_key;

                Ok(secp
                    .sign_ecdsa(&Message::from_slice(&msg[..])?, &privkey)
                    .serialize_compact()
                    .into())
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()?;

        (self.app_client)()
            .call(
                move |app| {
                    build_call!(app
                        .bitcoin
                        .checkpoints
                        .sign(xpub.into(), sigs.clone(), index))
                },
                |app| build_call!(app.app_noop()),
            )
            .await?;

        info!("Submitted signatures");

        Ok(false)
    }

    async fn check_change_rates(&self) -> Result<()> {
        let checkpoint_index = (self.app_client)()
            .query(|app| Ok(app.bitcoin.checkpoints.index()))
            .await?;
        if checkpoint_index < 100 {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let rates = (self.app_client)()
            .query(|app| Ok(app.bitcoin.change_rates(60 * 60 * 24, now)?))
            .await?;

        let withdrawal_rate = rates.withdrawal as f64 / 10_000.0;
        let sigset_change_rate = rates.sigset_change as f64 / 10_000.0;

        if withdrawal_rate > self.max_withdrawal_rate {
            return Err(orga::Error::App(format!(
                "Withdrawal rate of {} is above maximum of {}",
                withdrawal_rate, self.max_withdrawal_rate
            ))
            .into());
        }

        if sigset_change_rate > self.max_sigset_change_rate {
            return Err(orga::Error::App(format!(
                "Signatory set change rate of {} is above maximum of {}",
                sigset_change_rate, self.max_sigset_change_rate
            ))
            .into());
        }

        Ok(())
    }
}
