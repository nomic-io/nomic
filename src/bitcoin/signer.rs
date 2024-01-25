use crate::app::{InnerApp, Nom};
use crate::bitcoin::checkpoint::CheckpointStatus;
use crate::bitcoin::threshold_sig::Signature;
use crate::error::Result;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use lazy_static::lazy_static;
use log::info;
use orga::client::{AppClient, Wallet};
use orga::coins::Address;
use orga::encoding::LengthVec;
use orga::macros::build_call;
use orga::tendermint::client::HttpClient;
use prometheus_exporter::prometheus::{
    register_gauge, register_int_counter, register_int_gauge, Gauge, IntCounter, IntGauge,
};
use rand::Rng;
use std::fs;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::Path;
use std::time::SystemTime;

lazy_static! {
    static ref SIG_COUNTER: IntCounter =
        register_int_counter!("nomic_signer_sigs", "Number of signatures submitted").unwrap();
    static ref SIG_BATCH_COUNTER: IntCounter = register_int_counter!(
        "nomic_signer_sig_batches",
        "Number of batches of signatures submitted"
    )
    .unwrap();
    static ref CHECKPOINT_INDEX_GAUGE: IntGauge =
        register_int_gauge!("nomic_signer_checkpoint_index", "Current checkpoint index").unwrap();
    static ref CHECKPOINT_TIMESTAMP_GAUGE: IntGauge = register_int_gauge!(
        "nomic_signer_checkpoint_timestamp",
        "The creation time of the newest checkpoint"
    )
    .unwrap();
    static ref WITHDRAWAL_RATE_GAUGE: Gauge = register_gauge!(
        "nomic_signer_withdrawal_rate",
        "Rate of withdrawals from the reserve for the last 24 hours"
    )
    .unwrap();
    static ref SIGSET_CHANGE_RATE_GAUGE: Gauge = register_gauge!(
        "nomic_signer_sigset_change_rate",
        "Rate of changes to the signatory set for the last 24 hours"
    )
    .unwrap();
    static ref ERROR_COUNTER: IntCounter = register_int_counter!(
        "nomic_signer_errors",
        "Number of errors encountered. Note that these may be harmless, check logs for more info."
    )
    .unwrap();
}

/// The signer is responsible for signing checkpoints with a signatory key. It
/// is run by a signatory in its own process, and constantly watches the state
/// for new checkpoints to sign.
pub struct Signer<W, F> {
    op_addr: Address,
    xpriv: ExtendedPrivKey,
    max_withdrawal_rate: f64,
    max_sigset_change_rate: f64,
    reset_index: Option<u32>,
    app_client: F,
    exporter_addr: Option<SocketAddr>,
    _phantom: PhantomData<W>,
}

impl<W: Wallet, F> Signer<W, F>
where
    F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
{
    /// Create a new signer, loading the extended private key from the given
    /// path (`key_path`) if it exists. If the key does not exist, one will be
    /// generated and written to the path, then submitted to the chain, becoming
    /// associated with the submitter's operator address.
    ///
    /// **Parameters:**
    /// - `op_addr`: The operator address of the submitter. Used to check if the
    ///   operator has already submitted a signatory key.
    /// - `key_path`: The path to the file containing the extended private key,
    ///   or where it should be written if it does not yet exist.
    /// - `max_withdrawal_rate`: The maximum rate at which Bitcoin can be
    /// withdrawn from the reserve in a 24-hour period, temporarily halting
    /// signing if the limit is reached.
    /// - `max_sigset_change_rate`: The maximum rate at which the signatory set
    /// can change in a 24-hour period, temporarily halting signing if the limit
    /// is reached.
    /// - `reset_index`: A checkpoint index at which the rate limits should be
    /// reset, used to manually override the limits if the signer has checked on
    /// the pending withdrawals and decided they are legitimate.
    /// - `app_client`: A function that returns a new app client to be used in
    ///   querying and submitting calls.
    pub fn load_or_generate<P: AsRef<Path>>(
        op_addr: Address,
        key_path: P,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        reset_index: Option<u32>,
        app_client: F,
        exporter_addr: Option<SocketAddr>,
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
        info!("Signatory xpub:\n{}", xpub);

        Ok(Self::new(
            op_addr,
            xpriv,
            max_withdrawal_rate,
            max_sigset_change_rate,
            reset_index,
            app_client,
            exporter_addr,
        ))
    }

    /// Create a new signer with the given parameters.
    ///
    /// **Parameters:**
    /// - `op_addr`: The operator address of the submitter. Used to check if the
    ///  operator has already submitted a signatory key.
    /// - `xpriv`: The extended private key to use for signing.
    /// - `max_withdrawal_rate`: The maximum rate at which Bitcoin can be
    /// withdrawn from the reserve in a 24-hour period, temporarily halting
    /// signing if the limit is reached.
    /// - `max_sigset_change_rate`: The maximum rate at which the signatory set
    /// can change in a 24-hour period, temporarily halting signing if the limit
    /// is reached.
    /// - `reset_index`: A checkpoint index at which the rate limits should be
    /// reset, used to manually override the limits if the signer has checked on
    /// the pending withdrawals and decided they are legitimate.
    /// - `app_client`: A function that returns a new app client to be used in
    ///  querying and submitting calls.
    pub fn new(
        op_addr: Address,
        xpriv: ExtendedPrivKey,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        reset_index: Option<u32>,
        app_client: F,
        exporter_addr: Option<SocketAddr>,
    ) -> Self
    where
        F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
    {
        Signer {
            op_addr,
            xpriv,
            max_withdrawal_rate,
            max_sigset_change_rate,
            reset_index,
            app_client,
            exporter_addr,
            _phantom: PhantomData,
        }
    }

    /// Start the signer, which will run forever, signing checkpoints as they
    /// become available.
    ///
    /// If the operator has not yet submitted a signatory key, one will be
    /// generated and saved, then submitted.
    pub async fn start(mut self) -> Result<()> {
        if let Some(addr) = self.exporter_addr {
            // Populate change rate gauges
            let _ = self.check_change_rates().await;

            info!("Starting prometheus exporter on {}", addr);
            prometheus_exporter::start(addr).unwrap();
        }

        const CHECKPOINT_WINDOW: u32 = 20;
        info!("Starting signer...");
        let secp = Secp256k1::signing_only();
        let xpub = ExtendedPubKey::from_priv(&secp, &self.xpriv);

        let mut index = (self.app_client)()
            .query(|app| {
                let index = app.bitcoin.checkpoints.index();
                if index == 0 {
                    return Ok(0);
                }
                let first = index + 1 - app.bitcoin.checkpoints.len()?;
                Ok(index.saturating_sub(CHECKPOINT_WINDOW).max(first))
            })
            .await?;
        if let Some(reset_index) = self.reset_index {
            if reset_index > index {
                return Err(crate::error::Error::Checkpoint(format!(
                    "Limit reset index {} is greater than current checkpoint index {}",
                    reset_index, index
                )));
            }
        }

        loop {
            self.maybe_submit_xpub(&xpub).await?;

            let signed = match self.try_sign(&xpub, index).await {
                Ok(signed) => signed,
                Err(e) => {
                    ERROR_COUNTER.inc();
                    eprintln!("Signer error: {}", e);
                    false
                }
            };

            if signed {
                index += 1;
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    /// Check if the operator has already submitted a signatory key. If not,
    /// submit the given key.
    ///
    /// If the operator has already submitted a key, check that it matches the
    /// given key. If not, return an error (it is not currently possible to
    /// change the signatory key after submitting one).
    async fn maybe_submit_xpub(&mut self, xpub: &ExtendedPubKey) -> Result<()> {
        let cons_key = (self.app_client)()
            .query(|app: InnerApp| app.staking.consensus_key(self.op_addr))
            .await?;
        let onchain_xpub = (self.app_client)()
            .query(|app: InnerApp| Ok(app.bitcoin.signatory_keys.get(cons_key)?))
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

    /// Submit the given signatory key to the chain.
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

    /// Get a new app client.
    fn client(&self) -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W> {
        (self.app_client)()
    }

    /// Try to sign the checkpoint at the given index.
    ///
    /// Returns `Ok(true)` if the signatory has already signed all batches in
    /// this checkpoint and therefore should move onto to attempting to sign the
    /// next checkpoint.
    ///
    /// Returns `Ok(false)` if the signatory is not done signing the checkpoint,
    /// and should call `try_sign` for the same index again later (e.g. it is
    /// still `Building`, or we have not yet submitted signatures for the final
    /// batch of transactions).
    async fn try_sign(&mut self, xpub: &ExtendedPubKey, index: u32) -> Result<bool> {
        let secp = Secp256k1::signing_only();

        let (status, timestamp) = self
            .client()
            .query(|app| {
                let cp = app.bitcoin.checkpoints.get(index)?;
                Ok((cp.status, cp.create_time()))
            })
            .await?;

        CHECKPOINT_INDEX_GAUGE.set(index as i64);
        CHECKPOINT_TIMESTAMP_GAUGE.set(timestamp as i64);

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
        info!("Signing checkpoint ({} inputs)...", to_sign.len());

        let sigs = sign(&secp, &self.xpriv, &to_sign)?;

        (self.app_client)()
            .call(
                move |app| build_call!(app.bitcoin.sign(xpub.into(), sigs.clone(), index)),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        SIG_BATCH_COUNTER.inc();
        SIG_COUNTER.inc_by(to_sign.len() as u64);
        info!("Submitted signatures");

        Ok(false)
    }

    /// Check the current withdrawal and signatory set change rates, and return
    /// an error if either is above the configured maximum.
    ///
    /// This is a "circuit breaker" security mechanism which prevents large
    /// amounts of funds from being withdrawn too quickly or the signatory set
    /// from being changed too quickly, so that the network has time to assess
    /// and react.
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
        let reset_index = self.reset_index.unwrap_or(0);
        let rates = (self.app_client)()
            .query(|app| Ok(app.bitcoin.change_rates(60 * 60 * 24, now, reset_index)?))
            .await?;

        let withdrawal_rate = rates.withdrawal as f64 / 10_000.0;
        let sigset_change_rate = rates.sigset_change as f64 / 10_000.0;

        WITHDRAWAL_RATE_GAUGE.set(withdrawal_rate);
        SIGSET_CHANGE_RATE_GAUGE.set(sigset_change_rate);

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

/// Sign the given messages with the given extended private key, deriving the
/// correct private keys for each signature.
pub fn sign(
    secp: &Secp256k1<bitcoin::secp256k1::SignOnly>,
    xpriv: &ExtendedPrivKey,
    to_sign: &[([u8; 32], u32)],
) -> Result<LengthVec<u16, Signature>> {
    Ok(to_sign
        .iter()
        .map(|(msg, index)| {
            let privkey = xpriv
                .derive_priv(secp, &[ChildNumber::from_normal_idx(*index)?])?
                .private_key;

            Ok(secp
                .sign_ecdsa(&Message::from_slice(&msg[..])?, &privkey)
                .serialize_compact()
                .into())
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()?)
}
