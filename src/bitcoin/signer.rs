use crate::app::{InnerApp, Nom};
use crate::bitcoin::checkpoint::CheckpointStatus;
use crate::bitcoin::threshold_sig::Signature;
use crate::error::{Error, Result};
use crate::utils::load_bitcoin_key;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use futures::try_join;
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

pub fn load_xpriv<P: AsRef<Path> + Clone>(path: P) -> Result<ExtendedPrivKey> {
    if path.as_ref().exists() {
        load_bitcoin_key(path)
    } else {
        Err(Error::Signer(format!(
            "Key path {} not found",
            path.as_ref().display()
        )))
    }
}

/// The signer is responsible for signing checkpoints with a signatory key. It
/// is run by a signatory in its own process, and constantly watches the state
/// for new checkpoints to sign.
pub struct Signer<W, F> {
    op_addr: Address,
    xprivs: Vec<ExtendedPrivKey>,
    max_withdrawal_rate: f64,
    max_sigset_change_rate: f64,
    min_blocks_per_checkpoint: u64,
    reset_index: Option<u32>,
    pub app_client: F,
    exporter_addr: Option<SocketAddr>,
    _phantom: PhantomData<W>,
}

impl<W: Wallet, F> Signer<W, F>
where
    F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
{
    #![allow(clippy::too_many_arguments)]
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
    ///   withdrawn from the reserve in a 24-hour period, temporarily halting
    ///   signing if the limit is reached.
    /// - `max_sigset_change_rate`: The maximum rate at which the signatory set
    ///   can change in a 24-hour period, temporarily halting signing if the
    ///   limit is reached.
    /// - `min_checkpoint_seconds`: The minimum amount of time that must pass
    ///   before this signer will contribute its signature.
    /// - `reset_index`: A checkpoint index at which the rate limits should be
    ///   reset, used to manually override the limits if the signer has checked
    ///   on the pending withdrawals and decided they are legitimate.
    /// - `app_client`: A function that returns a new app client to be used in
    ///   querying and submitting calls.
    #[allow(clippy::too_many_arguments)]
    pub fn load_xprivs<P: AsRef<Path> + Clone>(
        op_addr: Address,
        default_xpriv_path: P,
        xpriv_paths: Vec<P>,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        min_checkpoint_seconds: u64,
        reset_index: Option<u32>,
        app_client: F,
        exporter_addr: Option<SocketAddr>,
    ) -> Result<Self> {
        let xpriv_paths = if xpriv_paths.is_empty() {
            if !default_xpriv_path.as_ref().exists() {
                return Err(Error::Signer("No local xpriv found. Run `nomic set-signatory-key` if you do not have a signatory key on-chain.".into()));
            }
            vec![default_xpriv_path]
        } else {
            xpriv_paths
        };

        let xprivs = xpriv_paths.iter().try_fold(Vec::new(), |mut acc, path| {
            let res = load_xpriv(path)?;
            acc.push(res);
            Ok::<_, Error>(acc)
        })?;

        Ok(Self::new(
            op_addr,
            xprivs,
            max_withdrawal_rate,
            max_sigset_change_rate,
            min_checkpoint_seconds,
            reset_index,
            app_client,
            exporter_addr,
        ))
    }

    /// Create a new signer with the given parameters.
    ///
    /// **Parameters:**
    /// - `op_addr`: The operator address of the submitter. Used to check if the
    ///   operator has already submitted a signatory key.
    /// - `xprivs`: The extended private keys to use for signing.
    /// - `max_withdrawal_rate`: The maximum rate at which Bitcoin can be
    ///   withdrawn from the reserve in a 24-hour period, temporarily halting
    ///   signing if the limit is reached.
    /// - `max_sigset_change_rate`: The maximum rate at which the signatory set
    ///   can change in a 24-hour period, temporarily halting signing if the
    ///   limit is reached.
    /// - `min_blocks_per_checkpoint`: The minimum number of new Bitcoin blocks
    ///   that must be mined before this signer will contribute its signature.
    /// - `reset_index`: A checkpoint index at which the rate limits should be
    ///   reset, used to manually override the limits if the signer has checked
    ///   on the pending withdrawals and decided they are legitimate.
    /// - `app_client`: A function that returns a new app client to be used in
    ///   querying and submitting calls.
    pub fn new(
        op_addr: Address,
        xprivs: Vec<ExtendedPrivKey>,
        max_withdrawal_rate: f64,
        max_sigset_change_rate: f64,
        min_blocks_per_checkpoint: u64,
        reset_index: Option<u32>,
        app_client: F,
        exporter_addr: Option<SocketAddr>,
    ) -> Self
    where
        F: Fn() -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W>,
    {
        Signer {
            op_addr,
            xprivs,
            max_withdrawal_rate,
            max_sigset_change_rate,
            min_blocks_per_checkpoint,
            reset_index,
            app_client,
            exporter_addr,
            _phantom: PhantomData,
        }
    }

    pub async fn start(self) -> Result<()> {
        if let Some(addr) = self.exporter_addr {
            // Populate change rate gauges
            let _ = self.check_change_rates().await;

            info!("Starting prometheus exporter on {}", addr);
            prometheus_exporter::start(addr).unwrap();
        }

        let cons_key = (self.app_client)()
            .query(|app| app.staking.consensus_key(self.op_addr))
            .await?;
        let onchain_xpub = (self.app_client)()
            .query(|app| Ok(app.bitcoin.signatory_keys.get(cons_key)?))
            .await?;
        if onchain_xpub.is_none() {
            return Err(Error::Signer(
                "No on-chain xpub found.
            Please run `nomic set-signatory-key` to set a signatory key."
                    .into(),
            ));
        }
        let secp = Secp256k1::signing_only();
        let xprivs = self.xprivs.clone();
        let (xpub_submitted, key_pairs) =
            xprivs
                .iter()
                .fold((false, Vec::default()), |mut acc, xpriv| {
                    let xpub = ExtendedPubKey::from_priv(&secp, xpriv);
                    acc.0 |= xpub == *onchain_xpub.unwrap();
                    acc.1.push((xpub, xpriv));
                    acc
                });
        if !xpub_submitted {
            return Err(Error::Signer(
                "No passed xpub matches on-chain xpub
            If you intended to change your signatory key, please run `nomic set-signatory-key`"
                    .into(),
            ));
        }

        let checkpoint_signing = self.start_checkpoint_signing(key_pairs.clone());
        let recovery_signing = self.start_recovery_signing(key_pairs.clone());

        let eth_signing = async {
            #[cfg(feature = "ethereum")]
            self.start_ethereum_signing(key_pairs).await?;
            Ok(())
        };

        try_join!(checkpoint_signing, recovery_signing, eth_signing)?;

        Ok(())
    }

    pub async fn start_checkpoint_signing(
        &self,
        key_pairs: Vec<(ExtendedPubKey, &ExtendedPrivKey)>,
    ) -> Result<()> {
        const CHECKPOINT_WINDOW: u32 = 20;
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

        info!("Starting checkpoint signer...");
        loop {
            let mut signed = false;

            for (xpub, xpriv) in key_pairs.iter() {
                signed |= match self.try_sign_checkpoint(xpub, xpriv, index).await {
                    Ok(signed) => signed,
                    Err(e) => {
                        ERROR_COUNTER.inc();
                        eprintln!("Signer error: {}", e);
                        false
                    }
                };
            }

            if signed {
                index += 1;
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    pub async fn start_recovery_signing(
        &self,
        key_pairs: Vec<(ExtendedPubKey, &ExtendedPrivKey)>,
    ) -> Result<()> {
        info!("Starting recovery transaction signer...");

        loop {
            for (xpub, xpriv) in key_pairs.iter() {
                match self.try_sign_recovery_txs(xpub, xpriv).await {
                    Ok(signed) => signed,
                    Err(e) => {
                        ERROR_COUNTER.inc();
                        eprintln!("Recovery tx signer error: {}", e);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    /// Get a new app client.
    pub fn client(&self) -> AppClient<InnerApp, InnerApp, HttpClient, Nom, W> {
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
    async fn try_sign_checkpoint(
        &self,
        xpub: &ExtendedPubKey,
        xpriv: &ExtendedPrivKey,
        index: u32,
    ) -> Result<bool> {
        let secp = Secp256k1::signing_only();

        let (status, timestamp) = self
            .client()
            .query(|app: InnerApp| {
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

        if matches!(status, CheckpointStatus::Signing) {
            self.check_change_rates().await?;
            let current_btc_height = self
                .client()
                .query(|app: InnerApp| Ok(app.bitcoin.headers.height()?))
                .await? as u64;
            let last_signed_btc_height: Option<u64> = self
                .client()
                .query(|app: InnerApp| {
                    Ok(app
                        .bitcoin
                        .checkpoints
                        .get(index.saturating_sub(1))?
                        .signed_at_btc_height)
                })
                .await?
                .map(|v| v as u64);

            if let Some(last_signed_btc_height) = last_signed_btc_height {
                if current_btc_height < last_signed_btc_height + self.min_blocks_per_checkpoint {
                    let delta = last_signed_btc_height + self.min_blocks_per_checkpoint
                        - current_btc_height;
                    info!(
                        "Checkpoint is too recent, {} more Bitcoin block{} required",
                        delta,
                        if delta == 1 { "" } else { "s" },
                    );
                    return Ok(false);
                }
            }
        }

        info!("Signing Bitcoin checkpoint ({} inputs)...", to_sign.len());

        let sigs = sign(&secp, xpriv, &to_sign)?;

        (self.app_client)()
            .call(
                move |app| build_call!(app.bitcoin.sign(xpub.into(), sigs.clone(), index)),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        SIG_BATCH_COUNTER.inc();
        SIG_COUNTER.inc_by(to_sign.len() as u64);
        info!("Submitted Bitcoin signatures");

        Ok(false)
    }

    async fn try_sign_recovery_txs(
        &self,
        xpub: &ExtendedPubKey,
        xpriv: &ExtendedPrivKey,
    ) -> Result<()> {
        let secp = Secp256k1::signing_only();

        let to_sign = self
            .client()
            .query(|app| Ok(app.bitcoin.recovery_txs.to_sign(xpub.into())?))
            .await?;

        if to_sign.is_empty() {
            return Ok(());
        }

        let sigs = sign(&secp, xpriv, &to_sign)?;

        (self.app_client)()
            .call(
                move |app| build_call!(app.bitcoin.recovery_txs.sign(xpub.into(), sigs.clone())),
                |app| build_call!(app.app_noop()),
            )
            .await?;

        Ok(())
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::app_client;
    use crate::utils::generate_bitcoin_key;
    use std::fs;

    #[test]
    fn signer_default_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let xpriv = generate_bitcoin_key(bitcoin::Network::Testnet).unwrap();
        fs::write(
            temp_dir.path().join("xpriv-default"),
            xpriv.to_string().as_bytes(),
        )
        .unwrap();

        let signer = Signer::load_xprivs(
            Address::default(),
            temp_dir.path().join("xpriv-default"),
            Vec::default(),
            1.0,
            1.0,
            0,
            None,
            || app_client("http://localhost:26657"),
            None,
        )
        .unwrap();

        assert!(signer.xprivs.first().unwrap() == &xpriv);
    }

    #[test]
    fn signer_primary_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let xpriv = generate_bitcoin_key(bitcoin::Network::Testnet).unwrap();
        fs::write(
            temp_dir.path().join("xpriv-primary"),
            xpriv.to_string().as_bytes(),
        )
        .unwrap();

        let signer = Signer::load_xprivs(
            Address::default(),
            temp_dir.path().join("xpriv-default"),
            vec![temp_dir.path().join("xpriv-primary")],
            1.0,
            1.0,
            0,
            None,
            || app_client("http://localhost:26657"),
            None,
        )
        .unwrap();
        assert!(signer.xprivs.len() == 1);
        assert!(signer.xprivs.first().unwrap() == &xpriv);
    }

    #[test]
    #[should_panic]
    fn signer_provided_primary_path_non_existent() {
        let temp_dir = tempfile::tempdir().unwrap();
        Signer::load_xprivs(
            Address::default(),
            temp_dir.path().join("xpriv-default"),
            vec![temp_dir.path().join("xpriv-primary")],
            1.0,
            1.0,
            0,
            None,
            || app_client("http://localhost:26657"),
            None,
        )
        .unwrap();
    }

    #[test]
    fn signer_additional_paths() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut xpriv_paths = Vec::new();
        let mut xprivs = Vec::new();
        for i in 0..10 {
            let path = temp_dir.path().join(format!("xpriv-additional-{}", i));
            let xpriv = generate_bitcoin_key(bitcoin::Network::Testnet).unwrap();
            fs::write(path.clone(), xpriv.to_string().as_bytes()).unwrap();
            xpriv_paths.push(path);
            xprivs.push(xpriv);
        }

        let signer = Signer::load_xprivs(
            Address::default(),
            temp_dir.path().join("xpriv-default"),
            xpriv_paths,
            1.0,
            1.0,
            0,
            None,
            || app_client("http://localhost:26657"),
            None,
        )
        .unwrap();

        signer.xprivs.iter().enumerate().for_each(|(i, xpriv)| {
            assert!(xpriv == &xprivs[i]);
        });
    }
}
