//! The signing process for the [`Frost`] module.
//! Commitments and key shares are kept in a [`MerkStore`], and the signing
//! process is driven by calls to [`Signer::step`].
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use frost_secp256k1_tr::round1::{commit, SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2;
use frost_secp256k1_tr::round2::SignatureShare;
use orga::call::build_call;
use orga::client::{AppClient, Transport, Wallet};
use orga::merk::MerkStore;
use orga::plugins::ABCIPlugin;
use rand::thread_rng;

use crate::app::{App, InnerApp, Nom};
use crate::bitcoin::threshold_sig::Pubkey;
use crate::frost::Encrypted;

use super::dkg::DkgState;
use super::signing::SigningState;
use super::{assemble_by_identifier, disassemble_by_identifier, identifier, Adapter, Config};
use frost_secp256k1_tr::keys::{dkg, KeyPackage};
use orga::call::Call;
use orga::coins::Address;
use orga::collections::Map;
use orga::encoding::LengthVec;
use orga::state::State;
use orga::store::{DefaultBackingStore, Read, Shared, Store, Write};
use orga::{Error, Result};

/// A key-value store for the signer's private data.
///
/// Updates are committed to disk immediately after each operation.
pub struct SecretStore {
    merk_store: MerkStore,
    path: PathBuf,
}

impl SecretStore {
    fn new<P: AsRef<Path>>(path: P) -> Self {
        let merk_store: MerkStore = MerkStore::new(path.as_ref());

        Self {
            merk_store,
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Create a new [`Store`] backed by a [`MerkStore`] at the provided path.
    pub fn new_store<P: AsRef<Path>>(path: P) -> Store {
        let secret_store = Self::new(path);

        Store::new(DefaultBackingStore::Other(Shared::new(Box::new(
            secret_store,
        ))))
    }

    pub fn wal_path(&self) -> PathBuf {
        self.path.join("secret_store.wal")
    }

    pub fn wal_file(&self) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.wal_path())
            .map_err(|e| Error::App(format!("Failed to open WAL file: {}", e)))
    }
}

impl Read for SecretStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.merk_store.get(key)
    }

    fn get_next(&self, key: &[u8]) -> Result<Option<orga::store::KV>> {
        self.merk_store.get_next(key)
    }

    fn get_prev(&self, key: Option<&[u8]>) -> Result<Option<orga::store::KV>> {
        self.merk_store.get_prev(key)
    }
}

impl orga::store::Write for SecretStore {
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        let mut wal = self.wal_file()?;
        writeln!(wal, "delete {:?}", key)?;

        self.merk_store.delete(key)?;

        self.flush()
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let mut wal = self.wal_file()?;
        writeln!(wal, "put {:?} value {:?}", key, value)?;

        self.merk_store.put(key, value)?;

        self.flush()
    }
}

impl SecretStore {
    fn flush(&mut self) -> Result<()> {
        self.merk_store.write(vec![])?;

        Ok(())
    }
}

/// The signing process for the [`Frost`] module.
pub struct Signer<W, C> {
    /// The app client constructor for interacting with a Nomic full node.
    client: C,
    /// The key-value store for the signer's private data.
    secret_store: Store,
    /// The communication secret key for this signer.
    comm_secret_key: ecies::SecretKey,
    /// The address of this signer.
    address: Address,
    /// Secret packages from the first DKG round, indexed by (group index,
    /// participant index).
    dkg_round1: HashMap<(u64, u16), dkg::round1::SecretPackage>,
    /// Secret packages from the second DKG round, indexed by (group index,
    /// participant index).
    dkg_round2: HashMap<(u64, u16), dkg::round2::SecretPackage>,
    _pd: std::marker::PhantomData<W>,
}

impl<W, C, Tr> Signer<W, C>
where
    C: Fn() -> AppClient<InnerApp, InnerApp, Tr, Nom, W>,
    W: Wallet,
    Tr: Transport<ABCIPlugin<App>>,
{
    /// Create a new [`Signer`] for the provided operator address.
    pub fn new(mut secret_store: Store, client: C, address: Address) -> Self {
        // TODO: audit secret store atomicity
        let maybe_comm_secret_key = secret_store.get(&[2]).unwrap();

        let comm_secret_key = match maybe_comm_secret_key {
            Some(key) => key,
            None => {
                let (sk, _pk) = ecies::utils::generate_keypair();

                secret_store.put(vec![2], sk.serialize().to_vec()).unwrap();
                secret_store.clone().flush(&mut vec![]).unwrap();

                sk.serialize().to_vec()
            }
        };

        Self {
            client,
            secret_store,
            comm_secret_key: ecies::SecretKey::parse_slice(&comm_secret_key).unwrap(),
            dkg_round1: HashMap::new(),
            dkg_round2: HashMap::new(),
            address,
            _pd: Default::default(),
        }
    }

    fn comm_pubkey(&self) -> Pubkey {
        Pubkey::new(ecies::PublicKey::from_secret_key(&self.comm_secret_key).serialize_compressed())
            .unwrap()
    }

    /// Access the key packages stored in the [`SecretStore`] using the provided
    /// `op` function, flushing immediately after execution.
    fn with_key_package<T, F: FnMut(&mut Map<(u64, u16), Adapter<KeyPackage>>) -> Result<T>>(
        &mut self,
        mut op: F,
    ) -> Result<T> {
        let mut key_package = Map::load(self.secret_store.sub(&[0]), &mut vec![].as_slice())?;

        let res = op(&mut key_package)?;

        let mut _b = vec![];
        key_package.flush(&mut _b)?;

        Ok(res)
    }

    /// Access the signing nonces stored in the [`SecretStore`] using the
    /// provided `op` function, flushing immediately after execution.
    fn with_signing_nonces<
        T,
        F: FnMut(&mut Map<(u64, u64, u32, u16), Adapter<SigningNonces>>) -> Result<T>,
    >(
        &mut self,
        mut op: F,
    ) -> Result<T> {
        let mut nonce_map = Map::load(self.secret_store.sub(&[1]), &mut vec![].as_slice())?;

        let res = op(&mut nonce_map)?;

        let mut _b = vec![];
        nonce_map.flush(&mut _b)?;

        Ok(res)
    }

    /// Builds and executes the given `payer` call with a no-op payee call.
    pub async fn call<F: FnOnce(&InnerApp) -> <InnerApp as Call>::Call>(
        &mut self,
        payer: F,
    ) -> Result<()> {
        self.client()
            .call(payer, |app| build_call!(app.aux_frost.noop_call()))
            .await?;

        Ok(())
    }

    fn client(&self) -> AppClient<InnerApp, InnerApp, Tr, Nom, W> {
        (self.client)()
    }

    /// Performs the DKG and signing steps where required for this signer.
    pub async fn step(&mut self) -> Result<()> {
        self.dkg_step().await?;
        self.signing_step().await?;

        Ok(())
    }

    /// Performs the DKG steps where required for this signer.
    pub async fn dkg_step(&mut self) -> Result<()> {
        let address = self.address;
        let indices: Vec<u64> = self
            .client()
            .query(|app: InnerApp| app.frost.dkg_action_required(address))
            .await?;

        for index in indices {
            let dkg_state = self
                .client()
                .query(|app: InnerApp| app.frost.dkg_state(index))
                .await?;

            let res = match dkg_state {
                DkgState::Round1 => self.dkg_part1(index).await,
                DkgState::Round2 => self.dkg_part2(index).await,
                DkgState::Attesting => self.dkg_part3(index).await,
                DkgState::Complete => Ok(()),
            };

            match res {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Error during DKG step: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Performs the signing steps where required for this signer.
    pub async fn signing_step(&mut self) -> Result<()> {
        let address = self.address;
        let indices: Vec<(u64, u64)> = self
            .client()
            .query(|app: InnerApp| app.frost.signing_action_required(address))
            .await?;

        for (group_index, sig_index) in indices {
            let res = match self
                .client()
                .query(|app: InnerApp| {
                    app.frost
                        .signing_state_with_iteration(group_index, sig_index)
                })
                .await?
            {
                (i, SigningState::Round1) => self.signing_commit(group_index, sig_index, i).await,
                (i, SigningState::Round2) => self.signing_sign(group_index, sig_index, i).await,
                (_i, SigningState::Complete) => Ok(()),
            };

            match res {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Error during signing step: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Queries the [`Config`] for the provided group index.
    async fn get_config(&self, index: u64) -> Result<Config> {
        self.client()
            .query(|app: InnerApp| app.frost.config(index))
            .await
    }

    /// Performs the DKG round 1 step for the given
    /// group index.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part1`].
    async fn dkg_part1(&mut self, index: u64) -> Result<()> {
        let mut rng = thread_rng();
        let config = self.get_config(index).await?;
        let max_signers = config.total_shares();
        let min_signers = config.threshold;

        let mut packages = vec![];
        for i in config.share_range(self.address)? {
            let id = identifier(i);
            let (secret_package, package) = dkg::part1(id, max_signers, min_signers, &mut rng)
                .map_err(|e| Error::App(format!("Error during DKG part 1: {}", e)))?;
            self.dkg_round1.insert((index, i), secret_package);
            packages.push((Adapter { inner: package }, self.comm_pubkey()));
        }

        let packages: LengthVec<u16, (Adapter<dkg::round1::Package>, Pubkey)> =
            packages.try_into()?;
        self.call(|app| build_call!(app.frost.submit_dkg_round1(index, packages.clone())))
            .await?;

        log::info!("Submitted DKG round 1 for group {}", index);

        Ok(())
    }

    /// Performs the DKG round 2 step for the given group index.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part2`].
    async fn dkg_part2(&mut self, index: u64) -> Result<()> {
        let config = self.get_config(index).await?;
        let packages: Vec<(u16, (dkg::round1::Package, Pubkey))> = self
            .client()
            .query(|app: InnerApp| app.frost.dkg_round1_packages(index))
            .await?;

        let round1_packages =
            assemble_by_identifier(packages.iter().map(|(i, (p, _))| (*i, p.clone())));
        let round1_pubkeys: HashMap<frost_secp256k1_tr::Identifier, Pubkey> = packages
            .iter()
            .map(|(i, (_, pk))| (identifier(*i), *pk))
            .collect();

        let mut round2_packages: Vec<
            LengthVec<u16, (u16, Encrypted<Adapter<dkg::round2::Package>>)>,
        > = vec![];
        for i in config.share_range(self.address)? {
            let mut round1_packages = round1_packages.clone();
            round1_packages.remove(&identifier(i));
            let secret_package = self
                .dkg_round1
                .get(&(index, i))
                .ok_or_else(|| Error::App(format!("Missing secret package for participant {}", i)))?
                .clone();
            let (secret_package, round2_package) = dkg::part2(secret_package, &round1_packages)
                .map_err(|e| Error::App(format!("Error during DKG part 2: {}", e)))?;
            self.dkg_round2.insert((index, i), secret_package);
            let round2_package = round2_package
                .into_iter()
                .map(|(i, package)| {
                    let pk = round1_pubkeys.get(&i).unwrap();
                    (
                        i,
                        Encrypted::encrypt(pk.as_slice(), Adapter { inner: package }).unwrap(),
                    )
                })
                .collect();
            round2_packages.push(disassemble_by_identifier(&round2_package).try_into()?);
        }

        let round2_packages: LengthVec<u16, _> = round2_packages.try_into()?;
        self.call(|app| build_call!(app.frost.submit_dkg_round2(index, round2_packages.clone())))
            .await?;

        log::info!("Submitted DKG round 2 for group {}", index);

        Ok(())
    }

    /// Performs the DKG round 3 step for the given group index and submits the
    /// public key attestation.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part3`].
    async fn dkg_part3(&mut self, index: u64) -> Result<()> {
        let config = self.get_config(index).await?;
        let packages: Vec<(u16, (dkg::round1::Package, Pubkey))> = self
            .client()
            .query(|app: InnerApp| app.frost.dkg_round1_packages(index))
            .await?;

        let round1_packages =
            assemble_by_identifier(packages.into_iter().map(|(i, (p, _))| (i, p)));
        let mut last_pubkey_package = None;
        for i in config.share_range(self.address)? {
            let mut round1_packages = round1_packages.clone();
            round1_packages.remove(&identifier(i));
            let round2_packages: Vec<(u16, Encrypted<Adapter<dkg::round2::Package>>)> = self
                .client()
                .query(|app: InnerApp| app.frost.dkg_round2_packages(index, i))
                .await?;

            let secret_package = self.dkg_round2.get(&(index, i)).ok_or_else(|| {
                Error::App(format!("Missing secret package for participant {}", i))
            })?;
            let mut decrypted_round2_packages = vec![];

            for (i, encrypted_package) in round2_packages {
                let decrypted =
                    encrypted_package.decrypt(self.comm_secret_key.serialize().as_slice())?;
                decrypted_round2_packages.push((i, decrypted.inner));
            }

            let (key_package, pubkey_package) = dkg::part3(
                secret_package,
                &round1_packages,
                &assemble_by_identifier(decrypted_round2_packages.into_iter()),
            )
            .map_err(|e| Error::App(format!("Error during DKG part 3: {}", e)))?;

            self.with_key_package(|key_packages| {
                key_packages.insert(
                    (index, i),
                    Adapter {
                        inner: key_package.clone(),
                    },
                )?;

                Ok(())
            })?;

            if let Some(ref package) = last_pubkey_package {
                if pubkey_package != *package {
                    return Err(Error::App(
                        "Participants computed different pubkeys".to_string(),
                    ));
                }
            } else {
                last_pubkey_package.replace(pubkey_package);
            }
            if let Some(pubkey) = last_pubkey_package.take() {
                let pubkey = Adapter { inner: pubkey };
                self.call(|app| build_call!(app.frost.attest_dkg_pubkey(index, pubkey.clone())))
                    .await?;

                log::info!("Submitted DKG pubkey attestation for group {}", index);
            }
        }

        Ok(())
    }

    /// Performs the signing round 1 step for the given group index and
    /// participant index.
    ///
    /// See [`frost_secp256k1_tr::round1::commit`].
    async fn signing_commit(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
    ) -> Result<()> {
        let mut rng = thread_rng();
        let config = self.get_config(group_index).await?;
        let mut commitments = vec![];
        for i in config.share_range(self.address)? {
            let key_package: KeyPackage = self.with_key_package(|key_packages| {
                Ok(key_packages
                    .get((group_index, i))?
                    .ok_or_else(|| {
                        Error::App(format!(
                            "Missing key package group {} participant {}",
                            group_index, i
                        ))
                    })?
                    .inner
                    .clone())
            })?;

            let signing_share = key_package.signing_share();
            let (nonces, commitment) = commit(signing_share, &mut rng);
            self.with_signing_nonces(|signing_nonces| {
                signing_nonces.insert(
                    (group_index, sig_index, iteration, i),
                    Adapter {
                        inner: nonces.clone(),
                    },
                )?;

                Ok(())
            })?;
            commitments.push(Adapter { inner: commitment });
        }

        let commitments: LengthVec<u16, Adapter<SigningCommitments>> = commitments.try_into()?;
        self.call(|app| {
            build_call!(app.frost.submit_commitments(
                group_index,
                sig_index,
                iteration,
                commitments.clone()
            ))
        })
        .await?;

        log::info!(
            "Submitted commitment for group {} signature {} iteration {}",
            group_index,
            sig_index,
            iteration
        );

        Ok(())
    }

    /// Performs the signing round 2 step for the given group index and
    /// participant index.
    ///
    /// See [`frost_secp256k1_tr::round2::sign`].
    async fn signing_sign(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
    ) -> Result<()> {
        let Some(signing_package) = self
            .client()
            .query(|app| {
                app.frost
                    .signing_package(group_index, sig_index)
                    .map(|p| p.map(|p| p.inner))
            })
            .await?
        else {
            return Err(Error::App("No signing package".to_string()));
        };

        let config = self.get_config(group_index).await?;

        let mut sig_shares = vec![];
        for i in config.share_range(self.address)? {
            let key_package: KeyPackage = self.with_key_package(|key_packages| {
                Ok(key_packages
                    .get((group_index, i))?
                    .ok_or_else(|| Error::App("Missing key package".to_string()))?
                    .inner
                    .clone())
            })?;

            let nonces = self.with_signing_nonces(|signing_nonces| {
                Ok(signing_nonces
                    .get((group_index, sig_index, iteration, i))?
                    .ok_or_else(|| Error::App("Missing signing nonces".to_string()))?
                    .inner
                    .clone())
            })?;

            let sig_share = round2::sign(&signing_package, &nonces, &key_package)
                .map_err(|e| Error::App(format!("Error during signing: {}", e)))?;

            sig_shares.push(Adapter { inner: sig_share });
        }

        let sig_shares: LengthVec<u16, Adapter<SignatureShare>> = sig_shares.try_into()?;
        self.call(|app| {
            build_call!(app.frost.submit_sig_shares(
                group_index,
                sig_index,
                iteration,
                sig_shares.clone()
            ))
        })
        .await?;

        log::info!(
            "Submitted signature share for group {} signature {} iteration {}",
            group_index,
            sig_index,
            iteration
        );

        Ok(())
    }

    pub async fn audit(&mut self) -> Result<()> {
        let groups = self
            .client()
            .query(|app| app.frost.completed_groups_for_address(self.address))
            .await?;

        self.with_key_package(|key_packages| {
            for (group_index, shares) in groups.iter() {
                for share in shares {
                    if !key_packages.contains_key((*group_index, *share))? {
                        return Err(Error::App(format!(
                            "Missing key package for group {} share {}",
                            group_index, share
                        )));
                    }
                }
            }
            Ok(())
        })?;

        Ok(())
    }
}

// TODO: remove once orga client supports subclient calls
/// The signing process for the [`Frost`] module.
pub struct AuxSigner<W, C> {
    /// The app client constructor for interacting with a Nomic full node.
    client: C,
    /// The key-value store for the signer's private data.
    secret_store: Store,
    /// The communication secret key for this signer.
    comm_secret_key: ecies::SecretKey,
    /// The address of this signer.
    address: Address,
    /// Secret packages from the first DKG round, indexed by (group index,
    /// participant index).
    dkg_round1: HashMap<(u64, u16), dkg::round1::SecretPackage>,
    /// Secret packages from the second DKG round, indexed by (group index,
    /// participant index).
    dkg_round2: HashMap<(u64, u16), dkg::round2::SecretPackage>,
    _pd: std::marker::PhantomData<W>,
}

impl<W, C, Tr> AuxSigner<W, C>
where
    C: Fn() -> AppClient<InnerApp, InnerApp, Tr, Nom, W>,
    W: Wallet,
    Tr: Transport<ABCIPlugin<App>>,
{
    /// Create a new [`Signer`] for the provided operator address.
    pub fn new(mut secret_store: Store, client: C, address: Address) -> Self {
        // TODO: audit secret store atomicity
        let maybe_comm_secret_key = secret_store.get(&[2]).unwrap();

        let comm_secret_key = match maybe_comm_secret_key {
            Some(key) => key,
            None => {
                let (sk, _pk) = ecies::utils::generate_keypair();

                secret_store.put(vec![2], sk.serialize().to_vec()).unwrap();
                secret_store.clone().flush(&mut vec![]).unwrap();

                sk.serialize().to_vec()
            }
        };

        Self {
            client,
            secret_store,
            comm_secret_key: ecies::SecretKey::parse_slice(&comm_secret_key).unwrap(),
            dkg_round1: HashMap::new(),
            dkg_round2: HashMap::new(),
            address,
            _pd: Default::default(),
        }
    }

    fn comm_pubkey(&self) -> Pubkey {
        Pubkey::new(ecies::PublicKey::from_secret_key(&self.comm_secret_key).serialize_compressed())
            .unwrap()
    }

    /// Access the key packages stored in the [`SecretStore`] using the provided
    /// `op` function, flushing immediately after execution.
    fn with_key_package<T, F: FnMut(&mut Map<(u64, u16), Adapter<KeyPackage>>) -> Result<T>>(
        &mut self,
        mut op: F,
    ) -> Result<T> {
        let mut key_package = Map::load(self.secret_store.sub(&[0]), &mut vec![].as_slice())?;

        let res = op(&mut key_package)?;

        let mut _b = vec![];
        key_package.flush(&mut _b)?;

        Ok(res)
    }

    /// Access the signing nonces stored in the [`SecretStore`] using the
    /// provided `op` function, flushing immediately after execution.
    fn with_signing_nonces<
        T,
        F: FnMut(&mut Map<(u64, u64, u32, u16), Adapter<SigningNonces>>) -> Result<T>,
    >(
        &mut self,
        mut op: F,
    ) -> Result<T> {
        let mut nonce_map = Map::load(self.secret_store.sub(&[1]), &mut vec![].as_slice())?;

        let res = op(&mut nonce_map)?;

        let mut _b = vec![];
        nonce_map.flush(&mut _b)?;

        Ok(res)
    }

    /// Builds and executes the given `payer` call with a no-op payee call.
    pub async fn call<F: FnOnce(&InnerApp) -> <InnerApp as Call>::Call>(
        &mut self,
        payer: F,
    ) -> Result<()> {
        self.client()
            .call(payer, |app| build_call!(app.aux_frost.noop_call()))
            .await?;

        Ok(())
    }

    fn client(&self) -> AppClient<InnerApp, InnerApp, Tr, Nom, W> {
        (self.client)()
    }

    /// Performs the DKG and signing steps where required for this signer.
    pub async fn step(&mut self) -> Result<()> {
        self.dkg_step().await?;
        self.signing_step().await?;

        Ok(())
    }

    /// Performs the DKG steps where required for this signer.
    pub async fn dkg_step(&mut self) -> Result<()> {
        let address = self.address;
        let indices: Vec<u64> = self
            .client()
            .query(|app: InnerApp| app.aux_frost.dkg_action_required(address))
            .await?;

        for index in indices {
            let dkg_state = self
                .client()
                .query(|app: InnerApp| app.aux_frost.dkg_state(index))
                .await?;

            let res = match dkg_state {
                DkgState::Round1 => self.dkg_part1(index).await,
                DkgState::Round2 => self.dkg_part2(index).await,
                DkgState::Attesting => self.dkg_part3(index).await,
                DkgState::Complete => Ok(()),
            };

            match res {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Error during DKG step: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Performs the signing steps where required for this signer.
    pub async fn signing_step(&mut self) -> Result<()> {
        let address = self.address;
        let indices: Vec<(u64, u64)> = self
            .client()
            .query(|app: InnerApp| app.aux_frost.signing_action_required(address))
            .await?;

        for (group_index, sig_index) in indices {
            let res = match self
                .client()
                .query(|app: InnerApp| {
                    app.aux_frost
                        .signing_state_with_iteration(group_index, sig_index)
                })
                .await?
            {
                (i, SigningState::Round1) => self.signing_commit(group_index, sig_index, i).await,
                (i, SigningState::Round2) => self.signing_sign(group_index, sig_index, i).await,
                (_i, SigningState::Complete) => Ok(()),
            };

            match res {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Error during signing step: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Queries the [`Config`] for the provided group index.
    async fn get_config(&self, index: u64) -> Result<Config> {
        self.client()
            .query(|app: InnerApp| app.aux_frost.config(index))
            .await
    }

    /// Performs the DKG round 1 step for the given
    /// group index.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part1`].
    async fn dkg_part1(&mut self, index: u64) -> Result<()> {
        let mut rng = thread_rng();
        let config = self.get_config(index).await?;
        let max_signers = config.total_shares();
        let min_signers = config.threshold;

        let mut packages = vec![];
        for i in config.share_range(self.address)? {
            let id = identifier(i);
            let (secret_package, package) = dkg::part1(id, max_signers, min_signers, &mut rng)
                .map_err(|e| Error::App(format!("Error during DKG part 1: {}", e)))?;
            self.dkg_round1.insert((index, i), secret_package);
            packages.push((Adapter { inner: package }, self.comm_pubkey()));
        }

        let packages: LengthVec<u16, (Adapter<dkg::round1::Package>, Pubkey)> =
            packages.try_into()?;
        self.call(|app| build_call!(app.aux_frost.submit_dkg_round1(index, packages.clone())))
            .await?;

        log::info!("Submitted DKG round 1 for group {}", index);

        Ok(())
    }

    /// Performs the DKG round 2 step for the given group index.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part2`].
    async fn dkg_part2(&mut self, index: u64) -> Result<()> {
        let config = self.get_config(index).await?;
        let packages: Vec<(u16, (dkg::round1::Package, Pubkey))> = self
            .client()
            .query(|app: InnerApp| app.aux_frost.dkg_round1_packages(index))
            .await?;

        let round1_packages =
            assemble_by_identifier(packages.iter().map(|(i, (p, _))| (*i, p.clone())));
        let round1_pubkeys: HashMap<frost_secp256k1_tr::Identifier, Pubkey> = packages
            .iter()
            .map(|(i, (_, pk))| (identifier(*i), *pk))
            .collect();

        let mut round2_packages: Vec<
            LengthVec<u16, (u16, Encrypted<Adapter<dkg::round2::Package>>)>,
        > = vec![];
        for i in config.share_range(self.address)? {
            let mut round1_packages = round1_packages.clone();
            round1_packages.remove(&identifier(i));
            let secret_package = self
                .dkg_round1
                .get(&(index, i))
                .ok_or_else(|| Error::App(format!("Missing secret package for participant {}", i)))?
                .clone();
            let (secret_package, round2_package) = dkg::part2(secret_package, &round1_packages)
                .map_err(|e| Error::App(format!("Error during DKG part 2: {}", e)))?;
            self.dkg_round2.insert((index, i), secret_package);
            let round2_package = round2_package
                .into_iter()
                .map(|(i, package)| {
                    let pk = round1_pubkeys.get(&i).unwrap();
                    (
                        i,
                        Encrypted::encrypt(pk.as_slice(), Adapter { inner: package }).unwrap(),
                    )
                })
                .collect();
            round2_packages.push(disassemble_by_identifier(&round2_package).try_into()?);
        }

        let round2_packages: LengthVec<u16, _> = round2_packages.try_into()?;
        self.call(|app| {
            build_call!(app
                .aux_frost
                .submit_dkg_round2(index, round2_packages.clone()))
        })
        .await?;

        log::info!("Submitted DKG round 2 for group {}", index);

        Ok(())
    }

    /// Performs the DKG round 3 step for the given group index and submits the
    /// public key attestation.
    ///
    /// See [`frost_secp256k1_tr::keys::dkg::part3`].
    async fn dkg_part3(&mut self, index: u64) -> Result<()> {
        let config = self.get_config(index).await?;
        let packages: Vec<(u16, (dkg::round1::Package, Pubkey))> = self
            .client()
            .query(|app: InnerApp| app.aux_frost.dkg_round1_packages(index))
            .await?;

        let round1_packages =
            assemble_by_identifier(packages.into_iter().map(|(i, (p, _))| (i, p)));
        let mut last_pubkey_package = None;
        for i in config.share_range(self.address)? {
            let mut round1_packages = round1_packages.clone();
            round1_packages.remove(&identifier(i));
            let round2_packages: Vec<(u16, Encrypted<Adapter<dkg::round2::Package>>)> = self
                .client()
                .query(|app: InnerApp| app.aux_frost.dkg_round2_packages(index, i))
                .await?;

            let secret_package = self.dkg_round2.get(&(index, i)).ok_or_else(|| {
                Error::App(format!("Missing secret package for participant {}", i))
            })?;
            let mut decrypted_round2_packages = vec![];

            for (i, encrypted_package) in round2_packages {
                let decrypted =
                    encrypted_package.decrypt(self.comm_secret_key.serialize().as_slice())?;
                decrypted_round2_packages.push((i, decrypted.inner));
            }

            let (key_package, pubkey_package) = dkg::part3(
                secret_package,
                &round1_packages,
                &assemble_by_identifier(decrypted_round2_packages.into_iter()),
            )
            .map_err(|e| Error::App(format!("Error during DKG part 3: {}", e)))?;

            self.with_key_package(|key_packages| {
                log::debug!(
                    "Inserting key package for group {} participant {}",
                    index,
                    i
                );
                key_packages.insert(
                    (index, i),
                    Adapter {
                        inner: key_package.clone(),
                    },
                )?;

                Ok(())
            })?;

            if let Some(ref package) = last_pubkey_package {
                if pubkey_package != *package {
                    return Err(Error::App(
                        "Participants computed different pubkeys".to_string(),
                    ));
                }
            } else {
                last_pubkey_package.replace(pubkey_package);
            }
            if let Some(pubkey) = last_pubkey_package.take() {
                let pubkey = Adapter { inner: pubkey };
                self.call(|app| {
                    build_call!(app.aux_frost.attest_dkg_pubkey(index, pubkey.clone()))
                })
                .await?;

                log::info!("Submitted DKG pubkey attestation for group {}", index);
            }
        }

        Ok(())
    }

    /// Performs the signing round 1 step for the given group index and
    /// participant index.
    ///
    /// See [`frost_secp256k1_tr::round1::commit`].
    async fn signing_commit(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
    ) -> Result<()> {
        let mut rng = thread_rng();
        let config = self.get_config(group_index).await?;
        let mut commitments = vec![];
        for i in config.share_range(self.address)? {
            let key_package: KeyPackage = self.with_key_package(|key_packages| {
                Ok(key_packages
                    .get((group_index, i))?
                    .ok_or_else(|| {
                        Error::App(format!(
                            "Missing key package group {} participant {}",
                            group_index, i
                        ))
                    })?
                    .inner
                    .clone())
            })?;

            let signing_share = key_package.signing_share();
            let (nonces, commitment) = commit(signing_share, &mut rng);
            self.with_signing_nonces(|signing_nonces| {
                signing_nonces.insert(
                    (group_index, sig_index, iteration, i),
                    Adapter {
                        inner: nonces.clone(),
                    },
                )?;

                Ok(())
            })?;
            commitments.push(Adapter { inner: commitment });
        }

        let commitments: LengthVec<u16, Adapter<SigningCommitments>> = commitments.try_into()?;
        self.call(|app| {
            build_call!(app.aux_frost.submit_commitments(
                group_index,
                sig_index,
                iteration,
                commitments.clone()
            ))
        })
        .await?;

        log::info!(
            "Submitted commitment for group {} signature {} iteration {}",
            group_index,
            sig_index,
            iteration
        );

        Ok(())
    }

    /// Performs the signing round 2 step for the given group index and
    /// participant index.
    ///
    /// See [`frost_secp256k1_tr::round2::sign`].
    async fn signing_sign(
        &mut self,
        group_index: u64,
        sig_index: u64,
        iteration: u32,
    ) -> Result<()> {
        let Some(signing_package) = self
            .client()
            .query(|app| {
                app.aux_frost
                    .signing_package(group_index, sig_index)
                    .map(|p| p.map(|p| p.inner))
            })
            .await?
        else {
            return Err(Error::App("No signing package".to_string()));
        };

        let config = self.get_config(group_index).await?;

        let mut sig_shares = vec![];
        for i in config.share_range(self.address)? {
            let key_package: KeyPackage = self.with_key_package(|key_packages| {
                Ok(key_packages
                    .get((group_index, i))?
                    .ok_or_else(|| Error::App("Missing key package".to_string()))?
                    .inner
                    .clone())
            })?;

            if signing_package
                .signing_commitments()
                .get(key_package.identifier())
                .is_none()
            {
                continue;
            }

            let nonces = self.with_signing_nonces(|signing_nonces| {
                Ok(signing_nonces
                    .get((group_index, sig_index, iteration, i))?
                    .ok_or_else(|| Error::App("Missing signing nonces".to_string()))?
                    .inner
                    .clone())
            })?;

            let sig_share = round2::sign(&signing_package, &nonces, &key_package)
                .map_err(|e| Error::App(format!("Error during signing: {}", e)))?;

            sig_shares.push(Adapter { inner: sig_share });
        }

        let sig_shares: LengthVec<u16, Adapter<SignatureShare>> = sig_shares.try_into()?;
        self.call(|app| {
            build_call!(app.aux_frost.submit_sig_shares(
                group_index,
                sig_index,
                iteration,
                sig_shares.clone()
            ))
        })
        .await?;

        log::info!(
            "Submitted signature share for group {} signature {} iteration {}",
            group_index,
            sig_index,
            iteration
        );

        Ok(())
    }

    pub async fn audit(&mut self) -> Result<()> {
        let groups = self
            .client()
            .query(|app| app.aux_frost.completed_groups_for_address(self.address))
            .await?;

        self.with_key_package(|key_packages| {
            for (group_index, shares) in groups.iter() {
                for share in shares {
                    if !key_packages.contains_key((*group_index, *share))? {
                        return Err(Error::App(format!(
                            "Missing key package for group {} share {}",
                            group_index, share
                        )));
                    }
                }
            }
            Ok(())
        })?;

        Ok(())
    }
}
