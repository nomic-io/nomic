use orga::merk::MerkStore;

#[test]
fn fresh_local_network() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_nomic"));
    cmd.env("STOP_HEIGHT", "2");
    cmd.args(["start", "--home", home.to_str().unwrap()]);

    let output = cmd.spawn().unwrap().wait_with_output().unwrap();
    assert_eq!(output.status.code().unwrap(), 138);

    let package_ver = env!("CARGO_PKG_VERSION");
    assert!(home.join(format!("bin/nomic-{}", package_ver)).exists());
    assert!(home.join("tendermint/config/genesis.json").exists());

    {
        let store = MerkStore::new(home.join("merk"));
        assert_eq!(
            store.merk().get_aux(b"height").unwrap().unwrap(),
            2u64.to_be_bytes().to_vec(),
        );
    }

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_nomic"));
    cmd.env("STOP_HEIGHT", "4");
    cmd.args(["start", "--home", home.to_str().unwrap()]);

    let output = cmd.spawn().unwrap().wait_with_output().unwrap();
    assert_eq!(output.status.code().unwrap(), 138);

    {
        let store = MerkStore::new(home.join("merk"));
        assert_eq!(
            store.merk().get_aux(b"height").unwrap().unwrap(),
            4u64.to_be_bytes().to_vec(),
        );
    }
}
