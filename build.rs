fn main() {
    let branch_name = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .unwrap();
    let branch_name = String::from_utf8(branch_name.stdout)
        .unwrap()
        .trim()
        .to_string();
    println!("cargo:rustc-env=GIT_BRANCH={}", branch_name);

    #[cfg(feature = "legacy-bin")]
    {
        println!("cargo:rerun-if-changed=build.sh");
        println!("cargo:rerun-if-env-changed=NOMIC_LEGACY_VERSION");
        println!("cargo:rerun-if-env-changed=NOMIC_LEGACY_REV");

        let version = std::env::var("NOMIC_LEGACY_VERSION");
        let rev = std::env::var("NOMIC_LEGACY_REV");

        let rev = if let Ok(rev) = rev {
            rev
        } else {
            let mut version_req_str = if let Ok(version_req_str) = version {
                version_req_str
            } else {
                #[cfg(feature = "testnet")]
                let toml = {
                    println!("cargo:rerun-if-changed=networks/testnet.toml");
                    include_str!("networks/testnet.toml")
                };
                #[cfg(not(feature = "testnet"))]
                let toml = {
                    println!("cargo:rerun-if-changed=networks/stakenet.toml");
                    include_str!("networks/stakenet.toml")
                };
                let config: toml::Value = toml::from_str(toml).unwrap();
                config
                    .as_table()
                    .unwrap()
                    .get("legacy_version")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            if version_req_str.chars().next().unwrap().is_numeric() {
                version_req_str = format!("={}", version_req_str);
            }
            let version_req = semver::VersionReq::parse(&version_req_str).unwrap();

            assert!(std::process::Command::new("git")
                .args(["fetch", "--tags", "--force"])
                .spawn()
                .unwrap()
                .wait_with_output()
                .unwrap()
                .status
                .success());
            let version = std::process::Command::new("git")
                .args(["tag"])
                .output()
                .unwrap()
                .stdout
                .split(|&b| b == b'\n')
                .map(|b| String::from_utf8(b.to_vec()).unwrap())
                .filter(|s| s.starts_with('v'))
                .filter_map(|s| semver::Version::parse(&s[1..]).ok())
                .filter(|v| version_req.matches(v))
                .max()
                .unwrap();
            println!(
                "Highest matching git tag for version requirement '{}': v{}",
                version_req_str, version,
            );
            format!("v{}", version)
        };
        println!("Using rev: {}", rev);

        let shell = std::env::var("SHELL").unwrap_or("/bin/bash".to_string());
        println!("Using shell: {}", shell);

        #[cfg(feature = "testnet")]
        let default_features = "full,feat-ibc,testnet";
        #[cfg(not(feature = "testnet"))]
        let default_features = "full,feat-ibc";

        let cargo_features =
            std::env::var("NOMIC_LEGACY_FEATURES").unwrap_or(default_features.to_string());

        let forwarded_envvars = [
            "OUT_DIR",
            "PATH",
            "NOMIC_CLEANUP_LEGACY_BUILD",
            "ROCKSDB_LIB_DIR",
            "ROCKSDB_STATIC",
        ];

        let mut cmd = std::process::Command::new(shell);
        cmd.env_clear();

        for var in forwarded_envvars {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        let res = cmd
            .env("NOMIC_LEGACY_REV", rev)
            .env("CARGO_FEATURES", cargo_features)
            .args(["build.sh"])
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(res.status.success());
    }
}
