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

        let mut version_req_str = if let Ok(version_req_str) = std::env::var("NOMIC_LEGACY_VERSION")
        {
            version_req_str
        } else {
            let toml = if branch_name == "main" {
                todo!()
            } else {
                println!("cargo:rerun-if-changed=networks/testnet.toml");
                include_str!("networks/testnet.toml")
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
            .args(["fetch", "--tags"])
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
        let rev = format!("v{}", version);
        println!(
            "Highest matching git tag for version requirement '{}': {}",
            version_req_str, rev,
        );

        let shell = std::env::var("SHELL").unwrap_or("/bin/bash".to_string());
        println!("Using shell: {}", shell);
        let res = std::process::Command::new(shell)
            .env_clear()
            .env("OUT_DIR", std::env::var("OUT_DIR").unwrap())
            .env("NOMIC_LEGACY_REV", rev)
            .args(["build.sh"])
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(res.status.success());
    }
}
