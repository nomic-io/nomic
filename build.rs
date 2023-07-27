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
        let shell = std::env::var("SHELL").unwrap_or("/bin/bash".to_string());
        println!("using shell: {}", shell);
        let version = if branch_name == "main" {
            todo!()
        } else {
            let toml = include_str!("networks/testnet.toml");
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

        std::process::Command::new(shell)
            .env_clear()
            .env("OUT_DIR", std::env::var("OUT_DIR").unwrap())
            .env("NOMIC_LEGACY_REV", format!("v{}", version))
            .args(["build.sh"])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
    }
}
