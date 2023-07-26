fn main() {
    let branch_name = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .unwrap();
    println!(
        "cargo:rustc-env=GIT_BRANCH={}",
        String::from_utf8(branch_name.stdout).unwrap().trim(),
    );

    #[cfg(feature = "legacy-bin")]
    {
        println!("cargo:rerun-if-changed=build.sh");

        let shell = std::env::var("SHELL").unwrap_or("/bin/bash".to_string());
        println!("using shell: {}", shell);

        // TODO: decide how to configure rev (support multiple?)
        let legacy_rev = "testnet".to_string();

        std::process::Command::new(shell)
            .env_clear()
            .env("OUT_DIR", std::env::var("OUT_DIR").unwrap())
            .env("NOMIC_LEGACY_REV", legacy_rev)
            .args(["build.sh"])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
    }
}
