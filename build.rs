fn main() {
    let branch_name = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .unwrap();
    println!(
        "cargo:rustc-env=GIT_BRANCH={}",
        String::from_utf8(branch_name.stdout).unwrap().trim(),
    );
}
