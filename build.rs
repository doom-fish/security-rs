use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if env::var("DOCS_RS").is_ok() {
        return;
    }

    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
