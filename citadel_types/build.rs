fn main() {
    #[cfg(feature = "typescript")]
    {
        use std::env;
        use std::path::PathBuf;

        // Set the output directory for TypeScript types
        let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("citadel-protocol-types-ts");

        println!("cargo:rustc-env=TS_RS_EXPORT_DIR={}", out_dir.display());
    }
}
