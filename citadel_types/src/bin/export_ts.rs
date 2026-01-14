#[cfg(feature = "typescript")]
use citadel_types::errors::*;
#[cfg(feature = "typescript")]
use citadel_types::prelude::*;
#[cfg(feature = "typescript")]
use citadel_types::proto::*;
#[cfg(feature = "typescript")]
use citadel_types::user::*;
#[cfg(feature = "typescript")]
use ts_rs::TS;

#[cfg(feature = "typescript")]
fn export_types() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::Path;

    // Create the output directory if it doesn't exist
    let output_dir = Path::new("../citadel-protocol-types-ts/src");
    fs::create_dir_all(output_dir)?;

    // Set the TS_RS_EXPORT_DIR environment variable
    std::env::set_var("TS_RS_EXPORT_DIR", output_dir.canonicalize()?);

    // Export user types
    MutualPeer::export()?;
    PeerInfo::export()?;
    UserIdentifier::export()?;

    // Export proto types
    ConnectMode::export()?;
    VirtualObjectMetadata::export()?;
    ObjectId::export()?;
    ObjectTransferOrientation::export()?;
    ObjectTransferStatus::export()?;
    SessionSecuritySettings::export()?;
    UdpMode::export()?;
    MemberState::export()?;
    GroupMemberAlterMode::export()?;
    MessageGroupOptions::export()?;
    GroupType::export()?;
    MessageGroupKey::export()?;
    TransferType::export()?;

    // Export connection types
    ClientConnectionType::export()?;
    PeerConnectionType::export()?;
    VirtualConnectionType::export()?;

    // Export crypto types
    CryptoParameters::export()?;
    EncryptionAlgorithm::export()?;
    SecrecyMode::export()?;
    KemAlgorithm::export()?;
    SigAlgorithm::export()?;
    SecurityLevel::export()?;
    HeaderObfuscatorSettings::export()?;
    PreSharedKey::export()?;

    // Export error types
    Error::export()?;

    println!("TypeScript types exported successfully!");
    Ok(())
}

fn main() {
    #[cfg(feature = "typescript")]
    {
        if let Err(e) = export_types() {
            eprintln!("Error exporting TypeScript types: {}", e);
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "typescript"))]
    {
        eprintln!("The typescript feature must be enabled to export types.");
        eprintln!("Run with: cargo run --bin export_ts --features typescript");
        std::process::exit(1);
    }
}
