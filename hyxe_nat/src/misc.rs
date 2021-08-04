use quinn::{CertificateChain, PrivateKey};
use openssl::pkcs12::ParsedPkcs12;
use std::path::Path;

pub fn read_pkcs_12_der_to_quinn_keys<P: AsRef<Path>>(path: P, password: &str) -> Result<(CertificateChain, PrivateKey), anyhow::Error> {
    let der = std::fs::read(path)?;
    pkcs12_to_quinn_keys(&der, password)
}

#[allow(unused_variables)]
pub fn pkcs12_to_quinn_keys(pkcs12_der: &[u8], password: &str) -> Result<(CertificateChain, PrivateKey), anyhow::Error> {
    let openssl_pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12_der)?;
    let ParsedPkcs12 { chain, cert, pkey } = openssl_pkcs12.parse(password)?;

    let key = quinn::PrivateKey::from_der(&pkey.private_key_to_der()?)?;
    let cert = quinn::Certificate::from_der(&cert.to_der()?)?;

    let mut certs = Vec::new();
    certs.push(cert);

    if let Some(chain) = chain {
        for cert in chain {
            certs.push(quinn::Certificate::from_der(&cert.to_der()?)?);
        }
    }

    Ok((quinn::CertificateChain::from_certs(certs), key))
}

#[cfg(test)]
mod tests {
    use crate::misc::read_pkcs_12_der_to_quinn_keys;

    #[test]
    fn main() {
        let _ = read_pkcs_12_der_to_quinn_keys("/Users/nologik/satori.net/keys/testing.p12", "mrmoney10").unwrap();
    }
}