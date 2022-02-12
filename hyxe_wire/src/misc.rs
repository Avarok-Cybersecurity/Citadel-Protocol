use openssl::pkcs12::ParsedPkcs12;
use std::path::Path;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::pkey::{PKey, Private};
use rustls::{Certificate, PrivateKey};

pub fn read_pkcs_12_der_to_quinn_keys<P: AsRef<Path>>(path: P, password: &str) -> Result<(Vec<Certificate>, PrivateKey), anyhow::Error> {
    let der = std::fs::read(path)?;
    pkcs12_to_quinn_keys(&der, password)
}

pub fn pkcs12_to_components(pkcs12_der: &[u8], password: &str) -> Result<(Option<Stack<X509>>, X509, PKey<Private>), anyhow::Error> {
    let openssl_pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12_der)?;
    let ParsedPkcs12 { chain, cert, pkey } = openssl_pkcs12.parse(password)?;
    Ok((chain, cert, pkey))
}

pub fn pkcs12_to_quinn_keys(pkcs12_der: &[u8], password: &str) -> Result<(Vec<Certificate>, PrivateKey), anyhow::Error> {
    let (chain, cert, pkey) = pkcs12_to_components(pkcs12_der, password)?;
    pkcs_12_components_to_quic_keys(chain.as_ref(), &cert, &pkey)
}

pub fn pkcs_12_components_to_quic_keys(chain: Option<&Stack<X509>>, cert: &X509, pkey: &PKey<Private>) -> Result<(Vec<Certificate>, PrivateKey), anyhow::Error> {
    let (cert, key) = cert_and_priv_key_der_to_quic_keys(&cert.to_der()?, &pkey.private_key_to_der()?)?;

    let mut certs = Vec::new();
    certs.push(cert);

    if let Some(chain) = chain {
        for cert in chain {
            certs.push(Certificate(cert.to_der()?));
        }
    }

    Ok((certs, key))
}

pub fn cert_and_priv_key_der_to_quic_keys(cert_der: &[u8], priv_key_der: &[u8]) -> Result<(Certificate, PrivateKey), anyhow::Error> {
    let key = PrivateKey(priv_key_der.to_vec());
    let cert = Certificate(cert_der.to_vec());
    Ok((cert, key))
}