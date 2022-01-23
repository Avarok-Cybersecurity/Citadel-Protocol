use quinn::{CertificateChain, PrivateKey, Certificate};
use openssl::pkcs12::ParsedPkcs12;
use std::path::Path;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::pkey::{PKey, Private};

pub fn read_pkcs_12_der_to_quinn_keys<P: AsRef<Path>>(path: P, password: &str) -> Result<(CertificateChain, PrivateKey), anyhow::Error> {
    let der = std::fs::read(path)?;
    pkcs12_to_quinn_keys(&der, password)
}

pub fn pkcs12_to_components(pkcs12_der: &[u8], password: &str) -> Result<(Option<Stack<X509>>, X509, PKey<Private>), anyhow::Error> {
    let openssl_pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12_der)?;
    let ParsedPkcs12 { chain, cert, pkey } = openssl_pkcs12.parse(password)?;
    Ok((chain, cert, pkey))
}

pub fn pkcs12_to_quinn_keys(pkcs12_der: &[u8], password: &str) -> Result<(CertificateChain, PrivateKey), anyhow::Error> {
    let (chain, cert, pkey) = pkcs12_to_components(pkcs12_der, password)?;
    pkcs_12_components_to_quic_keys(chain.as_ref(), &cert, &pkey)
}

pub fn pkcs_12_components_to_quic_keys(chain: Option<&Stack<X509>>, cert: &X509, pkey: &PKey<Private>) -> Result<(CertificateChain, PrivateKey), anyhow::Error> {
    let (cert, key) = cert_and_priv_key_der_to_quic_keys(&cert.to_der()?, &pkey.private_key_to_der()?)?;

    let mut certs = Vec::new();
    certs.push(cert);

    if let Some(chain) = chain {
        for cert in chain {
            certs.push(quinn::Certificate::from_der(&cert.to_der()?)?);
        }
    }

    Ok((quinn::CertificateChain::from_certs(certs), key))
}

pub fn cert_and_priv_key_der_to_quic_keys(cert_der: &[u8], priv_key_der: &[u8]) -> Result<(Certificate, PrivateKey), anyhow::Error> {
    let key = quinn::PrivateKey::from_der(priv_key_der)?;
    let cert = quinn::Certificate::from_der(cert_der)?;
    Ok((cert, key))
}

pub fn is_self_signed_from_bytes(cert_der: &[u8]) -> Option<bool> {
    is_self_signed(&X509::from_der(cert_der).ok()?)
}

/// If the (first) issuer equals the subject name, then the cert is self-signed. Self-signed certs will only have one IN/DN anyways, so only the first matter
pub fn is_self_signed(cert: &X509) -> Option<bool> {
    Some(cert.issuer_name().entries().next()?.data().as_slice() == cert.subject_name().entries().next()?.data().as_slice())
}

#[cfg(test)]
mod tests {
    use crate::misc::{read_pkcs_12_der_to_quinn_keys, is_self_signed};
    use crate::quic::generate_self_signed_cert;
    use openssl::x509::X509;


    #[test]
    fn main() {
        let _ = read_pkcs_12_der_to_quinn_keys("../keys/testing.p12", "mrmoney10").unwrap();
        let (cert, _) = generate_self_signed_cert().unwrap();
        println!("self-signed: {:?}", is_self_signed(&X509::from_der(&cert).unwrap()));
    }
}