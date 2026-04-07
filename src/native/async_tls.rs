// Native async TLS utilities. Consolidates certificate-ignoring TLS for pentesting.
//
// Provides a single `make_dangerous_tls_connector()` that accepts *any*
// server certificate.  This replaces the identical `NoVerify` structs that
// were copy-pasted across mqtt_bruteforce, tapo_c200_vulns, fortisiem, etc.

use std::sync::Arc;

use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

/// A `ServerCertVerifier` that accepts every certificate without validation.
///
/// **This is intentionally insecure** — it exists because penetration-testing
/// tools routinely connect to targets with self-signed, expired, or otherwise
/// invalid certificates.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Cached singleton — the config never varies so we build it once.
static DANGEROUS_TLS: std::sync::LazyLock<TlsConnector> = std::sync::LazyLock::new(|| {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
});

/// Create a `TlsConnector` that accepts **any** server certificate.
///
/// Returns a cached singleton — `TlsConnector` wraps `Arc<ClientConfig>`,
/// so the clone is cheap (just an Arc bump).
///
/// ```ignore
/// let connector = crate::native::async_tls::make_dangerous_tls_connector();
/// let tls_stream = connector.connect(server_name, tcp_stream).await?;
/// ```
#[inline]
pub fn make_dangerous_tls_connector() -> TlsConnector {
    DANGEROUS_TLS.clone()
}
