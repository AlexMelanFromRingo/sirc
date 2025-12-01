//! TLS certificate management for federated servers
//!
//! Provides self-signed certificate generation and TLS configuration
//! for secure server-to-server connections.

use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// TLS certificate manager for federation
pub struct TlsManager {
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TlsManager {
    /// Create a new TLS manager
    pub fn new(server_name: &str) -> Self {
        let cert_dir = Self::default_cert_dir();
        Self {
            cert_path: cert_dir.join(format!("{}.crt", server_name)),
            key_path: cert_dir.join(format!("{}.key", server_name)),
        }
    }

    /// Get default certificate directory
    pub fn default_cert_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".sirc").join("certs")
    }

    /// Generate a self-signed certificate for this server
    pub fn generate_self_signed(&self, server_name: &str) -> Result<()> {
        info!("Generating self-signed certificate for {}", server_name);

        // Create cert directory if it doesn't exist
        if let Some(parent) = self.cert_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create certificate directory")?;
        }

        // Generate certificate params
        let mut params = CertificateParams::new(vec![server_name.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, server_name);
        params.distinguished_name.push(DnType::OrganizationName, "SIRC Federation");

        // Generate key pair and certificate
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Save certificate
        fs::write(&self.cert_path, cert_pem)
            .context("Failed to write certificate file")?;

        // Save private key
        fs::write(&self.key_path, key_pem)
            .context("Failed to write private key file")?;

        // Set file permissions to user-only on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.key_path, perms)?;
        }

        info!("Certificate saved to {:?}", self.cert_path);
        info!("Private key saved to {:?}", self.key_path);

        Ok(())
    }

    /// Load or generate certificate
    pub fn load_or_generate(&self, server_name: &str) -> Result<()> {
        if !self.cert_path.exists() || !self.key_path.exists() {
            self.generate_self_signed(server_name)?;
        } else {
            info!("Using existing certificate at {:?}", self.cert_path);
        }
        Ok(())
    }

    /// Create server TLS configuration
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        // Load certificate
        let cert_pem = fs::read_to_string(&self.cert_path)
            .context("Failed to read certificate")?;
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate")?;

        // Load private key
        let key_pem = fs::read_to_string(&self.key_path)
            .context("Failed to read private key")?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .context("Failed to parse private key")?
            .context("No private key found")?;

        // Create server config with client verification disabled (for now)
        // In production, you'd want to verify client certificates
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to create server config")?;

        Ok(Arc::new(config))
    }

    /// Create client TLS configuration
    pub fn client_config(&self, trust_all: bool) -> Result<Arc<ClientConfig>> {
        let mut root_store = RootCertStore::empty();

        if trust_all {
            // For testing: trust all certificates (insecure!)
            info!("WARNING: TLS configured to trust all certificates (insecure)");

            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
                .with_no_client_auth();

            return Ok(Arc::new(config));
        }

        // Load trusted certificates from cert directory
        let cert_dir = Self::default_cert_dir();
        if cert_dir.exists() {
            for entry in fs::read_dir(cert_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().and_then(|s| s.to_str()) == Some("crt") {
                    let cert_pem = fs::read_to_string(&path)?;
                    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                        .collect::<Result<Vec<_>, _>>()?;

                    for cert in certs {
                        root_store.add(cert)?;
                    }

                    info!("Added trusted certificate from {:?}", path);
                }
            }
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    /// Get certificate fingerprint for verification
    pub fn fingerprint(&self) -> Result<String> {
        let cert_pem = fs::read_to_string(&self.cert_path)?;
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(cert) = certs.first() {
            let hash = blake3::hash(cert.as_ref());
            Ok(hex::encode(hash.as_bytes()))
        } else {
            anyhow::bail!("No certificate found")
        }
    }
}

/// Dangerous certificate verifier that trusts all certificates
/// ONLY for testing! Do not use in production!
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Trust everything (DANGEROUS!)
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_certificate() {
        let dir = tempdir().unwrap();
        let tls = TlsManager {
            cert_path: dir.path().join("test.crt"),
            key_path: dir.path().join("test.key"),
        };

        tls.generate_self_signed("test.sirc").unwrap();

        assert!(tls.cert_path.exists());
        assert!(tls.key_path.exists());
    }

    #[test]
    fn test_load_or_generate() {
        let dir = tempdir().unwrap();
        let tls = TlsManager {
            cert_path: dir.path().join("test2.crt"),
            key_path: dir.path().join("test2.key"),
        };

        // First call generates
        tls.load_or_generate("test2.sirc").unwrap();
        let fingerprint1 = tls.fingerprint().unwrap();

        // Second call loads same cert
        tls.load_or_generate("test2.sirc").unwrap();
        let fingerprint2 = tls.fingerprint().unwrap();

        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_server_config() {
        let dir = tempdir().unwrap();
        let tls = TlsManager {
            cert_path: dir.path().join("test3.crt"),
            key_path: dir.path().join("test3.key"),
        };

        tls.generate_self_signed("test3.sirc").unwrap();
        let _config = tls.server_config().unwrap();

        // Config should be created successfully
    }
}
