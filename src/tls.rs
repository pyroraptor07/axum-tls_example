use std::fs::File;
use std::io::BufReader;
use std::iter;
use std::sync::Arc;

use color_eyre::eyre::eyre;
use color_eyre::Result;
use rustls_pemfile::{read_one, Item};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;


pub struct TlsConfig {
    key_file_path: String,
    cert_file_path: String,
}

impl TryFrom<TlsConfig> for TlsAcceptor {
    type Error = color_eyre::Report;

    fn try_from(tls_config: TlsConfig) -> Result<Self> {
        // Import the key and cert files
        let key = import_key(tls_config.key_file_path)?;
        let cert = import_cert(tls_config.cert_file_path)?;

        // Load the Rustls server config
        // https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html
        let tls_server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;

        // Convert to TlsAcceptor on return
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/struct.TlsAcceptor.html#impl-From%3CArc%3CServerConfig%3E%3E
        Ok(Arc::new(tls_server_config).into())
    }
}

fn import_key(key_file_path: String) -> Result<PrivateKey> {
    // Load the file contents
    let f = File::open(key_file_path)?;
    let mut f = BufReader::new(f);

    // Filter the keys out of the file contents
    // Using example from here: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/
    let items: Vec<Vec<u8>> = iter::from_fn(|| read_one(&mut f).transpose())
        .filter_map(|item| {
            match item {
                Ok(item) => {
                    match item {
                        Item::RSAKey(key) => Some(key),
                        Item::PKCS8Key(key) => Some(key),
                        Item::ECKey(key) => Some(key),
                        _ => None,
                    }
                }
                Err(_) => None,
            }
        })
        .collect();

    // Return the first key in the list
    items
        .into_iter()
        .next()
        .ok_or_else(|| eyre!("Key file has no keys!"))
        .map(PrivateKey)
}

fn import_cert(cert_file_path: String) -> Result<Vec<Certificate>> {
    // Load the file contents
    let f = File::open(cert_file_path)?;
    let mut f = BufReader::new(f);

    // Filter the certs out of the file contents
    // Using example from here: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/
    let items: Vec<Certificate> = iter::from_fn(|| read_one(&mut f).transpose())
        .filter_map(|item| {
            match item {
                Ok(item) => {
                    match item {
                        Item::X509Certificate(cert) => Some(Certificate(cert)),
                        _ => None,
                    }
                }
                Err(_) => None,
            }
        })
        .collect();

    if items.is_empty() {
        return Err(eyre!("Cert file has no certs!"));
    }

    // Return the entire cert chain
    Ok(items)
}

pub fn load_tls_config() -> Result<TlsConfig> {
    dotenvy::dotenv().ok();

    let key_file_path = dotenvy::var("RUST_TLS_KEY_FILE")?;
    let cert_file_path = dotenvy::var("RUST_TLS_CERT_FILE")?;

    Ok(TlsConfig {
        key_file_path,
        cert_file_path,
    })
}
