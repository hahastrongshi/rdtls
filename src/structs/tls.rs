use serde::Serialize;
use tls_parser::{TlsVersion, TlsClientHelloContents, TlsServerHelloContents, TlsClientKeyExchangeContents};

#[derive(Debug, PartialEq, Serialize)]
pub enum TLS {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    ClientKeyExchange(ClientKeyExchange),
}

impl TLS {
    pub fn len(&self) -> usize {
        0
    }
}

fn tls_version(ver: TlsVersion) -> Option<&'static str> {
    match ver {
        TlsVersion::Ssl30 => Some("ssl3.0"),
        TlsVersion::Tls10 => Some("tls1.0"),
        TlsVersion::Tls11 => Some("tls1.1"),
        TlsVersion::Tls12 => Some("tls1.2"),
        TlsVersion::Tls13 => Some("tls1.3"),
        _                 => None,
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ClientHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
}

impl ClientHello {
    pub fn new(ch: &TlsClientHelloContents, hostname: Option<String>) -> ClientHello {
        let session_id = ch.session_id.map(base64::encode);

        ClientHello {
            version: tls_version(ch.version),
            session_id,
            hostname,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ServerHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub cipher: Option<&'static str>,
}

impl ServerHello {
    pub fn new(sh: &TlsServerHelloContents) -> ServerHello {
        let cipher = sh.cipher.get_ciphersuite()
            .map(|cs| cs.name);
        let session_id = sh.session_id.map(base64::encode);

        ServerHello {
            version: tls_version(sh.version),
            session_id,
            cipher,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ClientKeyExchange {
    //pub version: Option<&'static str>,
    pub premaster_secret: Option<Vec<u8>>,
}

impl ClientKeyExchange {
    pub fn new(cke: &TlsClientKeyExchangeContents) -> ClientKeyExchange {
        let client_key_exchange = cke.parameters.to_vec();

        ClientKeyExchange {
            premaster_secret: Option::from(client_key_exchange),
        }
    }
}
