use crate::structs::tls;
use crate::errors::ProtocolParseError;

use crate::structs::tls::{TLS, ClientHello, ServerHello, ClientKeyExchange};
use std::str;
use tls_parser::{TlsMessage, TlsMessageHandshake, TlsExtension, parse_tls_extension};

pub fn extract(remaining: &[u8]) -> Result<tls::TLS, ProtocolParseError> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut hostname = None;

                    if let Some(mut remaining) = ch.ext {
                        while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                            remaining = remaining2;
                            if let TlsExtension::SNI(sni) = ext {
                                for s in sni {
                                    let name = str::from_utf8(s.1)
                                        .map_err(|_| ProtocolParseError::ParsingError)?;
                                    hostname = Some(name.to_owned());
                                }
                            }
                        }

                        return Ok(TLS::ClientHello(ClientHello::new(&ch, hostname)));
                    }
                },
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    return Ok(TLS::ServerHello(ServerHello::new(&sh)));
                },
                TlsMessage::Handshake(TlsMessageHandshake::ClientKeyExchange(cke)) => {
                    println!("client key exchange, len: {}", cke.parameters.len());
                    return Ok(TLS::ClientKeyExchange(ClientKeyExchange::new(&cke)))
                }
                _ => (),
            }
        }

        Err(ProtocolParseError::ParsingError)
    } else {
        Err(ProtocolParseError::WrongProtocol)
    }
}
