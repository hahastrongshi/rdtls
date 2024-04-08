//! TLS handshake parser.
//!
//! The TLS handshake parser uses a [fork](https://github.com/thegwan/tls-parser) of the
//! [tls-parser](https://docs.rs/tls-parser/latest/tls_parser/) crate to parse the handshake phase
//! of a TLS connection. It maintains TLS state, stores selected parameters, and handles
//! defragmentation.
//!
//! Adapted from [the Rusticata TLS
//! parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs).

use std::fs::File;
use super::handshake::{
    Certificate, ClientDHParams, ClientECDHParams, ClientHello, ClientKeyExchange, ClientRSAParams,
    KeyShareEntry, ServerDHParams, ServerECDHParams, ServerHello, ServerKeyExchange,
    ServerRSAParams,
};
use super::Tls;
use crate::conntrack::conn::conn_info::{ConnInfo, ConnState, TlsInfo};
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{ConnParsable, ParseResult, ProbeResult, Session, SessionData};

use tls_parser::*;
extern crate openssl;


use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use std::io;
use std::io::Read;
use tls_decrypt::decrypt;
use tls_parser::nom::combinator::complete;
use tls_parser::nom::error::{Error, ErrorKind, make_error};
use tls_parser::nom::multi::many1;

extern crate tls_decrypt;

/// Parses a single TLS handshake per connection.
#[derive(Debug)]
pub struct TlsParser {
    sessions: Vec<Tls>,
    key_length: usize,
}

impl TlsParser {}

impl Default for TlsParser {
    fn default() -> Self {
        TlsParser {
            sessions: vec![Tls::new()],
            key_length: 0,
        }
    }
}

impl ConnParsable for TlsParser {
    fn parse(&mut self, pdu: &L4Pdu, tls_info: &mut TlsInfo) -> ParseResult {
        log::debug!("Updating parser tls");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.sessions[0].parse_tcp_level(data, pdu.dir, tls_info)
        } else {
            log::warn!("Malformed packet");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() <= 2 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            // First byte is record type (between 0x14 and 0x17, 0x16 is handhake) Second is TLS
            // version major (0x3) Third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
            // Does not support versions <= SSLv2
            match (data[0], data[1], data[2]) {
                (0x14..=0x17, 0x03, 0..=3) => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|tls| Session {
            data: SessionData::Tls(Box::new(tls)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|tls| Session {
                data: SessionData::Tls(Box::new(tls)),
                id: 0,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Remove
    }

    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Remove
    }
}

// ------------------------------------------------------------

impl Tls {
    /// Allocate a new TLS handshake instance.
    pub(crate) fn new() -> Tls {
        Tls {
            client_hello: None,
            server_hello: None,
            server_certificates: vec![],
            client_certificates: vec![],
            server_key_exchange: None,
            client_key_exchange: None,
            state: TlsState::None,
            tcp_buffer: vec![],
            record_buffer: vec![],
        }
    }

    /// Parse a ClientHello message.
    pub(crate) fn parse_handshake_clienthello(&mut self, content: &TlsClientHelloContents) {
        let mut client_hello = ClientHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suites: content.ciphers.to_vec(),
            compression_algs: content.comp.to_vec(),
            ..ClientHello::default()
        };

        let ext = parse_tls_client_hello_extensions(content.ext.unwrap_or(b""));
        log::trace!("client extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    client_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::SNI(ref v) => {
                            if !v.is_empty() {
                                let sni = v[0].1;
                                client_hello.server_name = Some(match std::str::from_utf8(sni) {
                                    Ok(name) => name.to_string(),
                                    Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(sni)),
                                });
                            }
                        }
                        TlsExtension::SupportedGroups(ref v) => {
                            client_hello.supported_groups = v.clone();
                        }
                        TlsExtension::EcPointFormats(v) => {
                            client_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::SignatureAlgorithms(ref v) => {
                            client_hello.signature_algs = v.clone();
                        }
                        TlsExtension::ALPN(ref v) => {
                            for proto in v {
                                client_hello.alpn_protocols.push(
                                    match std::str::from_utf8(proto) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => {
                                            format!("<Invalid UTF-8: {}>", hex::encode(proto))
                                        }
                                    },
                                );
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Client Shares: {:?}", v);
                            client_hello.key_shares = v
                                .iter()
                                .map(|k| KeyShareEntry {
                                    group: k.group,
                                    kx_data: k.kx.to_vec(),
                                })
                                .collect();
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            client_hello.supported_versions = v.clone();
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.client_hello = Some(client_hello);
    }

    /// Parse a ServerHello message.
    fn parse_handshake_serverhello(&mut self, content: &TlsServerHelloContents) {
        let mut server_hello = ServerHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suite: content.cipher,
            compression_alg: content.compression,
            ..ServerHello::default()
        };

        let ext = parse_tls_server_hello_extensions(content.ext.unwrap_or(b""));
        log::debug!("server_hello extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    server_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::EcPointFormats(v) => {
                            server_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::ALPN(ref v) => {
                            if !v.is_empty() {
                                server_hello.alpn_protocol =
                                    Some(match std::str::from_utf8(v[0]) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(v[0])),
                                    });
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Server Share: {:?}", v);
                            if !v.is_empty() {
                                server_hello.key_share = Some(KeyShareEntry {
                                    group: v[0].group,
                                    kx_data: v[0].kx.to_vec(),
                                });
                            }
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            if !v.is_empty() {
                                server_hello.selected_version = Some(v[0]);
                            }
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.server_hello = Some(server_hello);
    }

    /// Parse a Certificate message.
    fn parse_handshake_certificate(&mut self, content: &TlsCertificateContents, direction: bool) {
        log::trace!("cert chain length: {}", content.cert_chain.len());
        if direction {
            // client -> server
            for cert in &content.cert_chain {
                self.client_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        } else {
            // server -> client
            for cert in &content.cert_chain {
                self.server_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        }
    }

    /// Parse a ServerKeyExchange message.
    fn parse_handshake_serverkeyexchange(&mut self, content: &TlsServerKeyExchangeContents) {
        log::trace!("SKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_sig, ref parsed)) = parse_server_ecdh_params(content.parameters) {
                        if let ECParametersContent::NamedGroup(curve) =
                            parsed.curve_params.params_content
                        {
                            let ecdh_params = ServerECDHParams {
                                curve,
                                kx_data: parsed.public.point.to_vec(),
                            };
                            self.server_key_exchange = Some(ServerKeyExchange::Ecdh(ecdh_params));
                        };
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_sig, ref parsed)) = parse_server_dh_params(content.parameters) {
                        let dh_params = ServerDHParams {
                            prime: parsed.dh_p.to_vec(),
                            generator: parsed.dh_g.to_vec(),
                            kx_data: parsed.dh_ys.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_sig, ref parsed)) = parse_server_rsa_params(content.parameters) {
                        let rsa_params = ServerRSAParams {
                            modulus: parsed.modulus.to_vec(),
                            exponent: parsed.exponent.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.server_key_exchange =
                        Some(ServerKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
    }

    /// Parse a ClientKeyExchange message.
    fn parse_handshake_clientkeyexchange(&mut self, content: &TlsClientKeyExchangeContents) {
        log::trace!("CKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_rem, ref parsed)) = parse_client_ecdh_params(content.parameters) {
                        let ecdh_params = ClientECDHParams {
                            kx_data: parsed.ecdh_yc.point.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Ecdh(ecdh_params));
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_rem, ref parsed)) = parse_client_dh_params(content.parameters) {
                        let dh_params = ClientDHParams {
                            kx_data: parsed.dh_yc.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_rem, ref parsed)) = parse_client_rsa_params(content.parameters) {
                        let rsa_params = ClientRSAParams {
                            encrypted_pms: parsed.data.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.client_key_exchange =
                        Some(ClientKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
        //self.client_key_exchange = Some(client_key_exchange);
    }

    /// Parse a TLS message.
    pub(crate) fn parse_message_level(&mut self, msg: &TlsMessage, direction: bool, tls_info: &mut TlsInfo) -> ParseResult {
        log::trace!("parse_message_level {:?}", msg);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
           // return ParseResult::Done(0);
        }

        // update state machine
        match tls_state_transition(self.state, msg, direction) {
            Ok(s) => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
            }
        };
        log::trace!("TLS new state: {:?}", self.state);

        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => match *m {
                TlsMessageHandshake::ClientHello(ref content) => {
                    self.parse_handshake_clienthello(content);
                }
                TlsMessageHandshake::ServerHello(ref content) => {
                    self.parse_handshake_serverhello(content);
                }
                TlsMessageHandshake::Certificate(ref content) => {
                    self.parse_handshake_certificate(content, direction);
                }
                TlsMessageHandshake::ServerKeyExchange(ref content) => {
                    self.parse_handshake_serverkeyexchange(content);
                    println!("process serverkeyexchange ...");
                }
                TlsMessageHandshake::ClientKeyExchange(ref content) => {
                    self.parse_handshake_clientkeyexchange(content);
                    println!("process clientkeyexchange ...");
                    // todo 添加 密码解析
                    let (key_length, client_write_key, server_write_key, client_write_iv, server_write_iv) = self.decode_tls();

                    tls_info.client_cipher = Some(Box::new(decrypt::AesGCM128Sha256Decryptor::new(Vec::from(client_write_key), Vec::from(client_write_iv))));
                    tls_info.server_cipher = Some(Box::new(decrypt::AesGCM128Sha256Decryptor::new(Vec::from(server_write_key), Vec::from(server_write_iv))));
                }
                _ => (),
            },
            TlsMessage::Alert(ref a) => {
                if a.severity == TlsAlertSeverity::Fatal {
                    return ParseResult::Done(0);
                }
            }
            TlsMessage::ApplicationData(ref a) => {
               println!("ApplicationData: length: {}", a.blob.len());
                // todo 补充数据解密的过程, 传入 connInfo，然后将数据发送出去
                let mut decrypt_data = Vec::new();
                if (direction) {
                    decrypt_data = tls_info.client_cipher.as_ref().unwrap().decrypt(a.blob);
                    println!("解密后的数据: {:?}", decrypt_data);
                } else {
                    decrypt_data = tls_info.server_cipher.as_ref().unwrap().decrypt(a.blob);
                    println!("解密后的数据: {:?}", decrypt_data);
                }

                let newline = b"\r\n";
                // 将 decrypt_data 按照 newline 进行切割
                let mut result = Vec::new();
                let mut start = 0;
                for (i, &item) in decrypt_data.iter().enumerate() {
                    if item == newline[0] {
                        if decrypt_data[i + 1] == newline[1] {
                            result.push(&decrypt_data[start..i]);
                            // 将 截取 的数据转换为 utf8 格式输出
                            let s = std::str::from_utf8(&decrypt_data[start..i]).unwrap();
                            println!("s: {}", s);
                            start = i + 2;
                        }
                    }
                }
                return ParseResult::Data(decrypt_data);
            }
            _ => (),
        }

        ParseResult::Continue(0)
    }

    /// Parse a TLS record.
    pub(crate) fn parse_record_level(
        &mut self,
        record: &TlsRawRecord<'_>,
        direction: bool,
        tls_info: &mut TlsInfo
    ) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);

        log::trace!("parse_record_level ({} bytes)", record.data.len());
        log::trace!("{:?}", record.hdr);
        // log::trace!("{:?}", record.data);

        // do not parse if session is encrypted
        // todo 这里需要修改， tls 解密
        if self.state == TlsState::Finished {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        }

        // only parse some message types (the Content type, first byte of TLS record)
        match record.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake => (),
            TlsRecordType::Alert => (),
            TlsRecordType::ApplicationData => (), // 补充这里的逻辑
            _ => return ParseResult::Continue(0),
        }

        // Check if a record is being defragmented
        let record_buffer = match self.record_buffer.len() {
            0 => record.data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.record_buffer.len() + record.data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.record_buffer.split_off(0);
                v.extend_from_slice(record.data);
                v.as_slice()
            }
        };

        // TODO: record may be compressed Parse record contents as plaintext
        match self.parse_tls_record_with_header1(record_buffer, &record.hdr) {
            Ok((rem, ref msg_list)) => {
                for msg in msg_list {
                    // 这里是解析 client hello 等信息
                    status = self.parse_message_level(msg, direction, tls_info);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                if !rem.is_empty() {
                    log::debug!("warn: extra bytes in TLS record: {:?}", rem);
                };
            }
            Err(Err::Incomplete(needed)) => {
                log::trace!(
                    "Defragmentation required (TLS record), missing {:?} bytes",
                    needed
                );
                self.record_buffer.extend_from_slice(record.data);
            }
            Err(_e) => {
                log::debug!("warn: parse_tls_record_with_header failed");
                return ParseResult::Skipped;
            }
        };

        status
    }

    #[rustfmt::skip]
    #[allow(clippy::trivially_copy_pass_by_ref)] // TlsRecordHeader is only 6 bytes, but we prefer not breaking current API
    pub fn parse_tls_record_with_header1<'i, 'hdr>(&mut self, i:&'i [u8], hdr:&'hdr TlsRecordHeader ) -> IResult<&'i [u8], Vec<TlsMessage<'i>>> {
        if (hdr.record_type == TlsRecordType::ApplicationData) {
            let reslt = parse_tls_message_applicationdata(i);
            // 返回结果
            return match reslt {
                Ok((rem, ref msg)) => Ok((rem, vec![msg.clone()])),
                Err(e) => Err(e)
            }
        }

        match hdr.record_type {
            TlsRecordType::ChangeCipherSpec => many1(complete(parse_tls_message_changecipherspec))(i),
            TlsRecordType::Alert            => many1(complete(parse_tls_message_alert))(i),
            TlsRecordType::Handshake        => many1(complete(parse_tls_message_handshake))(i),
            TlsRecordType::ApplicationData  => many1(parse_tls_message_applicationdata)(i),
            TlsRecordType::Heartbeat        => parse_tls_message_heartbeat(i, hdr.len),
            _                               => Err(Err::Error(make_error(i, ErrorKind::Switch)))
        }
    }


    /// Parse a TCP segment, handling TCP chunks fragmentation.
    pub(crate) fn parse_tcp_level(&mut self, data: &[u8], direction: bool, tls_info: &mut TlsInfo) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);
        log::trace!("parse_tcp_level ({} bytes)", data.len());
        log::trace!("defrag buffer size: {}", self.tcp_buffer.len());

        // do not parse if session is encrypted
        // todo 这里可能需要删除逻辑
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            //return ParseResult::Done(0);
        };
        // Check if TCP data is being defragmented
        // todo 这里会将 tcp 大包进行拆分， 需要手动进行拆分
        let tcp_buffer = match self.tcp_buffer.len() {
            0 => data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.tcp_buffer.len() + data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.tcp_buffer.split_off(0);
                v.extend_from_slice(data);
                v.as_slice()
            }
        };
        let mut cur_data = tcp_buffer;
        while !cur_data.is_empty() {
            // parse each TLS record in the TCP segment (there could be multiple)
            // todo 这里需要考虑将数据提前解码，即使数据不完整，但是多余的数据在哪里将其传给后面呢
            match parse_tls_raw_record(cur_data) {
                Ok((rem, ref record)) => {
                    cur_data = rem;
                    // 这里在解析数据
                    status = self.parse_record_level(record, direction, tls_info);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                Err(Err::Incomplete(needed)) => {
                    log::trace!(
                        "Defragmentation required (TCP level), missing {:?} bytes",
                        needed
                    );
                    // tls_info 不为 空
                    if tls_info.client_cipher.is_some() {
                        // 这里开始解密数据， 并将多余的数据保存，传递给后面
                        // todo, 这里根据加密算法来提前将后续的数据分解，用于后续的加解密
                        let mut block_size: usize = 0;
                        if direction {
                            block_size = tls_info.client_cipher.as_ref().unwrap().block_size();
                        } else {
                            block_size = tls_info.server_cipher.as_ref().unwrap().block_size();
                        }

                        // 计算 一次可以解密的数据
                        let decrypt_size = ((cur_data.len() - 5) / block_size) * block_size;
                        let (to_decrypt, remain) = cur_data.split_at(decrypt_size + 5);
                        let (i, hdr) = parse_tls_record_header(to_decrypt).unwrap();
                        let remain_length =  hdr.len - decrypt_size as u16;
                        let hdr = TlsRecordHeader {
                            record_type: hdr.record_type,
                            version: hdr.version,
                            len: decrypt_size as u16,
                        };

                        let record = TlsRawRecord {
                            hdr: hdr,
                            data: to_decrypt,
                        };

                        // 将剩余的数据保存
                        // todo 需要将上一次的解密数据保存到 暂存中，留给下次 segment 解密使用
                        let high_byte = (remain_length >> 8) as u8;
                        let low_byte = (remain_length & 0xff) as u8;
                        self.tcp_buffer.extend_from_slice(vec![23, 3, 3, high_byte, low_byte].as_slice());
                        self.tcp_buffer.extend_from_slice(remain);

                        status = self.parse_record_level(&record, direction, tls_info);
                        if status != ParseResult::Continue(0) {
                            return status;
                        }

                        break;

                    }
                    self.tcp_buffer.extend_from_slice(cur_data);
                    break;
                }
                Err(_e) => {
                    log::debug!("warn: Parsing raw record failed");
                    break;
                }
            }
        }
        status
    }

    fn decode_tls(&mut self) -> (usize, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let client_key_exchange = self.client_key_exchange.as_ref().unwrap();
        // extract vec from client
        let client_key_exchange = match client_key_exchange {
            ClientKeyExchange::Rsa(client_rsa_params) => {
                client_rsa_params.encrypted_pms.to_vec()
            }
            _ => {
                println!("not support");
                return (0, Vec::new(), Vec::new(), Vec::new(), Vec::new())
            }
        };

        let private_key_file_path = "ztgame.key";
        let private_key = self.read_key_file(private_key_file_path).unwrap();

        let decode_premaster_secret = match tls_decrypt::tls::decrypt_premaster_secret(client_key_exchange, &*private_key) {
            Ok(premaster_secrete) => premaster_secrete,
            Err(e) =>  return (0, Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };

        // let decode_premaster_secret = match self.decrypt_premaster_secret(client_key_exchange, &*private_key){
        //     Ok(premaster_secrete) => premaster_secrete,
        //     Err(e) =>  return
        // };

        // 从premaster secret计算master secret
        let mut client_random = self.client_hello.as_ref().unwrap().random.to_vec();
        let mut server_random = self.server_hello.as_ref().unwrap().random.to_vec();

        let master_secret = tls_decrypt::tls::generate_master_secret(&*decode_premaster_secret, &*client_random, &*server_random);
        // let master_secret = self.generate_master_secret(&*decode_premaster_secret, &*client_random, &*server_random);

        // 根据TLS 1.2规范，我们需要生成的密钥材料长度
        let key_material_length = 2 * (16 + 0 + 4); // 对于AES-128-CBC和SHA-256的组合

        let key_material = tls_decrypt::tls::derive_key_material(&master_secret, &*client_random, &*server_random, key_material_length);

        // 分割key_material以获得所需的密钥和IV
        // 注意：实际分割方法取决于你的加密套件和TLS版本
        let client_write_key;
        let server_write_key;
        let client_write_iv;
        let server_write_iv;
        if key_material_length == 40 {
            client_write_key = &key_material[0..16];
            server_write_key = &key_material[16..32];
            client_write_iv = &key_material[32..36];
            server_write_iv = &key_material[36..40];
        } else {
            client_write_key = &key_material[64..80];
            server_write_key = &key_material[80..96];
            client_write_iv = &key_material[96..112];
            server_write_iv = &key_material[112..128];
        }

        // 输出以验证
        println!("Client Write Key: {:?}", client_write_key);
        println!("Server Write Key: {:?}", server_write_key);
        println!("Client Write IV: {:?}", client_write_iv);
        println!("Server Write IV: {:?}", server_write_iv);

        // 返回数据需要拷贝，后续优化
        (key_material_length, Vec::from(client_write_key.clone()), Vec::from(server_write_key.clone()), Vec::from(client_write_iv.clone()), Vec::from(server_write_iv.clone()))
    }

    fn read_key_file(&mut self, private_key_file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 读取私钥文件
        let mut file = File::open(private_key_file_path)?;
        let mut private_key_pem = Vec::new();
        file.read_to_end(&mut private_key_pem)?;
        Ok(private_key_pem)
    }


    // fn decrypt_premaster_secret(&mut self, encrypted_premaster: Vec<u8>, private_key_pem: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    //     // 从PEM格式加载私钥
    //     let rsa = Rsa::private_key_from_pem(private_key_pem)?;
    //     //let rsa = ring_rsa::KeyPair::from_pkcs8(&private_key_pem)?;
    //
    //
    //     // 解密premaster secret
    //     let mut decrypted_premaster = vec![0; rsa.size() as usize];
    //     let _ = rsa.private_decrypt(&*encrypted_premaster, &mut decrypted_premaster, Padding::PKCS1)?;
    //
    //     // 移除解密后的premaster secret中的填充数据
    //     Ok(decrypted_premaster.into_iter().filter(|&x| x != 0).collect())
    // }


    // rsa_cbc_128_sha256
    // 每次解密的 IV 都是在数据前 16 字节
// 需要自己维护一个列表， cipher -> length of IV, Mac, Key
// 将下面的 prf， 相关的代码
//     pub fn prf_raw(&mut self, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
//         let mut hmac_key = hmac::Key::new(hmac::HMAC_SHA256, secret);
//         let mut current_a = self.sign(&hmac_key, &[label, seed]);
//
//         let chunk_size = hmac_key.algorithm().digest_algorithm().output_len();
//         for chunk in out.chunks_mut(chunk_size) {
//             // P_hash[i] = HMAC_hash(secret, A(i) + seed)
//             let p_term = self.sign(&hmac_key,  &[current_a.as_ref(), label, seed]);
//             chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);
//
//             // A(i+1) = HMAC_hash(secret, A(i))
//             current_a = self.sign(&hmac_key, &[current_a.as_ref()])  ;
//         }
//
//     }

    // fn sign(&mut self, hmac_key: &hmac::Key, data: &[&[u8]]) -> Tag {
    //     let first = &[];
    //     let last = &[];
    //     let mut ctx = hmac::Context::with_key(hmac_key);
    //     ctx.update(first);
    //     for d in data {
    //         ctx.update(d);
    //     }
    //     ctx.update(last);
    //     ctx.sign()
    // }


    // pub fn derive_key_material(&mut self, master_secret: &[u8], client_random: &[u8], server_random: &[u8], key_material_length: usize) -> Vec<u8> {
    //     let label = b"key expansion";
    //
    //     let mut seed = Vec::new();
    //     seed.extend_from_slice(&*server_random);
    //     seed.extend_from_slice(&*client_random);
    //
    //     let mut out = vec![0u8; key_material_length];
    //
    //     self.prf_raw(master_secret, label.as_ref(), seed.as_ref(), &mut out);
    //     out
    // }

    // fn generate_master_secret(&mut self, premaster_secret: &[u8], client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    //     let label = b"master secret";
    //
    //     let mut seed = Vec::new();
    //     seed.extend_from_slice(&*client_random);
    //     seed.extend_from_slice(&*server_random);
    //
    //     let mut master_secret = [0u8; 48];
    //
    //     self.prf_raw(premaster_secret, label.as_ref(), seed.as_ref(), &mut master_secret);
    //     Vec::from(master_secret)
    // }

    // fn decrypt_aes_gcm_openssl(
    //     &mut self,
    //     encrypted_data: Vec<u8>,
    //     key: &[u8],
    // ) -> Vec<u8> {
    //     let nonce_len = 8;
    //     // 从 encrypted_data 中提取 nonce、
    //     // 在 nonce 前面添加 1, 138, 209, 110
    //     let nonce_new = &encrypted_data[..nonce_len];
    //     let nonce = [ &[1, 138, 209, 110], nonce_new].concat();
    //
    //
    //
    //     let mut encrypted_data = Vec::from(&encrypted_data[nonce_len..]);
    //
    //     let t = Cipher::aes_128_gcm();
    //     let mut c = Crypter::new(t, Mode::Decrypt, key, Some(&*nonce)).unwrap();
    //     let mut out = vec![0; encrypted_data.len() + t.block_size()];
    //
    //     let additional_data = [0, 0, 0, 0, 0, 0, 0, 1, 17, 3, 3];
    //     let tag_size = 16;
    //     let data_len = encrypted_data.len() - tag_size;
    //     let mut final_additional_data = Vec::from(additional_data);
    //     final_additional_data.push((data_len >> 8) as u8);
    //     final_additional_data.push((data_len & 0xff) as u8);
    //
    //     c.aad_update(&*final_additional_data).unwrap();
    //     let count = c.update(&*encrypted_data, &mut out).unwrap();
    //
    //     // let rest = c.set_tag()
    //     // c.finalize(&mut out[count..]).unwrap();
    //
    //
    //     out.truncate(count - tag_size);
    //
    //     out
    // }


}
