//! Types for parsing and manipulating stream-level network protocols.
//!
//! Any protocol that requires parsing over multiple packets within a single connection or flow is
//! considered a "stream-level" protocol, even if it is a datagram-based protocol in the
//! traditional-sense.

// pub mod dns;
// pub mod http;
pub mod tls;

extern crate pnet;

use pnet::datalink::{ MacAddr};
use pnet::packet::ethernet::{ MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::{ Packet};


use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
// use self::dns::{parser::DnsParser, Dns};
// use self::http::{parser::HttpParser, Http};
use self::tls::{parser::TlsParser, Tls};
use crate::conntrack::conn::conn_info::{ConnInfo, ConnState, TlsInfo};
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
// use crate::filter::Filter;
// use crate::subscription::*;

use std::str::FromStr;

use anyhow::{bail, Result};
use strum_macros::EnumString;
use std::string::ParseError;
use pcap_sys::pcap_t;

/// Represents the result of parsing one packet as a protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseResult {
    /// Session parsing done, check session filter. Returns the most-recently-updated session ID.
    Done(usize),
    /// Successfully extracted data, continue processing more packets. Returns most recently updated
    /// session ID.
    Continue(usize),
    /// Parsing skipped, no data extracted.
    Skipped,
    // application data
    Data(Vec<u8>),
}

/// Represents the result of a probing one packet as a protocol message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeResult {
    /// Segment matches the parser with great probability.
    Certain,
    /// Unsure if the segment matches the parser.
    Unsure,
    /// Segment does not match the parser.
    NotForUs,
    /// Error occurred during the probe. Functionally equivalent to Unsure.
    Error,
}

/// Represents the result of probing one packet with all registered protocol parsers.
#[derive(Debug)]
pub(crate) enum ProbeRegistryResult {
    /// A parser in the registry was definitively matched.
    Some(ConnParser),
    /// All parsers in the registry were definitively not matched.
    None,
    /// Unsure, continue sending more data.
    Unsure,
}

/// A trait all application-layer protocol parsers must implement.
pub(crate) trait ConnParsable {
    /// Parse the L4 protocol data unit as the parser's protocol.
    fn parse(&mut self, pdu: &L4Pdu, tls_info: &mut TlsInfo) -> ParseResult;

    /// Probe if the L4 protocol data unit matches the parser's protocol.
    fn probe(&self, pdu: &L4Pdu) -> ProbeResult;

    /// Removes session with ID `session_id` and returns it.
    fn remove_session(&mut self, session_id: usize) -> Option<Session>;

    /// Removes all sessions in the connection parser and returns them.
    fn drain_sessions(&mut self) -> Vec<Session>;

    /// Default state to set the tracked connection to on a matched session.
    fn session_match_state(&self) -> ConnState;

    /// Default state to set the tracked connection to on a non-matched session.
    fn session_nomatch_state(&self) -> ConnState;
}

/// Data required to filter on connections.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub struct ConnData {
    /// The connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// The protocol parser associated with the connection.
    pub conn_parser: ConnParser,
    /// Packet terminal node ID matched by first packet of connection.
    pub pkt_term_node: usize,
    /// Connection terminal node ID matched by connection after successful probe. If packet terminal
    /// node is terminal, this is the same as the packet terminal node.
    pub conn_term_node: usize,

    // 添加 network interface 网卡数据写入
    pub pcap_interface: Option<*mut pcap_t>,

    pub tcp_session: Option<TcpSession>,
}

impl ConnData {
    /// Create a new `ConnData` from the connection `five_tuple` and the ID of the last matched node
    /// in the filter predicate trie.
    pub(crate) fn new(five_tuple: FiveTuple, pkt_term_node: usize) -> Self {
        let Ok(parser) = ConnParser::from_str("tls") else { todo!() };
        ConnData {
            five_tuple,
            conn_parser: parser,
            pkt_term_node,
            conn_term_node: pkt_term_node,
            pcap_interface: None,
            tcp_session: None,
        }
    }

    /// Returns the application-layer protocol parser associated with the connection.
    pub fn service(&self) -> &ConnParser {
        &self.conn_parser
    }

    pub fn process_packet(&mut self, segment: L4Pdu, tls_info: &mut TlsInfo) {
        // todo 这里添加 TLS 的处理逻辑
        println!("process packet: {}, len: {}", self.five_tuple, segment.length());
        let result = self.conn_parser.parse(&segment, tls_info);
        // 在这里保存 tls 解密相关的数据
        match result {
            ParseResult::Done(_) => {
                // todo
            }
            ParseResult::Continue(_) => {
                // todo
            }
            ParseResult::Skipped => {
                // todo
            }
            ParseResult::Data(data) => {
                println!("plaintext....\n");
                println!("{:?}", data);

                if self.tcp_session == None {
                    self.init_new_session();
                }

                // todo     发送数据
                self.tcp_session.as_mut().unwrap().send_tcp_payload(segment.dir, data);

            }
        }
    }

    pub  fn init_new_session(&mut self) {
        // 打开设备
        let device_name = CString::new("en0").unwrap();
        let errbuf = [0i8; pcap_sys::PCAP_ERRBUF_SIZE as usize];
        let handle = unsafe { pcap_sys::pcap_open_live(device_name.as_ptr(), 65536, 1, 0, errbuf.as_ptr() as *mut i8)};

        if handle.is_null() {
            eprintln!("无法打开设备");
            return;
        }

        self.pcap_interface = Option::from(handle);

        let ori_ip = match  self.five_tuple.orig.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                eprintln!("不支持的ip类型");
                return;
            }
        };

        let dst_ip = match self.five_tuple.resp.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                eprintln!("不支持的ip类型");
                return;
            }
        };

        self.tcp_session = Option::from(TcpSession::new(ori_ip, dst_ip, self.five_tuple.orig.port(), self.five_tuple.resp.port()));

        // 发送 三次握手
        self.tcp_session.as_mut().unwrap().tcp_three_way_handshake()
    }


}

/// Data required to filter on application-layer protocol sessions.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub enum SessionData {
    // TODO: refactor to use trait objects.
    Tls(Box<Tls>),
    Null,
}

/// An application-layer protocol session.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
pub struct Session {
    /// Application-layer session data.
    pub data: SessionData,
    /// A unique identifier that represents the arrival order of the first packet of the session.
    pub id: usize,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            data: SessionData::Null,
            id: 0,
        }
    }
}

/// A connection protocol parser.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnParser {
    // TODO: refactor to use trait objects.
    Tls(TlsParser),
    Unknown,
}

impl ConnParser {
    /// Returns a new connection protocol parser of the same type, but with state reset.
    pub(crate) fn reset_new(&self) -> ConnParser {
        match self {
            ConnParser::Tls(_) => ConnParser::Tls(TlsParser::default()),
            ConnParser::Unknown => ConnParser::Unknown,
        }
    }

    /// Returns the result of parsing `pdu` as a protocol message.
    pub(crate) fn parse(&mut self, pdu: &L4Pdu, tls_info: &mut TlsInfo) -> ParseResult {
        match self {
            ConnParser::Tls(parser) => parser.parse(pdu, tls_info),
            ConnParser::Unknown => ParseResult::Skipped,
        }
    }

    /// Returns the result of probing whether `pdu` is a protocol message.
    pub(crate) fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        match self {
            ConnParser::Tls(parser) => parser.probe(pdu),
            ConnParser::Unknown => ProbeResult::Error,
        }
    }

    /// Removes the session with ID `session_id` from any protocol state managed by the parser, and
    /// returns it.
    pub(crate) fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        match self {
            ConnParser::Tls(parser) => parser.remove_session(session_id),
            ConnParser::Unknown => None,
        }
    }

    /// Removes all remaining sessions managed by the parser and returns them.
    pub(crate) fn drain_sessions(&mut self) -> Vec<Session> {
        match self {
            ConnParser::Tls(parser) => parser.drain_sessions(),
            ConnParser::Unknown => vec![],
        }
    }

    /// Returns the state that a connection should transition to on a session filter match.
    pub(crate) fn session_match_state(&self) -> ConnState {
        match self {
            ConnParser::Tls(parser) => parser.session_match_state(),
            ConnParser::Unknown => ConnState::Remove,
        }
    }

    /// Returns the state that a connection should transition to on a failed session filter match.
    pub(crate) fn session_nomatch_state(&self) -> ConnState {
        match self {
            ConnParser::Tls(parser) => parser.session_nomatch_state(),
            ConnParser::Unknown => ConnState::Remove,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TcpSession {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    client_seq: u32,
    server_seq: u32,

    handler: *mut pcap_t,
}

impl TcpSession {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Self {
        // 发送数据包
        // let send_result = unsafe {pcap_sys::pcap_sendpacket(*handler, packet.as_ptr(), packet.len() as i32)};
        // if send_result != 0 {
        //     println!("发送数据包失败");
        // } else {
        //     println!("发送成功");
        // }

        // 打开设备
        let device_name = CString::new("en0").unwrap();
        let errbuf = [0i8; pcap_sys::PCAP_ERRBUF_SIZE as usize];
        let handle = unsafe { pcap_sys::pcap_open_live(device_name.as_ptr(), 65536, 1, 0, errbuf.as_ptr() as *mut i8)};

        if handle.is_null() {
            eprintln!("无法打开设备");
            // todo 添加报错，这里应该不会报错，在程序初始化时，就处理这个问题
        }

        TcpSession {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            client_seq: 0,
            server_seq: 0,
            handler: handle,
        }
    }


    pub fn send_tcp_payload(&mut self, dir: bool, payload: Vec<u8>) -> bool {
        let payload_length = payload.len() as u32;
        if dir {
            let packet = self.assemble_packet(dir, self.client_seq, self.server_seq, payload);
        } else {
            let packet = self.assemble_packet(dir, self.server_seq, self.client_seq, payload);
        }
        // 发送 packet

        if dir {
            self.client_seq += payload_length;
        } else {
            self.server_seq += payload_length;
        }

        // ack
        if dir {
            let packet = self.assemble_packet(!dir, self.server_seq, self.client_seq, Vec::new());
            // 发送 packet
        } else {
            let packet = self.assemble_packet(!dir, self.client_seq, self.server_seq, Vec::new());
            // 发送 packet
        }
        true
    }



    pub fn tcp_three_way_handshake(&mut self)  {
        let packet = self.assemble_packet(true, self.client_seq, self.server_seq, Vec::new());
        // 发送 packet
        self.client_seq += 1;


        let packet = self.assemble_packet(false, self.server_seq, self.client_seq,Vec::new());
        // 发送 packet
        self.server_seq += 1;

        let packet = self.assemble_packet(true, self.client_seq, self.server_seq, Vec::new());
        // 发送 packet
    }

    pub fn assemble_packet(&mut self, dir: bool, seq: u32, ack: u32, payload: Vec<u8>) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; 1500];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        let mut ipv4_buffer = [0u8; 1486];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

        let mut tcp_buffer = [0u8; 1466];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        // 构造 TCP 数据包
        if dir {
            tcp_packet.set_source(self.src_port);
            tcp_packet.set_destination(self.dst_port);
        } else {
            tcp_packet.set_source(self.dst_port);
            tcp_packet.set_destination(self.src_port);
        }


        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(ack);

        tcp_packet.set_flags(TcpFlags::SYN); // 设置 SYN 标志位进行连接
        tcp_packet.set_window(1024);
        tcp_packet.set_options(&[]);
        tcp_packet.set_payload(&*payload);

        let first_ip;
        let second_ip;
        if dir {
            first_ip = self.src_ip.clone();
            second_ip = self.dst_ip.clone();
        } else {
            first_ip = self.dst_ip.clone();
            second_ip = self.src_ip.clone();
        }

        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(),
                                                            &Ipv4Addr::from(first_ip),
                                                            &Ipv4Addr::from(second_ip));
        tcp_packet.set_checksum(tcp_checksum);

        // 构造 IPv4 数据包
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(20 + tcp_packet.packet().len() as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        if dir {
            ipv4_packet.set_source(self.src_ip.clone());
            ipv4_packet.set_destination(self.dst_ip.clone());
        } else {
            ipv4_packet.set_source(self.dst_ip.clone());
            ipv4_packet.set_destination(self.src_ip.clone());
        }

        ipv4_packet.set_payload(tcp_packet.packet());

        // 构造 Ethernet 数据包
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        // source

        ethernet_packet.set_destination(MacAddr(0x00, 0x0c, 0x29, 0x3f, 0x3e, 0x7c));
        ethernet_packet.set_source(MacAddr(0x00, 0x0c, 0x29, 0x3f, 0x3e, 0x7d));
        ethernet_packet.set_payload(ipv4_packet.packet());


        let total_length = 14 + 20 + 20 + payload.len();
        ethernet_buffer[..total_length].to_vec()
    }
}

