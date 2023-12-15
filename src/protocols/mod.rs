use pktparse::{ethernet, ipv4};
use pktparse::ip::IPProtocol;
use pktparse::ethernet::EtherType;

use crate::errors::ProtocolParseError;
use crate::structs::raw;
use crate::structs::ether::{self, Ether};
use crate::structs::prelude::*;

pub mod tcp;
pub mod tls;

pub mod stream;

pub mod packet;

#[inline]
pub fn parse(data: &[u8]) -> raw::Raw {
     match parse_eth(data) {
        Ok(eth) => eth,
        Err(_)  => Unknown(data.to_vec()),
    }
}

#[inline]
pub fn parse_eth(data: &[u8]) -> Result<raw::Raw, ProtocolParseError> {
    use crate::structs::ether::Ether::Unknown;
    if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(data) {
        let inner = match eth_frame.ethertype {
            EtherType::IPv4 => match parse_ipv4(remaining) {
                Ok(ipv4) => ipv4,
                Err(_) => Unknown(remaining.to_vec()),
            },
            _ => {
                Unknown(remaining.to_vec())
            },
        };
        Ok(Ether(eth_frame, inner))
    } else {
        Err(ProtocolParseError::InvalidPacket)
    }
}


#[inline]
pub fn parse_ipv4(data: &[u8]) -> Result<ether::Ether, ProtocolParseError> {
    use crate::structs::ipv4::IPv4::*;

    if let Ok((remaining, ip_hdr)) = ipv4::parse_ipv4_header(data) {
        let inner = match ip_hdr.protocol {
            IPProtocol::TCP => match tcp::parse(remaining) {
                Ok((tcp_hdr, tcp)) => TCP(tcp_hdr, tcp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            _ => {
                Unknown(remaining.to_vec())
            }
        };
        Ok(IPv4(ip_hdr, inner))
    } else {
        Ok(Ether::Unknown(data.to_vec()))
    }
}

