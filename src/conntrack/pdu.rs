// use crate::memory::mbuf::Mbuf;


use anyhow::{bail, Result};

use std::net::{IpAddr, SocketAddr};

use crate::memory::mbuf::Mbuf;

use crate::protocols;
use crate::structs::raw::Raw;
use crate::structs::ether::Ether;
use crate::structs::ipv4::IPv4;

/// Transport-layer protocol data unit for stream reassembly and application-layer protocol parsing.
#[derive(Debug)]
pub struct L4Pdu<'a> {
    /// Internal packet buffer containing frame data.
    pub(crate) mbuf: &'a Mbuf,
    /// Transport layer context.
    pub(crate) ctxt: L4Context,
    /// `true` if segment is in the direction of orig -> resp.
    pub(crate) dir: bool,
}

impl<'a> L4Pdu<'a> {
    pub(crate) fn new(mbuf: &'a Mbuf, ctxt: L4Context, dir: bool) -> Self {
        L4Pdu { mbuf, ctxt, dir }
    }

    #[inline]
    pub(crate) fn mbuf_own(self) -> &'a Mbuf {
        self.mbuf
    }

    #[inline]
    pub(crate) fn mbuf_ref(&self) -> &Mbuf {
        &self.mbuf
    }

    #[inline]
    pub(crate) fn offset(&self) -> usize {
        self.ctxt.offset
    }

    #[inline]
    pub(crate) fn length(&self) -> usize {
        self.ctxt.length
    }

    #[inline]
    pub(crate) fn seq_no(&self) -> u32 {
        self.ctxt.seq_no
    }

    #[inline]
    pub(crate) fn flags(&self) -> u8 {
        self.ctxt.flags
    }
}

/// Parsed transport-layer context from the packet used for connection tracking.
#[derive(Debug, Clone, Copy)]
pub struct L4Context {
    /// Source socket address.
    pub(crate) src: SocketAddr,
    /// Destination socket address.
    pub(crate) dst: SocketAddr,
    /// L4 protocol.
    pub(crate) proto: usize,
    /// Index of the predicate that was last matched in the packet filter.
    pub(crate) idx: usize,
    /// Offset into the mbuf where payload begins.
    pub(crate) offset: usize,
    /// Length of the payload in bytes.
    pub(crate) length: usize,
    /// Raw sequence number of segment.
    pub(crate) seq_no: u32,
    /// TCP flags.
    pub(crate) flags: u8,
    pub(crate) rst: bool,
}

impl L4Context {
    pub(crate) fn new(mbuf: &Mbuf, idx: usize) -> Result<Self> {

            let packet = protocols::parse( mbuf.data());
            // 需要简化这块的操作, 不然长了
            match packet {
                // 这里面直接对 不同元素命名，后面可以直接使用
                Raw::Ether(_, ether) => {
                    println!("{:?}", ether);
                    match ether {
                        Ether::IPv4(header, tcp) => {
                            match tcp {
                                IPv4::TCP(tcpHeader, payload) => {
                                    println!("protocol: {:?},  {:?}:{:?} -> {:?}:{:?}, payload: {:?}",
                                             header.protocol, header.source_addr, tcpHeader.source_port,
                                             header.dest_addr, tcpHeader.dest_port, payload);

                                    Ok(L4Context {
                                        src: SocketAddr::new(IpAddr::V4(header.source_addr), tcpHeader.source_port),
                                        dst: SocketAddr::new(IpAddr::V4(header.dest_addr), tcpHeader.dest_port),
                                        proto: 1,
                                        idx,
                                        offset: tcpHeader.data_offset as usize,
                                        length: payload.len(),
                                        seq_no: tcpHeader.sequence_no,
                                        flags: 0b0000_0010,
                                        rst: tcpHeader.flag_rst,
                                    })
                                    // bail!("Malformed Packet")

                                },
                                IPv4::Unknown(_) => { bail!("Malformed Packet"); }
                            }
                        },
                        Ether::Unknown(_) => { bail!("Malformed Packet"); }
                    }
                },
                Raw::Unknown(_) => {
                    bail!("Malformed Packet");
                }
            }



    }

}
