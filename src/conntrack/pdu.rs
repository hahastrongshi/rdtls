// use crate::memory::mbuf::Mbuf;
// use crate::protocols::packet::ethernet::Ethernet;
// use crate::protocols::packet::ipv4::Ipv4;
// use crate::protocols::packet::ipv6::Ipv6;
// use crate::protocols::packet::tcp::{Tcp, TCP_PROTOCOL};
// use crate::protocols::packet::udp::{Udp, UDP_PROTOCOL};
// use crate::protocols::packet::Packet;

use anyhow::{bail, Result};

use std::net::{IpAddr, SocketAddr};

/// Transport-layer protocol data unit for stream reassembly and application-layer protocol parsing.
#[derive(Debug)]
pub struct L4Pdu<'a> {
    /// Internal packet buffer containing frame data.
    pub(crate) mbuf: &'a[u8],
    /// Transport layer context.
    pub(crate) ctxt: L4Context,
    /// `true` if segment is in the direction of orig -> resp.
    pub(crate) dir: bool,
}

impl<'a> L4Pdu<'a> {
    pub(crate) fn new(mbuf: &'a[u8], ctxt: L4Context, dir: bool) -> Self {
        L4Pdu { mbuf, ctxt, dir }
    }

    #[inline]
    pub(crate) fn mbuf_own(self) -> &'a[u8] {
        self.mbuf
    }

    #[inline]
    pub(crate) fn mbuf_ref(&self) -> &[u8] {
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
    pub(crate) src: u64,
    /// Destination socket address.
    pub(crate) dst: u64,
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
}

impl L4Context {
    pub(crate) fn new(mbuf: &[u8], idx: usize) -> Result<Self> {
            Ok(L4Context {
                src: 1,
                dst: 1,
                proto: 1, // 后续使用 enum 替代
                idx,
                offset: 1,
                length: 1,
                seq_no: 1,
                flags: 1,
            })
    }
}
