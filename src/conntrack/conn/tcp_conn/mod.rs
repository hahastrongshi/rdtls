pub(crate) mod reassembly;

use self::reassembly::TcpFlow;
use crate::conntrack::conn::conn_info::ConnInfo;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::protocols::packet::tcp::{FIN, RST};

pub(crate) struct TcpConn<'a> {
    pub(crate) ctos: TcpFlow<'a>,
    pub(crate) stoc: TcpFlow<'a>,
}

impl TcpConn<'_> {
    pub(crate) fn new_on_syn(ctxt: L4Context, max_ooo: usize) -> Self {
        let flags = ctxt.flags;
        let next_seq = ctxt.seq_no.wrapping_add(1 + ctxt.length as u32);
        TcpConn {
            ctos: TcpFlow::new(max_ooo, next_seq, flags),
            stoc: TcpFlow::default(max_ooo),
        }
    }

    /// Insert TCP segment ordered into ctos or stoc flow
    #[inline]
    pub(crate) fn reassemble(
        &mut self,
        segment: L4Pdu,
        info: &mut ConnInfo,
    ) {
        if segment.dir {
            self.ctos
                .insert_segment(segment, info);
        } else {
            self.stoc
                .insert_segment(segment, info);
        }
    }

    /// Returns `true` if the connection should be terminated
    #[inline]
    pub(crate) fn is_terminated(&self) -> bool {
        // Both sides have sent FIN, or a RST has been sent
        (self.ctos.consumed_flags & self.stoc.consumed_flags & FIN
            | self.ctos.consumed_flags & RST
            | self.stoc.consumed_flags & RST)
            != 0
    }

    /// Updates connection termination flags
    #[inline]
    pub(super) fn update_term_condition(&mut self, flags: u8, dir: bool) {
        if dir {
            self.ctos.consumed_flags |= flags;
        } else {
            self.stoc.consumed_flags |= flags;
        }
    }
}
