use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnData, ParseResult, Session,
};
use crate::conntrack::conn::trackedconnection::TrackedConnection;

#[derive(Debug)]
pub struct TlsInfo {
    pub client_cipher: Option<Box<dyn tls_decrypt::decrypt::Decryptor>>,
    pub server_cipher: Option<Box<dyn tls_decrypt::decrypt::Decryptor>>,
}

#[derive(Debug)]
pub(crate) struct ConnInfo {
    /// State of Conn
    pub(crate) state: ConnState,
    /// Connection data (for filtering)
    pub(crate) cdata: ConnData,
    /// Subscription data (for delivering)
    /// 更换为 trackedConnection
    pub(crate) sdata: TrackedConnection,

    pub tls_info: TlsInfo,
}

impl ConnInfo
{
    pub(super) fn new(five_tuple: FiveTuple, pkt_term_node: usize) -> Self {
        ConnInfo {
            state: ConnState::Probing,
            cdata: ConnData::new(five_tuple, pkt_term_node),
            sdata: TrackedConnection::new(five_tuple),
            tls_info: TlsInfo{
                client_cipher: None,
                server_cipher: None,
            },
        }
    }

    pub(crate) fn consume_pdu(
        &mut self,
        pdu: L4Pdu,
    ) {
        match self.state {
            ConnState::Probing => {
                self.on_probe(pdu);
            }
            ConnState::Parsing => {
                // 这里是真正消费数据的地方
                self.on_parse(pdu);
            }
            ConnState::Tracking => {
                self.on_track(pdu);
            }
            ConnState::Remove => {
                drop(pdu);
            }
            _ => {}
        }
    }

    fn on_probe(
        &mut self,
        pdu: L4Pdu,
    ) {

                // conn_parser remains Unknown
                self.cdata.process_packet(pdu, &mut self.tls_info);

                // todo 查看实现
                //self.sdata.on_match();
                // self.state = self.get_match_state(0);
                self.state = ConnState::Parsing;


    }

    fn on_parse(&mut self, pdu: L4Pdu) {
        self.cdata.process_packet(pdu, &mut self.tls_info);
        // match self.cdata.conn_parser.parse(&pdu) {
        //     ParseResult::Done(id) => {
        //         self.sdata.pre_match(pdu, Some(id));
        //         if let Some(session) = self.cdata.conn_parser.remove_session(id) {
        //             if subscription.filter_session(&session, self.cdata.conn_term_node) {
        //                 self.sdata.on_match(session, subscription);
        //                 self.state = self.get_match_state(id);
        //             } else {
        //                 self.state = self.get_nomatch_state(id);
        //             }
        //         } else {
        //             log::error!("Done parse but no mru");
        //             self.state = ConnState::Remove;
        //         }
        //     }
        //     ParseResult::Continue(id) => {
        //         self.sdata.pre_match(pdu, Some(id));
        //     }
        //     ParseResult::Skipped => {
        //         self.sdata.pre_match(pdu, None);
        //     }
        // }
    }

    fn on_track(&mut self, pdu: L4Pdu) {
        // todo 这里需要传入 connInfo
        self.cdata.process_packet(pdu, &mut self.tls_info);
    }

    fn get_match_state(&self, session_id: usize) -> ConnState {
        if session_id == 0  {
            ConnState::Tracking
        } else {
            self.cdata.conn_parser.session_match_state()
        }
    }

    fn get_nomatch_state(&self, session_id: usize) -> ConnState {
        if session_id == 0  {
            ConnState::Remove
        } else {
            self.cdata.conn_parser.session_nomatch_state()
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnState {
    /// Unknown application-layer protocol, needs probing.
    Probing,
    /// Known application-layer protocol, needs parsing.
    Parsing,
    /// No need to probe or parse, just track. Application-layer protocol may or may not be known.
    Tracking,
    /// Connection will be removed
    Remove,
}
