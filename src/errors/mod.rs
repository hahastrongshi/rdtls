#[derive(Debug, PartialEq)]
pub enum ProtocolParseError {
    WrongProtocol,
    ParsingError,

    UnknownProtocol,
    InvalidPacket,
}