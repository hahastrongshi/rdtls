use crate::structs::tcp;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum IPv4 {
    TCP(pktparse::tcp::TcpHeader, tcp::TCP),
    Unknown(Vec<u8>),
}

impl IPv4 {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::IPv4::*;
        match *self {
            TCP(ref header, ref tcp) => tcp.noise_level(header),
            Unknown(_) => NoiseLevel::Maximum,
        }
    }
}
