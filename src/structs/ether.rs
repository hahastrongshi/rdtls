use crate::structs::ipv4;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum Ether {
    IPv4(pktparse::ipv4::IPv4Header, ipv4::IPv4),
    Unknown(Vec<u8>),
}

impl Ether {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::Ether::*;
        match *self {
            IPv4(_, ref ipv4) => ipv4.noise_level(),
            Unknown(_) => NoiseLevel::Maximum,
        }
    }
}
