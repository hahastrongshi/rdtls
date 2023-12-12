pub mod raw;
pub mod ether;
pub mod ipv4;
pub mod tcp;
pub mod tls;


/// `Zero`            - This packet is very interesting
/// `One`             - This packet is somewhat interesting
/// `Two`             - Stuff you want to see if you're looking really hard
/// `AlmostMaximum`   - Some binary data
/// `Maximum`         - We couldn't parse this
#[derive(Debug)]
pub enum NoiseLevel {
    Zero          = 0,
    One           = 1,
    Two           = 2,
    AlmostMaximum = 3,
    Maximum       = 4,
}

pub mod prelude {
    pub use crate::structs::raw::Raw::*;
    pub use crate::structs::ether::Ether::*;
}