use crate::structs::tls;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum TCP {
    //TLS(tls::TLS),

    Text(String),
    Binary(Vec<u8>),
    Empty,
}

impl TCP {
    pub fn noise_level(&self, header: &pktparse::tcp::TcpHeader) -> NoiseLevel {
        use self::TCP::*;

        if header.flag_rst || header.flag_syn || header.flag_fin {
            // control packet
            match *self {
                Text(_) => NoiseLevel::Two,
                Binary(_) => NoiseLevel::Two,
                Empty => NoiseLevel::Two,
                _ => NoiseLevel::Zero,
            }
        } else {
            // data packet
            match *self {
                Text(ref text) if text.len() <= 8 => NoiseLevel::AlmostMaximum,
                Binary(_) => NoiseLevel::AlmostMaximum,
                Empty => NoiseLevel::AlmostMaximum,
                _ => NoiseLevel::Zero,
            }
        }
    }

    pub fn len(&self) -> usize {
        // 打印出  self 的类型
        println!("{:?}", self);
        match self {
            //TCP::TLS(tls_data) => tls_data.len(), // 假设 tls::TLS 有一个 size 方法
            TCP::Text(text) => text.len(),
            TCP::Binary(data) => data.len(),
            TCP::Empty => 0,
            // 获取 self 的字节长度

        }
    }
}
