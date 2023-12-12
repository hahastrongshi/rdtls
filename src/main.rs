pub mod protocolparse;
pub mod errors;

pub mod structs;

pub mod pcap;

use std::sync::{Arc, Mutex};
use std::thread;
use anyhow::{ Result};
use crate::structs::raw::Raw;
use crate::structs::ether::Ether;
use crate::structs::ipv4::IPv4;


fn main() -> Result<()> {
   let device = "en0";

    let cap = pcap::open(&device, &pcap::Config {
        promisc: false,
        immediate_mode: true,
    })?;


    let threads: usize = 1;

    let cap = Arc::new(Mutex::new(cap));

    for _ in 0..threads {
        let cap = cap.clone();
         thread::spawn(move || {
            loop {
                let packet = {
                    let mut cap = cap.lock().unwrap();
                    cap.next_pkt()
                };

                if let Ok(Some(packet)) = packet {

                    let packet = protocolparse::parse( &packet.data);
                    match packet {
                        // 这里面直接对 不同元素命名，后面可以直接使用
                        Raw::Ether(_, ether) => {
                            // println!("{:?}", ether);
                            match ether {
                                Ether::IPv4(header, tcp) => {
                                    match tcp {
                                        IPv4::TCP(tcpHeader, _) => {
                                            println!("protocol: {:?},  {:?}:{:?} -> {:?}:{:?}", header.protocol, header.source_addr, tcpHeader.source_port, header.dest_addr, tcpHeader.dest_port);

                                        },
                                        IPv4::Unknown(_) => {}
                                    }
                                },
                                Ether::Unknown(_) => {}
                            }
                        },
                        Raw::Unknown(_) => {

                        }
                    }
                }

                // 提取数据完毕
            }
         });
    }


    // 添加堵塞一分钟
    thread::sleep(std::time::Duration::from_secs(60));
    Ok(())

}
