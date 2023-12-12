pub mod pcap;
use std::sync::{Arc, Mutex};
use std::thread;
use anyhow::{ Result};
use crate::structs::raw::Raw;
pub mod protocolparse;
pub mod errors;

pub mod structs;

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
                        Raw::Ether(_, _) => {
                            println!("{:?}", packet);
                        }
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
