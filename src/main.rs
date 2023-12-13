pub mod protocolparse;
pub mod errors;

pub mod structs;

pub mod pcap;
pub mod conntrack;

use std::sync::{Arc, Mutex};
use std::thread;
use anyhow::{ Result};
use crate::structs::raw::Raw;
use crate::structs::ether::Ether;
use crate::structs::ipv4::IPv4;

use crate::conntrack::pdu::L4Context;



fn main() -> Result<()> {
   let device = "en0";

    let cap = pcap::open(&device, &pcap::Config {
        promisc: false,
        immediate_mode: true,
    })?;

    // conntrack
    let connTrackConfig = conntrack::TrackerConfig{
        max_connections: 1000,
        max_out_of_order: 1000,
        /// Time to expire inactive UDP connections (in milliseconds).
        udp_inactivity_timeout: 120000,
        /// Time to expire inactive TCP connections (in milliseconds).
        tcp_inactivity_timeout: 12000,
        /// Time to expire unestablished TCP connections (in milliseconds).
        tcp_establish_timeout: 2000,
        /// Frequency to check for inactive streams (in milliseconds).
        timeout_resolution: 10000,
    };

    let mut connTracker = conntrack::ConnTracker::new(connTrackConfig);



    let threads: usize = 1;

    let cap = Arc::new(Mutex::new(cap));

    // for _ in 0..threads {
    //     let cap = cap.clone();
    //      thread::spawn(move || {
            loop {
                let packet = {
                    let mut cap = cap.lock().unwrap();
                    cap.next_pkt()
                };

                if let Ok(Some(packet)) = packet {
                    if packet.data.len() < 64 {
                        continue;
                    }

                    // mac 6 + 6 + 2 上层协议 （类型长度，可能是 vlan）
                    // ip 20  4bit version + 4bit header length  10: tcp or udp 12: srcIP 16: dstIP
                    // tcp 20 0: srcPort 2: dstPort

                    let ipv4 = packet.data[14] >> 4 ;
                    // 非 ipv4 直接返回
                    if ipv4 != 4 {
                        continue;
                    }

                    let ipLength = (packet.data[14] & 0x0f) * 4;

                    let tcp = packet.data[23];
                    // 非 tcp 协议直接返回
                    if tcp != 6 {
                        continue
                    }

                    // 最低两位
                    let mut hash =   packet.data[28].wrapping_add(packet.data[29]);
                    hash = hash.wrapping_add(packet.data[32]);
                    hash = hash.wrapping_add(packet.data[33]);
                    // port
                    hash = hash.wrapping_add(packet.data[34]);
                    hash = hash.wrapping_add(packet.data[35]);
                    hash = hash.wrapping_add(packet.data[36]);
                    hash = hash.wrapping_add(packet.data[37]);
                    println!("data len: {:?}, hash: {}", packet.data.len(), hash);

                    if let Ok(ctx) = L4Context::new(&packet.data, 1) {
                        connTracker.process(&packet.data, ctx);
                    }

                }

                //     let packet = protocolparse::parse( &packet.data);
                //     // 需要简化这块的操作, 不然长了
                //     match packet {
                //         // 这里面直接对 不同元素命名，后面可以直接使用
                //         Raw::Ether(_, ether) => {
                //             println!("{:?}", ether);
                //             match ether {
                //                 Ether::IPv4(header, tcp) => {
                //                     match tcp {
                //                         IPv4::TCP(tcpHeader, payload) => {
                //                             println!("protocol: {:?},  {:?}:{:?} -> {:?}:{:?}, payload: {:?}",
                //                                      header.protocol, header.source_addr, tcpHeader.source_port,
                //                                      header.dest_addr, tcpHeader.dest_port, payload);
                //
                //                         },
                //                         IPv4::Unknown(_) => {}
                //                     }
                //                 },
                //                 Ether::Unknown(_) => {}
                //             }
                //         },
                //         Raw::Unknown(_) => {
                //
                //         }
                //     }
                // }


            }
    //      });
    // }
    //
    //
    // // 添加堵塞一分钟
    // thread::sleep(std::time::Duration::from_secs(60));
    // Ok(())

}
