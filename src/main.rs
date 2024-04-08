pub mod protocols;
pub mod errors;

pub mod structs;

pub mod pcap;
pub mod conntrack;

pub mod memory;

pub mod utils;

use std::sync::mpsc;
use std::thread;
use std::sync::{Arc, Mutex};
use anyhow::{ Result};
use libc::{int16_t, uint16_t};
use crate::structs::raw::Raw;
use crate::structs::ether::Ether;
use crate::structs::ipv4::IPv4;

use crate::conntrack::pdu::L4Context;
use crate::memory::mbuf::Mbuf;



fn main() -> Result<()> {
    let device = "en0";
    let read = true;
    let path = "aes128gcmsha256.pcap";

    let cap = if read {
        let cap = pcap::open_file(&path)?;
        cap
    } else {
        let cap = pcap::open(&device, &pcap::Config {
            promisc: false,
            immediate_mode: true,
        })?;
        cap
    };

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


    // 为每个工作线程创建一个通道
    // let (tx, rx) = mpsc::channel::<Vec<u8>>();
    // // 创建工作线程
    // thread::spawn(move || {
    //     // 在这里处理接收到的消息
    //     for message in rx {
    //         println!("Worker  received: {}",  message.len());
    //         let mbuf = Mbuf::new(message);
    //
    //         if let Ok(ctx) = L4Context::new(&mbuf, 1) {
    //             //println!("tcp infp: {:?}", ctx);
    //             connTracker.process(mbuf, ctx);
    //         }
    //     }
    // });

    // let threads: usize = 1;

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
                        continue;
                    }

                    // 判断的是否为 tls 流量
                    let src_port = (packet.data[34] as uint16_t * 256).wrapping_add(packet.data[35] as uint16_t);
                    let dst_port = (packet.data[36] as uint16_t * 256).wrapping_add(packet.data[37] as uint16_t);
                    if src_port != 443 && dst_port != 443 {
                        continue;
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
                    // println!("data len: {:?}, hash: {}", packet.data.len(), hash);
                    // todo 从这里把数据的 开始位置记录下来？？

                    // 发送 packet
                    // tx.send(packet.data).unwrap();

                    let mbuf = Mbuf::new(packet.data);
                    if let Ok(ctx) = L4Context::new(&mbuf, 1) {
                        //println!("tcp infp: {:?}", ctx);
                        connTracker.process(mbuf, ctx);
                    }

                } else {
                    println!("End of packet stream, shutting down reader thread");
                    // 添加一个 sleep 30 s
                    thread::sleep(std::time::Duration::from_secs(30));
                }

                //     let packet = protocols::parse( &packet.data);
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
