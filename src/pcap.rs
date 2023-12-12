use std::ffi::CString;
use std::ffi::CStr;
use anyhow::{ Result, bail};

pub struct Cap {
    handle: *mut pcap_sys::pcap,
}

pub struct Config {
    pub promisc: bool,
    pub immediate_mode: bool,
}

pub fn open(dev: &str, config: &Config) -> Result<Cap> {
    let mut errbuf = [0; pcap_sys::PCAP_ERRBUF_SIZE as usize];
    let dev = CString::new(dev).unwrap();
    let handle = unsafe { pcap_sys::pcap_create(dev.as_ptr(), errbuf.as_mut_ptr()) };

    if handle.is_null() {
        let err = unsafe { CStr::from_ptr(errbuf.as_ptr()) };
        println!("Failed to open interface: {}", err.to_str()?);
    }

    if config.promisc {
        unsafe { pcap_sys::pcap_set_promisc(handle, 1) };
    }

    if config.immediate_mode {
        unsafe { pcap_sys::pcap_set_immediate_mode(handle, 1) };
    }

    let ret = unsafe { pcap_sys::pcap_activate(handle) };
    if ret != 0 {
        let err = unsafe { pcap_sys::pcap_geterr(handle) };
        let err = unsafe { CStr::from_ptr(err) };
        println!("Failed to activate interface: {}", err.to_str()?);
    }

    Ok(Cap {
        handle,
    })
}


impl Cap {
    pub fn datalink(&self) -> i32 {
        unsafe { pcap_sys::pcap_datalink(self.handle) }
    }

    pub fn next_pkt(&mut self) -> Result<Option<Packet>> {
        use std::mem::MaybeUninit;

        let mut header = MaybeUninit::<*mut pcap_sys::pcap_pkthdr>::uninit();
        let mut packet = MaybeUninit::<*const libc::c_uchar>::uninit();

        let retcode = unsafe { pcap_sys::pcap_next_ex(self.handle, header.as_mut_ptr(), packet.as_mut_ptr()) };

        match retcode {
            i if i >= 1 => {
                let header = unsafe { header.assume_init() };
                let packet = unsafe { packet.assume_init() };

                use std::slice;
                let packet = unsafe { slice::from_raw_parts(packet, (*header).caplen as _) };

                Ok(Some(Packet {
                    data: packet.to_vec(),
                }))
            },
            0 => bail!("timeout expired"),
            -2 => Ok(None),
            _ => unreachable!(),
        }
    }
}

impl Drop for Cap {
    fn drop(&mut self) {
        unsafe { pcap_sys::pcap_close(self.handle) };
    }
}

#[derive(Debug)]
pub struct Packet {
    pub data: Vec<u8>,
}

unsafe impl Send for Cap {}
