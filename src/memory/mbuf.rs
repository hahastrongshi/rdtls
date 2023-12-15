
use std::fmt;
use std::ptr::NonNull;
use std::slice;

use anyhow::{bail, Result};
use thiserror::Error;


#[derive(Clone, Debug)]
/// A packet buffer.
///
/// This is a wrapper around a DPDK message buffer that represents a single Ethernet frame.
pub struct Mbuf {
    raw: Vec<u8>,
}

impl Mbuf {

    /// Creates a new Mbuf from Vec<u8>.
    pub(crate) fn new(mbuf: Vec<u8>) -> Mbuf {
        Mbuf {
            raw: mbuf,
        }
    }

    /// Creates a new Mbuf from a byte slice.
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Mbuf> {
        Ok(Mbuf {
            raw: data.to_vec(),
        })
    }



    /// Returns a mutable reference to the inner rte_mbuf.
    fn raw_mut(&mut self) -> &mut Vec<u8> {
        self.raw.as_mut()
    }

    /// Returns the UNIX timestamp of the packet.
    #[allow(dead_code)]
    pub(crate) fn timestamp(&self) -> usize {
        unimplemented!();
    }

    /// Returns the length of the data in the Mbuf.
    pub fn data_len(&self) -> usize {
        self.raw.len() as usize
    }

    /// Returns the contents of the Mbuf as a byte slice.
    pub fn data(&self) -> &[u8] {
        self.raw.as_slice()
    }

    /// Returns a byte slice of data with length count at offset.
    ///
    /// Errors if `offset` is greater than or equal to the buffer length or `count` exceeds the size
    /// of the data stored at `offset`.
    pub fn get_data_slice(&self, offset: usize, count: usize) -> Result<&[u8]> {
        if offset < self.raw.len() {
            if offset + count <= self.raw.len() {
                Ok(&self.raw[offset..offset+count])

            } else {
                bail!(MbufError::ReadPastBuffer)
            }
        } else {
            bail!(MbufError::BadOffset)
        }
    }

    /// Reads the data at `offset` as `T` and returns it as a raw pointer. Errors if `offset` is
    /// greater than or equal to the buffer length or the size of `T` exceeds the size of the data
    /// stored at `offset`.


    /// Returns the raw pointer from the offset.
    fn get_data_address(&self, offset: usize) -> *const u8 {
        unimplemented!();
    }

    /// Returns the RSS hash of the Mbuf computed by the NIC.
    #[allow(dead_code)]
    pub(crate) fn rss_hash(&self) -> u32 {
        unimplemented!();
    }

    /// Returns any MARKs tagged on the Mbuf by the NIC.
    #[allow(dead_code)]
    pub(crate) fn mark(&self) -> u32 {
        unimplemented!();
    }
}


#[derive(Error, Debug)]
pub(crate) enum MbufError {
    #[error("Offset exceeds Mbuf segment buffer length")]
    BadOffset,

    #[error("Data read exceeds Mbuf segment buffer")]
    ReadPastBuffer,

    #[error("Data write exceeds Mbuf segment buffer")]
    WritePastBuffer,
}