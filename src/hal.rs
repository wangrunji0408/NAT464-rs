//! Hardware Abstract Layer

use core::time::Duration;
use smoltcp::wire::*;

/// Interface for Hardware Abstract Layer
///
/// * Send and recv buffer
/// * AMC (Address Mapping Cache):          IPv4/6 -> IPv6/4
/// * FIB (Forwarding Information Base):    Destination IP -> NextHop IP
/// * ARC (Address Resolution Cache):       NextHop IP -> MAC
pub trait HAL {
    fn recv_packet(&mut self, buf: &mut [u8]) -> HALResult<Metadata>;
    fn send_packet(&mut self, iface_id: usize, buf: &[u8]) -> HALResult<()>;

    fn get_time(&self) -> HALResult<Duration>;
    fn get_iface_mac(&self, iface_id: usize) -> HALResult<EthernetAddress>;

    fn amc_get(&self, ip: IpAddress) -> HALResult<&IpAddress>;
    fn amc_add(&self, ip: IpAddress, new_ip: IpAddress) -> HALResult<()>;

    fn fib_get(&self, ip: IpAddress) -> HALResult<&IpAddress>;
    fn fib_add(&mut self, ip: IpAddress, next_hop: IpAddress) -> HALResult<()>;

    fn arc_get_mac(&self, ip: &IpAddress) -> HALResult<&EthernetAddress>;
    fn arc_add_mac(&mut self, ip: IpAddress, mac: EthernetAddress) -> HALResult<()>;
}

/// A specialized Result type for [`HAL`](trait.HAL.html).
pub type HALResult<T> = Result<T, HALError>;

/// The error type for [`HAL`](trait.HAL.html) functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HALError {
    EndOfFile,
    NotFound,
}

/// The metadata of a received packet.
pub struct Metadata {
    /// The interface ID from which the packet came.
    pub iface_id: usize,
    /// The length of the packet.
    pub len: usize,
}
