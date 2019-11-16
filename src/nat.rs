//! The core of Network Address Translation (NAT) logic

use crate::hal::{HALError, HAL};
use smoltcp::phy::{Checksum, ChecksumCapabilities};
use smoltcp::wire::*;
use smoltcp::Error as NetError;

/// Network Address Translation (NAT).
pub struct NAT<H: HAL> {
    pub hal: H,
    pub ifaces: [IFaceConfig; 4],
}

/// Configuration of a network interface.
pub struct IFaceConfig {
    pub mac: EthernetAddress,
    pub ipv4: Ipv4Address,
    pub ipv6: Ipv6Address,
}

impl<H: HAL> NAT<H> {
    /// Infinitely run until some error happened.
    pub fn run(&mut self) -> NATResult<()> {
        self.send_gratuitous_arps()?;
        let mut recv_buf = [0u8; 0x1000];
        loop {
            let meta = self.hal.recv_packet(&mut recv_buf)?;
            let mut frame = EthernetFrame::new_unchecked(&mut recv_buf[..]);
            match frame.ethertype() {
                EthernetProtocol::Arp => {
                    self.process_arp(meta.iface_id, frame.into_inner())?;
                }
                EthernetProtocol::Ipv4 => {
                    self.process_ipv4(meta.iface_id, frame.into_inner())?;
                }
                EthernetProtocol::Ipv6 => {
                    self.process_ipv6(frame.payload_mut());
                }
                EthernetProtocol::Unknown(type_) => {
                    warn!("unknown ethernet type: {}", type_);
                }
            }
        }
    }

    /// Send gratuitous ARP packet for each iface.
    fn send_gratuitous_arps(&mut self) -> NATResult<()> {
        const MAX_ARP_PACKET_LEN: usize = 42;
        let mut send_buf = [0u8; MAX_ARP_PACKET_LEN];
        for (iface_id, iface) in self.ifaces.iter().enumerate() {
            let mut frame = EthernetFrame::new_unchecked(&mut send_buf[..]);
            frame.set_src_addr(iface.mac);
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_ethertype(EthernetProtocol::Arp);

            let mut arp = ArpPacket::new_unchecked(frame.payload_mut());
            arp.set_operation(ArpOperation::Reply);
            arp.set_hardware_type(ArpHardware::Ethernet);
            arp.set_protocol_type(EthernetProtocol::Ipv4);
            arp.set_hardware_len(6);
            arp.set_protocol_len(4);
            arp.set_source_hardware_addr(iface.mac.as_bytes());
            arp.set_source_protocol_addr(iface.ipv4.as_bytes());
            arp.set_target_hardware_addr(&[0u8; 6]);
            arp.set_target_protocol_addr(iface.ipv4.as_bytes());

            self.hal.send_packet(iface_id, &send_buf)?;
        }
        Ok(())
    }

    /// Process IPv4 ARP packet
    fn process_arp(&mut self, iface_id: usize, recv_buf: &mut [u8]) -> NATResult<()> {
        let mut frame = EthernetFrame::new_unchecked(recv_buf);
        let mut arp = ArpPacket::new_checked(frame.payload_mut())?;
        if let ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr: src_mac,
            source_protocol_addr: src_ipv4,
            target_hardware_addr: dst_mac,
            target_protocol_addr: dst_ipv4,
        } = ArpRepr::parse(&arp)?
        {
            // update ARC for src
            self.hal.arc_add_mac(IpAddress::Ipv4(src_ipv4), src_mac)?;

            match operation {
                ArpOperation::Request => {
                    // reply (reuse input buffer)
                    let iface = &self.ifaces[iface_id];
                    arp.set_operation(ArpOperation::Reply);
                    arp.set_source_hardware_addr(iface.mac.as_bytes());
                    arp.set_source_protocol_addr(iface.ipv4.as_bytes());
                    arp.set_target_hardware_addr(src_mac.as_bytes());
                    arp.set_target_protocol_addr(src_ipv4.as_bytes());
                    frame.set_dst_addr(frame.src_addr());
                    frame.set_src_addr(iface.mac);
                    self.hal.send_packet(iface_id, &frame.into_inner()[..42])?;
                }
                ArpOperation::Reply => {
                    // update ARC for dst
                    self.hal.arc_add_mac(IpAddress::Ipv4(dst_ipv4), dst_mac)?;
                }
                ArpOperation::Unknown(op) => {
                    warn!("unknown ARP operation: {}", op);
                    return Err(NATError::Netstack(NetError::Unrecognized));
                }
            }
        } else {
            unreachable!()
        }
        Ok(())
    }

    /// Process IPv6 NDP packet
    fn process_ndp(&mut self, _ndp_buf: &[u8]) {}

    /// Process IPv4 packet
    fn process_ipv4(&mut self, iface_id: usize, recv_buf: &[u8]) -> NATResult<()> {
        let frame_in = EthernetFrame::new_unchecked(recv_buf);
        let ipv4_in = Ipv4Packet::new_checked(frame_in.payload())?;

        // If the packet is going to be forwarded and its hop limit is 1,
        // send an ICMP error message (Time exceeded).
        if self.is_forward(ipv4_in.dst_addr()) && ipv4_in.hop_limit() == 1 {
            const MAX_ICMP_PACKET_LEN: usize = 14 + 20 + 8;
            let mut send_buf = [0u8; MAX_ICMP_PACKET_LEN];

            let mut frame = EthernetFrame::new_unchecked(&mut send_buf[..]);
            frame.set_src_addr(self.ifaces[iface_id].mac);
            frame.set_dst_addr(frame_in.src_addr());
            frame.set_ethertype(EthernetProtocol::Ipv4);

            let mut ipv4 = Ipv4Packet::new_unchecked(frame.payload_mut());
            Ipv4Repr {
                src_addr: self.ifaces[iface_id].ipv4,
                dst_addr: ipv4_in.src_addr(),
                protocol: IpProtocol::Icmp,
                payload_len: 8,
                hop_limit: 64,
            }
            .emit(&mut ipv4, &{
                let mut cap = ChecksumCapabilities::ignored();
                cap.ipv4 = Checksum::Tx;
                cap
            });

            let mut icmp = Icmpv4Packet::new_unchecked(ipv4.payload_mut());
            icmp.set_msg_type(Icmpv4Message::TimeExceeded);
            icmp.set_msg_code(Icmpv4TimeExceeded::TtlExpired.into());
            icmp.set_echo_ident(0);
            icmp.set_echo_seq_no(0);
            icmp.fill_checksum();

            self.hal.send_packet(iface_id, &send_buf)?;
        }

        // TODO: If the packet that is an IPv6 packet or has DF bit set is going
        //       to be translated and forwarded, and it would be too big after
        //       translation, send an ICMP error message (Packet Too Big).

        Ok(())
    }

    /// Process IPv6 packet
    fn process_ipv6(&mut self, _ipv6_buf: &[u8]) {}

    /// Whether `dst_ipv4` is going to be forwarded.
    fn is_forward(&self, dst_ipv4: Ipv4Address) -> bool {
        self.ifaces
            .iter()
            .find(|iface| iface.ipv4 == dst_ipv4)
            .is_none()
    }
}

/// A specialized Result type for [`NAT`](struct.NAT.html).
pub type NATResult<T> = Result<T, NATError>;

/// The error type for [`NAT`](struct.NAT.html) object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NATError {
    Netstack(NetError),
    Hal(HALError),
}

impl From<NetError> for NATError {
    fn from(e: NetError) -> Self {
        NATError::Netstack(e)
    }
}

impl From<HALError> for NATError {
    fn from(e: HALError) -> Self {
        NATError::Hal(e)
    }
}
