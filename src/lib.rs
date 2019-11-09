use smoltcp::wire::*;
use smoltcp::Error;

struct Translator {
    local_prefix: Ipv6Address,
    remote_prefix: Ipv6Address,
}

impl Translator {
    /// Translate IPv4 packet on `ipv4_buf` to IPv6 packet on `ipv6_buf`.
    /// Return the length of IPv6 packet.
    fn ip_4to6(&self, ipv4_buf: &[u8], ipv6_buf: &mut [u8]) -> Result<usize, Error> {
        let ipv4 = Ipv4Packet::new_checked(ipv4_buf)?;
        let mut ipv6 = Ipv6Packet::new_unchecked(ipv6_buf);

        // translate addresses
        let src_addr6 = self.src_addr_4to6(ipv4.src_addr());
        let dst_addr6 = self.dst_addr_4to6(ipv4.dst_addr());

        // translate the header
        ipv6.set_version(6);
        ipv6.set_traffic_class(0);
        ipv6.set_flow_label(0);
        ipv6.set_payload_len(ipv4.payload().len() as u16);
        ipv6.set_next_header(ipv4.protocol());
        ipv6.set_hop_limit(ipv4.hop_limit());
        ipv6.set_src_addr(src_addr6);
        ipv6.set_dst_addr(dst_addr6);
        ipv6.check_len()?;

        // handle fragmentation
        let ipv6_payload = Self::frags_4to6(&ipv4, &mut ipv6)?;

        // for incrementally updating checksum on UDP & TCP header
        let checksum_delta = checksum(src_addr6.as_bytes())
            + checksum(dst_addr6.as_bytes())
            + checksum_neg(ipv4.src_addr().as_bytes())
            + checksum_neg(ipv4.dst_addr().as_bytes());

        // translate upper-layer protocol data
        if ipv4.frag_offset() == 0 {
            match ipv4.protocol() {
                IpProtocol::Icmp => {
                    let len = self.icmp_4to6(ipv4.payload(), ipv6_payload, src_addr6, dst_addr6)?;
                    ipv6.set_payload_len(len as u16);
                    ipv6.set_next_header(IpProtocol::Icmpv6);
                }
                IpProtocol::Udp => {
                    let mut udp = UdpPacket::new_unchecked(ipv6_payload);
                    udp.set_checksum(checksum_final(udp.checksum() as u32 + checksum_delta));
                }
                IpProtocol::Tcp => {
                    let mut tcp = TcpPacket::new_unchecked(ipv6_payload);
                    tcp.set_checksum(checksum_final(tcp.checksum() as u32 + checksum_delta));
                }
                _ => {}
            }
        }

        Ok(ipv6.total_len())
    }

    /// Append IPv6 fragmentation header if IPv4 packet is fragment.
    /// Return the rest payload of IPv6 packet.
    fn frags_4to6<'a>(
        ipv4: &Ipv4Packet<&[u8]>,
        ipv6: &'a mut Ipv6Packet<&mut [u8]>,
    ) -> Result<&'a mut [u8], Error> {
        let is_fragment = ipv4.more_frags() || ipv4.frag_offset() != 0;
        if !is_fragment {
            return Ok(ipv6.payload_mut());
        }
        // update IPv6 header
        const IPV6_FRAG_HEADER_LEN: usize = 8;
        let new_payload_len = ipv6.payload_mut().len() + IPV6_FRAG_HEADER_LEN;
        ipv6.set_next_header(IpProtocol::Ipv6Frag);
        ipv6.set_payload_len(new_payload_len as u16);
        ipv6.check_len()?;
        // add fragment header
        let mut frag = Ipv6FragmentHeader::new_unchecked(ipv6.payload_mut());
        frag.clear_reserved();
        frag.set_next_header(ipv4.protocol());
        frag.set_frag_offset(ipv4.frag_offset());
        frag.set_more_frags(ipv4.more_frags());
        frag.set_ident(ipv4.ident() as u32);
        Ok(&mut ipv6.payload_mut()[IPV6_FRAG_HEADER_LEN..])
    }

    /// Translate ICMPv4 packet on `icmpv4_buf` to ICMPv6 packet on `icmpv6_buf`.
    /// Also need `src_addr` and `dst_addr` to calculate checksum.
    /// Return the length of ICMPv6 packet.
    fn icmp_4to6(
        &self,
        icmpv4_buf: &[u8],
        icmpv6_buf: &mut [u8],
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) -> Result<usize, Error> {
        let icmpv4 = Icmpv4Packet::new_checked(icmpv4_buf)?;
        let mut icmpv6 = Icmpv6Packet::new_unchecked(icmpv6_buf);

        let (type6, code6) = Self::icmp_type_code_4to6(icmpv4.msg_type(), icmpv4.msg_code())
            .ok_or(Error::Illegal)?;
        icmpv6.set_msg_type(type6);
        icmpv6.set_msg_code(code6);

        match type6 {
            Icmpv6Message::EchoRequest | Icmpv6Message::EchoReply => {
                icmpv6.set_echo_ident(icmpv4.echo_ident());
                icmpv6.set_echo_seq_no(icmpv4.echo_seq_no());
            }
            Icmpv6Message::PktTooBig => {
                let v4mtu = icmpv4.echo_seq_no(); // no `mtu()` method

                // let v6mtu = v4mtu as usize - icmpv4.header_len() + icmpv6.header_len();
                // assume: v6 header length == v4 hender length == 8
                let v6mtu = v4mtu as u32;
                icmpv6.set_pkt_too_big_mtu(v6mtu);
            }
            _ => {}
        }
        icmpv6.payload_mut()[..icmpv4.data().len()].copy_from_slice(icmpv4.data());
        // TODO: Incrementally update the checksum
        icmpv6.fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));

        Ok(icmpv6.header_len()) // TODO: check
    }

    /// Translate source `addr` from IPv4 to IPv6
    #[inline]
    fn src_addr_4to6(&self, addr: Ipv4Address) -> Ipv6Address {
        let mut v6 = self.local_prefix;
        v6.0[12..16].copy_from_slice(addr.as_bytes());
        v6
    }

    /// Translate destination `addr` from IPv4 to IPv6
    #[inline]
    fn dst_addr_4to6(&self, addr: Ipv4Address) -> Ipv6Address {
        let mut v6 = self.remote_prefix;
        v6.0[12..16].copy_from_slice(addr.as_bytes());
        v6
    }

    /// Translate ICMP `type4` and `code4` from v4 to v6
    #[inline]
    fn icmp_type_code_4to6(type4: Icmpv4Message, code4: u8) -> Option<(Icmpv6Message, u8)> {
        use Icmpv4Message as v4;
        use Icmpv6DstUnreachable as v6d;
        use Icmpv6Message as v6;
        use Icmpv6TimeExceeded as v6t;

        match (type4, code4) {
            (v4::TimeExceeded, 0) => Some((v6::TimeExceeded, v6t::HopLimitExceeded.into())),
            (v4::TimeExceeded, 1) => Some((v6::TimeExceeded, v6t::FragReassemExceeded.into())),
            (v4::EchoRequest, 0) => Some((v6::EchoRequest, 0)),
            (v4::EchoReply, 0) => Some((v6::EchoReply, 0)),
            (v4::DstUnreachable, 0) => Some((v6::DstUnreachable, v6d::NoRoute.into())),
            (v4::DstUnreachable, 1) => Some((v6::DstUnreachable, v6d::AddrUnreachable.into())),
            (v4::DstUnreachable, 3) => Some((v6::DstUnreachable, v6d::PortUnreachable.into())),
            (v4::DstUnreachable, 4) => Some((v6::PktTooBig, 0)),
            _ => None,
        }
    }
}

/// Calculate the checksum of `data`.
#[inline]
fn checksum(mut data: &[u8]) -> u32 {
    let mut s = 0u32;
    while data.len() >= 2 {
        s += ((data[0] as u32) << 8) | data[1] as u32;
        data = &data[2..];
    }
    if data.len() == 1 {
        s += data[0] as u32;
    }
    s
}

/// Calculate the negative checksum of `data`.
#[inline]
fn checksum_neg(mut data: &[u8]) -> u32 {
    let mut s = 0u32;
    while data.len() >= 2 {
        s += !(((data[0] as u16) << 8) | data[1] as u16) as u32;
        data = &data[2..];
    }
    if data.len() == 1 {
        s += !(data[0] as u16) as u32;
    }
    s
}

/// checksum field
#[inline]
fn checksum_final(mut s: u32) -> u16 {
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}
