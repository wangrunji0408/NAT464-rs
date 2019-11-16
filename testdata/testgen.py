from scapy.layers.inet import ICMP, fragment
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.utils import wrpcap


MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
MAC_ZERO = '00:00:00:00:00:00'

IFACE_MAC = [b'TWD2_0', b'TWD2_1', b'TWD2_2', b'TWD2_3']
IFACE_IPV4 = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']

# use VLAN tag to store the metadata of a packet
#   id: { 0: input, 1: output }
#   vlan: iface ID
IN, OUT = 0, 1

# common header for IP464 test
ETHER = Ether(src=IFACE_MAC[0], dst=IFACE_MAC[1])
IPV4_HEADER = ETHER / IP(src='10.0.0.1', dst='10.0.0.2')
IPV6_HEADER = ETHER / IPv6(src='2001:db8:1:4646::10.0.0.1', dst='2001:db8:2:4646::10.0.0.2')


def gen_udp():
    udp = UDP(sport=3333, dport=4444) / b'1234'
    ins = [IPV4_HEADER / udp]
    outs = [IPV6_HEADER / udp]
    wrpcap("udp_v4.pcap", ins)
    wrpcap("udp_v6.pcap", outs)


def gen_tcp():
    tcp = TCP(sport=3333, dport=4444) / b'1234'
    ins = [IPV4_HEADER / tcp]
    outs = [IPV6_HEADER / tcp]
    wrpcap("tcp_v4.pcap", ins)
    wrpcap("tcp_v6.pcap", outs)


def gen_icmp():
    icmps = [
        (ICMP(type='echo-request') / b'hello',
         ICMPv6EchoRequest() / b'hello'),
        (ICMP(type='echo-reply') / b'hello',
         ICMPv6EchoReply() / b'hello'),
        (ICMP(type='time-exceeded', code='ttl-zero-during-transit'),
         ICMPv6TimeExceeded(code='hop limit exceeded in transit')),
        (ICMP(type='time-exceeded', code='ttl-zero-during-reassembly'),
         ICMPv6TimeExceeded(code='fragment reassembly time exceeded')),
        (ICMP(type='dest-unreach', code='network-unreachable'),
         ICMPv6DestUnreach(code='No route to destination')),
        (ICMP(type='dest-unreach', code='host-unreachable'),
         ICMPv6DestUnreach(code='Address unreachable')),
        (ICMP(type='dest-unreach', code='port-unreachable'),
         ICMPv6DestUnreach(code='Port unreachable')),
        (ICMP(type='dest-unreach', code='fragmentation-needed', nexthopmtu=1500),
         ICMPv6PacketTooBig(mtu=1500)),
    ]
    ins = [IPV4_HEADER / icmpv4 for (icmpv4, _) in icmps]
    outs = [IPV6_HEADER / icmpv6 for (_, icmpv6) in icmps]
    wrpcap("icmp_v4.pcap", ins)
    wrpcap("icmp_v6.pcap", outs)


def gen_frag():
    payload = UDP(sport=3333, dport=4444) / ('G' * 4000)
    ins = fragment(IPV4_HEADER / payload, fragsize=1480)
    outs = fragment6(IPV6_HEADER / IPv6ExtHdrFragment(id=1) / payload, fragSize=1480 + 14 + 40 + 8)
    wrpcap("frag_v4.pcap", ins)
    wrpcap("frag_v6.pcap", outs)


def gen_arp():
    def gratuitous_arp(iface, mac, ip):
        return Ether(src=mac, dst=MAC_BROADCAST) / Dot1Q(id=OUT, vlan=iface) \
               / ARP(op='is-at', hwsrc=mac, psrc=ip, hwdst=MAC_ZERO, pdst=ip)

    gratuitous_arps = [
        gratuitous_arp(i, IFACE_MAC[i], IFACE_IPV4[i])
        for i in range(4)
    ]
    mac0 = b'@WRJ_1'
    ip0 = '10.0.1.2'
    arps = [
        Ether(src=mac0, dst=MAC_BROADCAST) / Dot1Q(id=IN, vlan=0)
        / ARP(op='who-has', hwsrc=mac0, psrc=ip0, hwdst=MAC_BROADCAST, pdst=IFACE_IPV4[0]),
        Ether(src=IFACE_MAC[0], dst=mac0) / Dot1Q(id=OUT, vlan=0)
        / ARP(op='is-at', hwsrc=IFACE_MAC[0], psrc=IFACE_IPV4[0], hwdst=mac0, pdst=ip0),
    ]
    packets = gratuitous_arps + arps
    wrpcap("arp.pcap", packets)


gen_icmp()
gen_udp()
gen_tcp()
gen_frag()

gen_arp()
