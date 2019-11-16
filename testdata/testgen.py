from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.utils import wrpcap


MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
MAC_ZERO = '00:00:00:00:00:00'

IFACE_MAC = [b'TWD2_0', b'TWD2_1', b'TWD2_2', b'TWD2_3']
IFACE_IPV4 = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']


def gen_udp():
    ether = Ether(src=IFACE_MAC[0], dst=IFACE_MAC[1])
    udp = UDP(sport=3333, dport=4444) / b'1234'
    ins = [ether / IP(src='10.0.0.1', dst='10.0.0.2') / udp]
    outs = [ether / IPv6(src='2001:db8:1:4646::10.0.0.1', dst='2001:db8:2:4646::10.0.0.2') / udp]
    wrpcap("udp_v4.pcap", ins)
    wrpcap("udp_v6.pcap", outs)


def gen_tcp():
    ether = Ether(src=IFACE_MAC[0], dst=IFACE_MAC[1])
    tcp = TCP(sport=3333, dport=4444) / b'1234'
    ins = [ether / IP(src='10.0.0.1', dst='10.0.0.2') / tcp]
    outs = [ether / IPv6(src='2001:db8:1:4646::10.0.0.1', dst='2001:db8:2:4646::10.0.0.2') / tcp]
    wrpcap("tcp_v4.pcap", ins)
    wrpcap("tcp_v6.pcap", outs)


def gen_arp():
    def gratuitous_arp(iface, mac, ip):
        return Ether(src=mac, dst=MAC_BROADCAST) / Dot1Q(vlan=iface) \
               / ARP(op='is-at', hwsrc=mac, psrc=ip, hwdst=MAC_ZERO, pdst=ip)

    gratuitous_arps = [
        ('out', gratuitous_arp(i, IFACE_MAC[i], IFACE_IPV4[i]))
        for i in range(4)
    ]
    mac0 = b'@WRJ_1'
    ip0 = '10.0.1.2'
    arps = [
        ('in', Ether(src=mac0, dst=MAC_BROADCAST) / Dot1Q(vlan=0)
         / ARP(op='who-has', hwsrc=mac0, psrc=ip0, hwdst=MAC_BROADCAST, pdst=IFACE_IPV4[0])),
        ('out', Ether(src=IFACE_MAC[0], dst=mac0) / Dot1Q(vlan=0)
         / ARP(op='is-at', hwsrc=IFACE_MAC[0], psrc=IFACE_IPV4[0], hwdst=mac0, pdst=ip0)),
    ]
    packets = gratuitous_arps + arps
    packets = [p for (t, p) in packets]
    wrpcap("arp.pcap", packets)


gen_udp()
gen_tcp()
gen_arp()
