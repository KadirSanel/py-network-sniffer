import socket
import libs.tabs as tabs
from libs.print_packets import PrintPack
from modules.packets import Packets
from modules.core import Sniff

packets = Packets()
print_pack = PrintPack()
sniff = Sniff()

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, ethernet_proto, data = sniff.ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Dest :  {}, Src: {}, Proto: {}'.format(dest_mac, src_mac, ethernet_proto))

        if ethernet_proto == 8:
            (ver, headlength, ttl, proto, src, target, data) = sniff.ipv4_packet(data)
            print(tabs.TAB_1 + 'IPv4 Packet:')
            print(tabs.TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(ver, headlength, ttl))
            print(tabs.TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                print_pack.print_icmp(data)

            elif proto == 6:
                print_pack.print_tcp(data)

main()

