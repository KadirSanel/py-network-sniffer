import textwrap
import libs.tabs as tabs
from modules.packets import Packets

class PrintPack:

    def __init__(self):
        self.packets = Packets()

    def print_icmp(self, data):
        icmptype, code, checksum, data = self.packets.icmp_packet(data)
        print(tabs.TAB_1 + 'ICMP Packet:'.format())
        print(tabs.TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmptype, code, checksum))
        print(tabs.TAB_2 + 'Data:')
        print(self.format_multi_line(tabs.DATA_TAB_3, data))

    def print_tcp(self, data):
        src_port, dest_port, seq, acknow, urg, ack, psh, rst, syn, fin, data = self.packets.tcp_packet(data)
        print(tabs.TAB_1 + 'TCP Segment:'.format())
        print(tabs.TAB_2 + 'Src Port: {}, Dest Port: {}'.format(src_port, dest_port))
        print(tabs.TAB_2 + 'Seq: {}, Acknow: {}'.format(seq, acknow))
        print(tabs.TAB_2 + 'Flags:')
        print(tabs.TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(urg, ack, psh, rst, syn, fin))
        print(tabs.TAB_2 + 'Data:')
        print(self.format_multi_line(tabs.DATA_TAB_3, data))

    def format_multi_line(self, prefix, string, size = 80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size %2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])