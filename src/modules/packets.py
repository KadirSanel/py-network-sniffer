import struct

class Packets:
    def icmp_packet(self, data):
        icmptype, code, checksum = struct.unpack('! B B H', data[:4])
        return icmptype, code, checksum, data[4:]

    def tcp_packet(self, data):
        (src_port, dest_port, seq, acknow, osetrespack) = struct.unpack('! H H L L H', data[:14])
        offset = (osetrespack >> 12) * 4
        urg = (osetrespack & 32) >> 5
        ack = (osetrespack & 16) >> 4
        psh = (osetrespack & 8) >> 3
        rst = (osetrespack & 4) >> 2
        syn = (osetrespack & 2) >> 1
        fin = osetrespack & 1
        return src_port, dest_port, seq, acknow, urg, ack, psh, rst, syn, fin, data[offset:]