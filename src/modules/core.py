import socket
import struct

class Sniff:
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.to_mac_addr(dest_mac), self.to_mac_addr(src_mac), socket.htons(proto), data[14:]

    def to_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def to_ipv4(self, addr):
        return '.'.join(map(str, addr))

    def ipv4_packet(self, data):
        vheadlength = data[0]
        ver = vheadlength >> 4
        headlength = (vheadlength & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return ver, headlength, ttl, proto, self.to_ipv4(src), self.to_ipv4(target), data[headlength:]