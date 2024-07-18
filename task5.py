import socket
import struct
import binascii
import sys

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': binascii.hexlify(dest_mac).decode('ascii'),
        'src_mac': binascii.hexlify(src_mac).decode('ascii'),
        'proto': proto
    }

def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 0xF) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = '.'.join(map(str, src))
    target_ip = '.'.join(map(str, target))
    return {
        'version': version,
        'header_len': header_len,
        'ttl': ttl,
        'proto': proto,
        'src_ip': src_ip,
        'target_ip': target_ip
    }

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return {
        'icmp_type': icmp_type,
        'code': code,
        'checksum': checksum
    }

def tcp_segment(data):
    src_port, dest_port, seq, ack, offset_res = struct.unpack('! H H L L H', data[:14])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'seq': seq,
        'ack': ack,
        'offset_res': offset_res
    }

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length
    }

def packet_sniffer():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        raw_data, addr = s.recvfrom(65536)
        eth_frame = ethernet_frame(raw_data)
        print('Ethernet Frame:')
        print(f'Source MAC: {eth_frame["src_mac"]}, Destination MAC: {eth_frame["dest_mac"]}, Protocol: {eth_frame["proto"]}')

        if eth_frame['proto'] == 0x0800:
            ipv4_packet_data = ipv4_packet(raw_data[14:])
            print('IPv4 Packet:')
            print(f'Source IP: {ipv4_packet_data["src_ip"]}, Destination IP: {ipv4_packet_data["target_ip"]}, Protocol: {ipv4_packet_data["proto"]}')

            if ipv4_packet_data['proto'] == 1:
                icmp_packet_data = icmp_packet(raw_data[34:])
                print('ICMP Packet:')
                print(f'Type: {icmp_packet_data["icmp_type"]}, Code: {icmp_packet_data["code"]}, Checksum: {icmp_packet_data["checksum"]}')
            elif ipv4_packet_data['proto'] == 6:
                tcp_segment_data = tcp_segment(raw_data[34:])
                print('TCP Segment:')
                print(f'Source Port: {tcp_segment_data["src_port"]}, Destination Port: {tcp_segment_data["dest_port"]}, Sequence Number: {tcp_segment_data["seq"]}, Acknowledgment Number: {tcp_segment_data["ack"]}')
            elif ipv4_packet_data['proto'] == 17:
                udp_segment_data = udp_segment(raw_data[34:])
                print('UDP Segment:')
                print(f'Source Port: {udp_segment_data["src_port"]}, Destination Port: {udp_segment_data["dest_port"]}, Length: {udp_segment_data["length"]}')

if __name__ == "__main__":
    packet_sniffer()