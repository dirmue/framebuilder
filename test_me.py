#!/usr/bin/env python3

from framebuilder import ipv4, tcp, tools

iface = 'enp7s0f3u1u1'
target_ip = '78.47.151.229'
remote_port = 33333
local_port = 12345

tcp_seg = tcp.TCPSegment()
tcp_seg.src_port = local_port
tcp_seg.dst_port = remote_port
tcp_seg.syn = 1
tcp_seg.payload = 'Hello World!'.encode() * 50
tcp_seg.add_tcp_mss_option(1000)

ip_handler = ipv4.IPv4Handler(iface, target_ip, proto=6)
ip_handler.send(tcp_seg)
tcp_seg.info()
