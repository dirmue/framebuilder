#!/usr/bin/env python3

from framebuilder import ipv4, udp, tools

iface = 'enp7s0f3u1u1'
target_ip = '78.47.151.229'
remote_port = 33333
local_port = 12345

udp_dgram = udp.UDPDatagram()
udp_dgram.src_port = local_port
udp_dgram.dst_port = remote_port
udp_dgram.payload = b'\x0a' * 100

ip_handler = ipv4.IPv4Handler(iface, target_ip, proto=17)
ip_handler.send(udp_dgram)
udp_dgram.info()
