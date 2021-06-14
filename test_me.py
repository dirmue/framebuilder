#!/usr/bin/env python3

from framebuilder import ipv4, tcp, udp, tools

iface = 'wlp3s0'

ip_handler = ipv4.IPv4Handler(iface)
pk_count = 0
try:
    while True:
        pk = ip_handler.receive()
        if pk is not None:
            pk_count += 1
            print('--- Packet #{} ---'.format(pk_count))
            pk.info()
            if pk.protocol == 6:
                tcp_seg = tcp.TCPSegment.from_packet(pk)
                tcp_seg.info()
            if pk.protocol == 17:
                udp_dgram = udp.UDPDatagram.from_packet(pk)
                udp_dgram.info()
except KeyboardInterrupt:
    print('--- Finished ---')
