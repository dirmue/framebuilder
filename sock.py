#!/usr/bin/env python3

import sys, time, struct
import socket as s

def print_tcp_info(sock):
    tcp_info = struct.unpack("B"*8+"I"*24, sock.getsockopt(s.SOL_TCP, s.TCP_INFO, 32))
    info_str = f'cwin: {tcp_info[26]}'
    # ... see /usr/include/linux/tcp.h
    print(info_str)


sock = s.socket(s.AF_INET, s.SOCK_STREAM)
dst_ip = s.gethostbyname(sys.argv[1])
start = time.time()
sock.connect((dst_ip, int(sys.argv[2])))
with open(sys.argv[3], 'r') as file:
    while True:
        payload = file.read(1460).encode()
        if len(payload) == 0:
            break        
        sock.send(payload)
        print_tcp_info(sock)
    print('.', end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
sock.close()
