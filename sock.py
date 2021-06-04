#!/usr/bin/env python3

import sys, time
import socket as s

sock = s.socket(s.AF_INET, s.SOCK_STREAM)
dst_ip = s.gethostbyname(sys.argv[1])
start = time.time()
sock.connect((dst_ip, int(sys.argv[2])))
with open(sys.argv[3], 'r') as file:
    payload = file.read().encode()
    sock.send(payload)
    print('.', end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
sock.close()
