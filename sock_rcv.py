#!/usr/bin/env python3

import sys, time
import socket as s

server = s.socket(s.AF_INET, s.SOCK_STREAM)
dst_ip = '172.31.1.100'
server.bind((dst_ip, int(sys.argv[1])))
server.listen()
sock = server.accept()[0]
start = time.time()
while True:
    data = sock.recv(1412)
    if len(data) == 0:
        sock.close()
        break
    print(data.decode('utf-8'), end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
server.close()
