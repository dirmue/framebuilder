#!/usr/bin/env python3

import sys, time
import socket as s

server = s.socket(s.AF_INET, s.SOCK_STREAM)
dst_ip = s.gethostbyname(sys.argv[1])
server.bind((dst_ip, int(sys.argv[2])))
server.listen()
sock = server.accept()[0]
start = time.time()
while True:
    try:
        data = sock.recv(65635)
        print(data.decode('utf-8', end='')
    except EOFError:
        sock.close()
        break
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
server.close()
