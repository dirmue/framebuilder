#!/usr/bin/env python3

import sys, time, socket
from framebuilder import tcp, tools

dst_ip = sys.argv[1]
if not tools.is_valid_ipv4_address(sys.argv[1]):
    try:
        dst_ip = socket.gethostbyname(sys.argv[1])
    except:
        sys.exit(1)

h = tcp.TCPHandler('wlp3s0', debug=False)
start = time.time()
h.open(dst_ip, int(sys.argv[2]))

if len(sys.argv) > 3:
    # transfer a file ...
    with open(sys.argv[3], 'r') as file:
        payload = file.read().encode()
        h.send(payload)
else:
    # poor man's netcat
    try:
        while h.state != h.CLOSED:
            user_input = input() + '\n'
            h.send(user_input.encode())
    except (KeyboardInterrupt, EOFError):
        h.close()
if h.state == h.ESTABLISHED:
    h.close()
    while h.state != h.CLOSED:
        print((h.receive()).decode('utf-8'), end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
print('\n\nBye!')
