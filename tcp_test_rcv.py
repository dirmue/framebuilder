#!/usr/bin/env python3

import sys, time, socket
from framebuilder import tcp, tools

h = tcp.TCPHandler.listen('eth0', int(sys.argv[1]),debug=False)
start = time.time()
while h.state != h.CLOSED:
    print((h.receive()).decode('utf-8'), end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
print('\n\nBye!')
