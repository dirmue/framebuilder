#!/usr/bin/env python3

import sys, time
from framebuilder import tcp

h = tcp.TCPHandler.listen('eth0', int(sys.argv[1]),debug=True)
start = time.time()
while h.state != h.CLOSED:
    #h.receive()
    print((h.receive()).decode('utf-8'), end='')
print('\n---------------\ntransfer took', time.time() - start, 'seconds')
print('\n\nBye!')
