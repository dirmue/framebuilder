#!/usr/bin/env python3

import sys
from framebuilder import tcp

h = tcp.TCPHandler('wlp3s0')
h.open('78.47.151.229', int(sys.argv[1]))

payload = b'Hello World\n' * 10000
h.send(payload)
h.close()
