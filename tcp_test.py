#!/usr/bin/env python3

import sys

from framebuilder import tcp

h = tcp.TCPHandler('wlp3s0')
h.open('78.47.151.229', int(sys.argv[1]))

with open(sys.argv[2], 'r') as file:
    payload = file.read().encode()
    h.send(payload)
h.close()
