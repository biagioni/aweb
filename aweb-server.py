#! /usr/bin/python3

# Author: Edoardo Biagioni, esb@hawaii.edu, 2026

# optional argument 1: directory holding web pages, instead of .
#   (certificates and private keys are always in ./certs and ./keys)
# optional argument 2: UDP port number, defaults to 1480
#   (can only use if optional argument 1 is present)

# limitation: can only send files/content up to the maximum UDP size
# This used to be 65507 bytes or less, but may be greater
# if using IPv6 and modern protocol implementations.

# networking code inspired by:
# https://pythontic.com/modules/socket/udp-client-server-example

import sys		# sys.argv
import socket
import os		# to read files
import pwd		# password file access, to change to nobody
import pathlib		# to go through the keys directory
import ssl		# for certificates

import cryptography	# keys
from cryptography.hazmat.primitives import serialization	# keys
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# https://stackoverflow.com/questions/4685217/parse-raw-http-headers
from http.server import BaseHTTPRequestHandler
from io import BytesIO

# start by reading all the private keys, then if we are root
# transition to user nobody
# private keys are found in the subdirectory "keys" of the directory we are
# started in.  Each private key is named after the host for which it
# is the private key, followed by .priv.  For example, www.example.org.priv
private_keys = {}
keysDir = pathlib.Path("keys")
for keyFile in keysDir.iterdir():
    if keyFile.is_file() and keyFile.name[-5:].lower() == ".priv":
        host = keyFile.name[:-5].lower()
        print("found key", keyFile, "for host", host)
        key_data = ''.encode("utf-8")
        with open(keyFile, 'rb') as fd:
            key_data = bytearray(fd.read())
            key = serialization.load_pem_private_key(key_data, password=None)
            if isinstance(key, rsa.RSAPrivateKey):
                private_keys[host] = key
# print("private keys", private_keys)
# for host in private_keys:
#     print("host", host, "key", private_keys[host])

# now that the keys are loaded, if we are root change to nobody/nogroup
if os.geteuid() == 0:
    os.setuid(pwd.getpwnam("nobody").pw_uid)
    print("root has become nobody")

# copied from somewhere on the web, I think
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

# codes for certificate requests, http requests, and https requests
httpSel = b'\01'.decode()
httpsSel = b'\02'.decode()
certSel = b'\03'.decode()
# mark the End Of a String
eos = b'\0'.decode()
# standard lines end in crnl
cr = 13
nl = 10
# the field names in a secure request's name-value pairs
nonce_name = 'Nonce: '
key_name = 'SessionKey: '

# return the string up to but not including the next newline
def truncEOL(bytes):
    index = 0;
    for b in bytes:
        if b == cr or b == nl:
            return bytes[:index]
        index = index + 1
    return bytes

# htmlDir is where the web pages are, default the current working directory
htmlDir     = os.getcwd()
if len(sys.argv) > 1:            # or as specified on the command line
	htmlDir = sys.argv[1]
localIP     = "0.0.0.0"
localPort   = 1480
if len(sys.argv) > 2:            # the UDP port may also be on the command line
	localPort = int(sys.argv[2])
# the maximum UDP size used to be 65K - 1
# in any case, this is the maximum size of requests, and
# most requests will be small, less than 1K bytes
bufferSize  = 65536

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("UDP server up and listening on port " + str(localPort))
print("web pages at " + htmlDir)

# infinite loop handling requests and sending responses
# if we don't have a valid response, it is fine to not respond
while(True):
    (request, address) = UDPServerSocket.recvfrom(bufferSize)
    clientMsg = "Message from Client:{}".format(request)
    clientIP  = "Client IP Address:{}".format(address)
    # print(clientIP)
    # print(clientMsg)
# valid methods are CRT for a certificate request, GET for an unencrypted
# http-like request, and CPT for an enCryPTed https-like request
    header = request[0:4].decode()
    print("header is " + header)
    nonce = ''
    sessionkey = ''
    if (header.lower() == "crt "):   # return a certificate
        message = request[4:].decode().casefold()
        domain_name = message.strip()
        print("certificate request for " + domain_name)
# https://stackoverflow.com/questions/295135/turn-a-string-into-a-valid-filename
        base_name = "".join(i for i in domain_name if i not in "\\/:*?<>| ")
        file_name = os.getcwd() + "/certs/" + base_name
        print("certificate file name is " + file_name)
        cert = ''.encode("utf-8")
        try:
            with open(file_name, 'rb') as fd:
                cert = bytearray(fd.read())
        except FileNotFoundError:
            print("certificate", file_name, "not found")
            continue              # restart by reading the next UDP packet
        responseStr = certSel + domain_name + eos
        # print(responseStr)
        response = responseStr.encode("utf-8") + cert
        # print(response)
        UDPServerSocket.sendto(response, address)
        continue    # done serving certificate, read new data from the socket
    # if it is an encrypted request, prepare to handle it, then continue
    # on the common code path for encrypted and unencrypted requests
    is_encrypted = False
    if (header.lower() == "cpt "):    # encrypted request after hostname\r\n
        # the hostname tells us which private key to use to decrypt the request
        # search for the newline.  Can't use request.decode().find()
        # because decode may fail due to bytes that aren't valid in utf-8
        currentIndex = 4
        crIndex = -1
        for byte in request[4:]:
            if byte == 13:
                crIndex = currentIndex + 1
            if byte == 10 and crIndex == currentIndex:
                break
            currentIndex = currentIndex + 1
        domain_name = request[4:currentIndex - 1].decode()
        print("got encrypted request for host name " + domain_name)
        base_name = "".join(i for i in domain_name if i not in "\\/:*?<>| ")
        if base_name in private_keys:
            key = private_keys[base_name]
            print("found key for", base_name)
            encrypted = request[currentIndex + 1:]
            print("length of encrypted data is", len(encrypted))
            request = key.decrypt(encrypted, padding.PKCS1v15())
            print("successfully decrypted request!")
            # print("successfully decrypted! request is:")
            # print(request.decode())
            nonceIndex = request.decode().index(nonce_name) + len(nonce_name)
            nonceStr = truncEOL(request[nonceIndex:]).decode()
            # print("converting to bytes:", nonceStr)
            nonce = bytes.fromhex(nonceStr)
            keyIndex = request.decode().index(key_name) + len(key_name)
            sessionkeyStr = truncEOL(request[keyIndex:]).decode()
            sessionkey = bytes.fromhex(sessionkeyStr)
            print("nonce ", nonceStr)
            # knowing the key, one can decrypt the content
            # print("key ", sessionkeyStr)
            # for security, nonces should have a minimum length
            if len(nonce) < 12:    # 12 is arbitrary, but not unreasonable
                print("warning: minimum nonce length 12, received",
                      len(nonce), nonceStr)
            # minimum requirements
            if len(nonce) > 0 and len(sessionkey) == 32:
                # extend the nonce to 16 bytes by prepending 0s
                while len(nonce) < 16:
                    blank = bytes(1)          # a single 0 byte
                    nonce = blank + nonce
                is_encrypted = True           # success!
            else:
                print("error: nonce, key", len(nonceStr), len(sessionkey))
        if not is_encrypted:
            print("decryption failed")
            continue                          # start over with the next UDP
# if this was an encrypted request, we successfully decrypted it.
# continue handling the request, just with is_encrypted set to true
    parsed = HTTPRequest(request)
    # print("parsed request as ", parsed)
    if (parsed.command.lower() == "get"):
        print("parsed command is GET")
        host = parsed.headers['host']
        path = parsed.path
        if path[:4].lower() == "http":   # error, no path
            path = '/'
        if path[-1] == '/' :
            path += 'index.html'
        file = htmlDir + path
        print("path is", path, "file", file)
        # print('reading file ' + file)
        content = ''.encode("utf-8")
        try:
            with open(file, 'rb') as fd:
                content = bytearray(fd.read())
        except FileNotFoundError:
            print(file, "not found")
            continue              # restart by reading the next UDP packet
        if localPort != 1480:
            host += ':' + str(localPort)
        ctype = 'application/octet-stream'
        print("file[-5:].lower() is ", file[-5:].lower())
        if file[-5:].lower() == ".html":
            ctype = 'text/html'
        if file[-4:].lower() == ".pdf":
            ctype = 'application/pdf'
        if file[-4:].lower() == ".png":
            ctype = 'image/png'
        if file[-4:].lower() == ".jpg" or file[-5:].lower() == ".jpeg":
            ctype = 'image/jpeg'
        print("content type is", ctype)
        ctype = 'Content-Type: ' + ctype
        response = ''
        print("content length is", len(content))
        # encrypted and unencrypted have significantly different details
        # both create a response variable that is sent back
        if is_encrypted:
            header = httpsSel + nonceStr + eos
            plainheader = 'HTTP/1.1 200 OK\r\n' + ctype + '\r\n\r\n'
            plaintext = plainheader.encode("utf-8") + content
            # print("session key is ", sessionkeyStr)
            # AESGCM is Advanced Encryption Standard Galois Counter Mode
            # -- did you really want to know?
            aesgcm = AESGCM(sessionkey)
            # print("iv", bytes.hex(nonce));
# 3rd parameter to aesgcm.encrypt is data that is authenticated but unencrypted
            encrypted_response = aesgcm.encrypt(nonce, plaintext, None)
            # print("encrypted response:", encrypted_response.hex())
            response = header.encode("utf-8") + encrypted_response
        else:
            header = httpSel + 'http://' + host + parsed.path + eos
            header = header + 'HTTP/1.1 200 OK\r\n' + ctype + '\r\n\r\n'
            print(header)
            response = header.encode("utf-8") + content
        # print(response.hex())
        print("response length is", len(response))
        UDPServerSocket.sendto(response, address)
    else:
        print("error, unknown method", parsed.command)

print("UDP server quit, oh no!")
