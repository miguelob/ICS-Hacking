import socket
import struct

if __name__ == "__main__":
    dstport = 102
    dstip = "192.168.56.15"
    addr = (dstip,dstport)
    sock = socket.socket(socket.AF_INET, socket.sock_STREAM)
    sock.connect(addr)
    #COTP CR TPDU
    sock.send("\x03\x00\x00\x16\x11\xe0\00\x00\x00\x08\x00\xc1\x02\x06\x00\xc2\x02\x06\x00\xc0\x01\x0a")