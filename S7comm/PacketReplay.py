from scapy.all import *
import binascii
import socket

hex = binascii.unhexlify(str('2863369a210400e04c68062808004500004d000040004006489fc0a838acc0a8380fd8fd0066b9c2e7bff89fc29d5018ffff8b8400000300002502f08032010000000a000e00060501120a10020002000184000000000400100032'))
pkt = Raw(hex)
print(hexdump(pkt))

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
server_address = ('192.168.56.15', 102)
sock.connect(server_address)
#sock.sendall(bytes(pkt)) 