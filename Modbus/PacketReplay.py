from scapy.all import *
import socket

class Modbus(Packet):
    name = 'Modbus'
    fields_desc = [
            XShortField("transId", int('8', 16)),
            XShortField("protoId",int('0000', 16)),
            ShortField("len", int('6', 16)),
            XByteField("unitId", int('1', 16)),
            XByteField("funcCode", int('5', 16)),
            XShortField("outputAddr", int('0000', 16)),
            XShortField("outputValue", int('ff00', 16))
            ]

pkt = Modbus()
sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
server_address = ('192.168.1.5', 502)
sock.connect(server_address)
sock.sendall(bytes(pkt))
data = sock.recv(1024)
print("RX: ",data)