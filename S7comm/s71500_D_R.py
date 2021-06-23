#!/usr/local/bin/python
#READING THE DIGITAL INPUT/OUTPUT MEMORY OF THE PLC
import sys
from scapy.all import *
import binascii
sport= random.randint(1024,2000)
#SYN
ip=IP(src='192.168.1.37',dst='192.168.1.10',proto=6,flags=2)
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

#\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x01\x00\x00\x0e\x00\x00
#\x04 READ VARIABLE
#\x01\x12\x0a\x10\x02
#\x00\x01 LENGTH
#\x00\x00
#\x82 Q MEMORY - CHANGE FOR \x81 WHEN READING THE INPUT MEMORY. EXAMPLE SHOWED BELOW IN THE VARIABLE CALLED sensor_input
#\x00\x00\x08 ADDRESS
header=TCP(sport=sport, dport=102, flags='PA', seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40) 
#------------------------------PAYLOAD FOR SPACE OF MEMORY Q 1.0-----------------------------------
sensor = "\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x01\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x82\x00\x00\x08"
print(binascii.b2a_hex(bytes(sensor.encode("UTF-8"))))

#sensor_input = "\x03\x00\x00\x1f\x02\xf0\x80\x32\x01\x00\x00\x01\x00\x00\x0e\x00\x00\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x81\x00\x00\x08"

rsp_1 = sr1(ip/header/sensor)
s71PA=TCP(sport=sport,dport=102,flags='A',seq=rsp_1.ack, ack=rsp_1.len+rsp_1.seq-40)
send(ip/s71PA)
#----------------------------------------PRINTING RESPONSE-----------------------------------------
len_request = len(sensor)
print("DATOS: ",binascii.b2a_hex(bytes(sensor[len_request-4:len_request-3].encode("UTF-8"))))
if (binascii.hexlify(sensor[len_request-4:len_request-3]))=='82':
    print ("Reading: Digital Output Memory")
    #print ("Byte Address: " + str(int(ultrasonic[len_request-1:len_request].encode("HEX"),16)/8))
    print ("Memory Addressed: Q " + str(int(sensor[len_request-1:len_request].encode("HEX"),16)/8) + ".0")
load_len = len(rsp_1.load.encode("HEX"))
print ("Value (HEX): " + str(rsp_1.load.encode("HEX")[load_len-1:load_len]) + ", Value (INT): " + str(int(rsp_1.load.encode("HEX")[load_len-1:load_len],16)))


