from scapy.all import *
import binascii

#2863369a2104 mac dest S71500 PLC_15
#6805cabcc38e mac origen (CAMBIAR POR LA DEL EQUIPO) -->	ether 00:e0:4c:68:06:28 
#810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000 Payload + resto

raw_pkt = binascii.unhexlify('2863369a210400e04c680628810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000')
pn_dcp = Ether(raw_pkt)
pn_dcp.show()
sendp(pn_dcp,iface="en8")