from scapy.all import *
import binascii

#010ecf00000 mac dest
#6805cabcc38e mac origen (CAMBIAR POR LA DEL EQUIPO) -->	ether 00:e0:4c:68:06:28 
#810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000 Payload + resto

raw_pkt = binascii.unhexlify('010ecf00000000e04c680628810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000')
pn_dcp = Ether(raw_pkt)
pn_dcp.show()
sendp(pn_dcp,iface="en8")
