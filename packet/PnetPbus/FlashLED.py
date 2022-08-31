from scapy.all import *
import binascii

#2863369a2104 dest mac address S71500 PLC_15 (Use Discovery.py and wireshark to get any profinet device address)
#6805cabcc38e org mac addres (MUST CHANGE TP YOUR PC MAC ADDRESS) -->	Example: ether 00:e0:4c:68:06:28 
#810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000 Payload + Others (Do not change)

# Change org mac address and merge 3 parts into one hex string and replace the one below
class FlashLED(macog,macdst):
    def __init__(self, macog,macdst):
        Hex = macdst + macog + '810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000'
        raw_pkt = binascii.unhexlify(Hex)
        pn_dcp = Ether(raw_pkt)
        pn_dcp.show()
        sendp(pn_dcp,iface="en8")
        print("Flash LED packet sent")
