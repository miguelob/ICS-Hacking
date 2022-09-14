from scapy.all import *
import binascii

#010ecf00000 dest mac address (Do not change)
#6805cabcc38e Origin mac address (Change to your pc mac address) -->	Example: ether 00:e0:4c:68:06:28 
#810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000 Payload + Others (Do not change)

# Change org mac address and merge 3 parts into one hex string and replace the one below
def Discovery(mac):
    Hex = '010ecf00000000' + mac + '810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000'
    raw_pkt = binascii.unhexlify(Hex)
    pn_dcp = Ether(raw_pkt)
    pn_dcp.show()
    sendp(pn_dcp,iface="en8")
    print("Discovery packet sent")
    print("Please check wireshark for the response")