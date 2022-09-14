from scapy.all import *
import binascii

def FlashLED(macog,macdst,interface):
    Hex = macdst + macog + '810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000'
    raw_pkt = binascii.unhexlify(Hex)
    pn_dcp = Ether(raw_pkt)
    pn_dcp.show()
    sendp(pn_dcp,iface=interface)
    print("Flash LED packet sent")
def Discovery(mac,interface):
    Hex = '010ecf00000000' + '147dda79a57c' + '810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000'
    raw_pkt = binascii.unhexlify(Hex)
    pn_dcp = Ether(raw_pkt)
    pn_dcp.show()
    sendp(pn_dcp,iface=interface)
    print("Discovery packet sent")
    print("Please check wireshark for the response")