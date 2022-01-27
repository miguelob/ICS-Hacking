from scapy.all import *
import binascii

def Discovery(MAC, interface = "en8"):

    raw_pkt = binascii.unhexlify('010ecf000000'+MAC+'810000008892fefe05000000000100010004ffff00000000000000000000000000000000000000000000000000000000')
    pn_dcp = Ether(raw_pkt)
    pn_dcp.show()
    sendp(pn_dcp,iface=interface)

def FlashLED():

    raw_pkt = binascii.unhexlify('2863369a210400e04c680628810000008892fefd04000000000400000008050300040000010000000000000000000000000000000000000000000000')
    pn_dcp = Ether(raw_pkt)
    pn_dcp.show()
    sendp(pn_dcp,iface="en8")
