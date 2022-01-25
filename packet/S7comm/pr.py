from scapy.all import *

pkts = rdpcap('/Users/miguel/OneDrive - Universidad Pontificia Comillas/ICAI_4GITT/TFG/TFG/S7comm/s7_w.pcap')
print(hexdump(pkts[182]))

sendp(pkts[182], iface="en8")