from scapy.all import *
import traceback

try:
    class Modbus(Packet):
        name = 'Modbus'
        fields_desc = [
                XShortField("transId", int('8', 16)),
                XShortField("protoId",int('0000', 16)),
                ShortField("len", int('6', 16)),
                XByteField("unitId", int('1', 16)),
                XByteField("funcCode", int('5', 16)),
                XShortField("outputAddr", int('0001', 16)),
                XShortField("outputValue", int('ff00', 16))
                ]

    # Ether Fields
    src_mac = '60:a4:4c:3e:16:c1'
    dst_mac = 'a4:1f:72:56:1f:75'

    # IP Fields
    src_ip = '192.168.1.10'
    dst_ip = '192.168.1.5'
    leng = 52
    i_d = 30001
    ip_flags = 2
    ttl = 128
    ip_checksum = int('0233', 16)

    # TCP Fields
    sport = 51228
    dport = 2502
    seq = int('214eca35', 16)
    ack = int('ac7f79de', 16)
    tcp_flags = 'PA'
    window = 512
    tcp_checksum = int('4e57', 16)
    urgptr = 0

    pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, len=leng, id=i_d, flags=ip_flags, ttl=ttl, chksum=ip_checksum)/TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=tcp_flags, window=window, chksum=tcp_checksum, urgptr=urgptr)/Modbus()
    hexdump(pkt)
    #wrpcap('filtered.pcap', pkt)
    sendp(pkt)
except:
    traceback.print_exc()