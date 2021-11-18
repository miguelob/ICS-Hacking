# TFG
This is a cibersecurity repository where several industrial protocols and systems were investigated and pentested.
## Protocols
- S7Comm & S7Comm Plus
- Profinet & Profibus
- SCADA
- ModBus
## Tools
- Kali Linux
- Wireshark
- Scapy
- Python & packages
## Modbus 
![ModBus Logo](https://www.opiron.com/wp-content/uploads/2017/06/modbus.png)
There are two Packet Replay attacks on these protocol. These two are into the Modbus folder of the repository [Modbus Folder](https://github.com/miguelob/TFG/tree/main/Modbus). Here you will find two .py files for these attack. On the [PacketReplay-Completo.py](https://github.com/miguelob/TFG/blob/main/Modbus/PacketReplay-Completo.py) differs from [PacketReplay.py](https://github.com/miguelob/TFG/blob/main/Modbus/PacketReplay.py) as it crafts a complete Modbus paquet from scratch. The simple PacketReplay.py just focus on crafting the Modbus field over TCP/IP.

For both Python scripts, you will need to import Scapy module with the following command:

**Windows Scapy install**

`pip install --pre scapy[complete]`

**MacOS Scapy install**

`pip install --pre scapy[basic]`

Then you need to instal *Brew* packet if you have not already have it:

`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"`

Then you proceed installing Scapy's dependencies using Brew:
```
$ brew update
$ brew install libpcap
```

Finally enable it on Scapy:

`conf.use_pcap = True`
