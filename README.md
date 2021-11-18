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
![ModBus Logo](https://github.com/miguelob/TFG/blob/main/images/modbus.png)
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

## Profinet & Profibus
![Profinet & Profibus logos](https://github.com/miguelob/TFG/blob/main/images/prof.png)

On this folder you will find several attacks and pcaps for pentesting devices working on these protocols.

- [Discovery.py](https://github.com/miguelob/TFG/blob/main/Profinet%20%26%20Profibus/Discovery.py): This scripts sends a Ethernet packet containing a hex string that acts as a Profinet discovery packet (pn_dcp). **You must need to change the hex stream according to the source mac address to your mac address.** It is recommended to use [Wireshark](https://www.wireshark.org) and filtering by this type of packets. You must need Scapy to run the script.
- [FlashLED.py](https://github.com/miguelob/TFG/blob/main/Profinet%20%26%20Profibus/FlashLED.py): This script is similar to the previous one. First you will need to run the *Discovery.py* in order to get a mac address of any Profinet device. This programm is optimized to blick the status led on a S7-1500 PLC. One you got the mac address, replace it on the hex stream, as well as the origin mac address.
- [PacketReplay-Completo.py](https://github.com/miguelob/TFG/blob/main/Profinet%20%26%20Profibus/PacketReplay-Completo.py): This script is a complete python programm to scann, craft and send profinet packets. You must edit the full code in order to be prepeared to run it.

## Snap7 (S7Comm & S7Comm Plus)
![Snap7 logo](https://github.com/miguelob/TFG/blob/main/images/s7.png)

In this resopitory you will find attacks, documents, and pcaps of both S7Comm protocol and its bigger brother S7Comm+:
- [S7Comm](https://github.com/miguelob/TFG/tree/main/S7comm): 

