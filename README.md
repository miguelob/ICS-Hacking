# ICS and PLC Pentesting and Hacking
This is a cibersecurity repository where several industrial protocols and systems were investigated and pentested. This project was born as a telecommunications engineering final degree project at the [Universidad Pontificia de Comillas ICAI](https://www.comillas.edu/icai) by me, **Miguel Oleo Blanco**. For contacting me, please check the Contact section at the end. You can find examples of the attacks on my [YouTube channel](https://www.youtube.com/c/Migueloleoblanco).
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
![ModBus Logo](https://github.com/miguelob/ICS-Hacking/blob/main/images/modbus.png)
There are two Packet Replay attacks on these protocol. These two are into the Modbus folder of the repository [Modbus Folder](https://github.com/miguelob/ICS-Hacking/tree/main/Modbus). Here you will find two .py files for these attack. On the [PacketReplay-Complete.py](https://github.com/miguelob/ICS-Hacking/blob/main/Modbus/PacketReplay-Complete.py) differs from [PacketReplay.py](https://github.com/miguelob/ICS-Hacking/blob/main/Modbus/PacketReplay.py) as it crafts a complete Modbus paquet from scratch. The simple PacketReplay.py just focus on crafting the Modbus field over TCP/IP.

For both Python scripts, you will need to import Scapy module with the following command:

**Windows Scapy install**

```
pip install --pre scapy[complete]
```

**MacOS Scapy install**

```
pip install --pre scapy[basic]
```

Then you need to instal *Brew* packet if you have not already have it:

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Then you proceed installing Scapy's dependencies using Brew:
```
$ brew update
$ brew install libpcap
```

Finally enable it on Scapy:

`conf.use_pcap = True`

## Profinet & Profibus
![Profinet & Profibus logos](https://github.com/miguelob/ICS-Hacking/blob/main/images/prof.png)

On this folder you will find several attacks and pcaps for pentesting devices working on these protocols.

- [Discovery.py](https://github.com/miguelob/ICS-Hacking/blob/main/Profinet%20%26%20Profibus/Discovery.py): This scripts sends a Ethernet packet containing a hex string that acts as a Profinet discovery packet (pn_dcp). **You must need to change the hex stream according to the source mac address to your mac address.** It is recommended to use [Wireshark](https://www.wireshark.org) and filtering by this type of packets. You must need Scapy to run the script.
- [FlashLED.py](https://github.com/miguelob/ICS-Hacking/blob/main/Profinet%20%26%20Profibus/FlashLED.py): This script is similar to the previous one. First you will need to run the *Discovery.py* in order to get a mac address of any Profinet device. This programm is optimized to blick the status led on a S7-1500 PLC. One you got the mac address, replace it on the hex stream, as well as the origin mac address.
- [PacketReplay-Completo.py](https://github.com/miguelob/ICS-Hacking/blob/main/Profinet%20%26%20Profibus/PacketReplay-Complete.py): This script is a complete python programm to scann, craft and send profinet packets. You must edit the full code in order to be prepeared to run it.

## Snap7 (S7Comm & S7Comm Plus)
![Snap7 logo](https://github.com/miguelob/ICS-Hacking/blob/main/images/s7.png)

In this resopitory you will find attacks, documents, and pcaps of both S7Comm protocol and its bigger brother S7Comm+:
- [S7Comm](https://github.com/miguelob/ICS-Hacking/tree/main/S7comm): In this folder you will find multiple Python Scripts that let you read and write data to internal variables of the PLC CPU. On the [Test Scripts folder](https://github.com/miguelob/ICS-Hacking/tree/main/S7comm/Test%20Scripts) you will find multiple test scripts in which you can base your own developed code. You will find example codes of writing and reading from internal variables and interal databases. 

  As an example for developing your own hacking interface, you can see the [Read&Write.py](https://github.com/miguelob/ICS-Hacking/blob/main/S7comm/Read%26Write.py) which adds iteraction with the user by cli. For a realistic TIA PORTAL project, i used the [CyberLabProject.py](https://github.com/miguelob/ICS-Hacking/blob/main/S7comm/CyberLabProject.py) script.

- [S7Comm-plus](https://github.com/miguelob/ICS-Hacking/tree/main/S7comm-plus): For these protocol you will find two scripts. The *pr.py* is an example of a simple packet replay and the *denial.py* is an example of a request overflow that denies the PLC for few seconds. If this last script is continiously being executed, the PLC would be completely denied for that perior of time.

For the attacks of both protocols, you would need to install Snap7 for python with this command:

`$ pip install python-snap7`

In  addition, you will also need to install the binaries of the protocol into your computer.

**Windows install**

You just need to install move into your PC the *Snap7.dll* from [Snap7 download](https://sourceforge.net/projects/snap7/)

**MacOS install**

You will need to have Brew cli previously install and then install Snap7 with Brew:

`$ brew install snap7`


## SCADA
![SCADA example](https://github.com/miguelob/ICS-Hacking/blob/main/images/SCADA.png)

In this section you will find a Python programm with a UI simulating a very simple SCADA system. This UI only have text showing the state of diferent variables and buttons to change its state. The UI is simple but it keeps it all real when it comes to a cyber attack. This SCADA example implements two protocols to make it more realistic. It works at the same time with ModBus and Snap7, with real time reading and writting. In order to attack this SCADA, please reffer to the attacks of each protocol.

For running this app you will need to install diferent Python modules (or create a requirements.txt with the following packages):

```
$ pip install python-snap7
$ pip install pickle-mixin
$ pip install python-tk
$ pip install pymodbus
```
## Package
This packages contain all the code and funtionality from the repository on a terminal based GUI.
You can find the realeases on the [Releases website](https://github.com/miguelob/ICS-Hacking/releases). It is recommended to download the latest version. Inside this package you will find the requirements.txt that need to be installed before running the main.py, with the following command:

`pip install -r requirements.txt`

After installing the requirements, you can directly run the main.py and the terminal GUI will guide you throught the different functionalities.


## Contact
- **Email 1**: moleoblanco@hawk.iit.edu
- **Email 2**: miguel.oleo@alu.comillas.edu
- **Linkedin**: https://www.linkedin.com/in/miguel-oleo-blanco/
- **YouTube**: https://www.youtube.com/c/Migueloleoblanco
