import snap7
from scapy.all import *
import binascii
import socket

def labProject(IP, RACK = 0, SLOT = 1):
    def Lectura():
        datos=[]
        QB = plc.ab_read(2,7)
        print("================================================")
        print("poGiro: ", snap7.util.get_bool(QB,0,6))
        print("poSentido: ", snap7.util.get_bool(QB,0,7))
        print("mClockPermiso: ", snap7.util.get_bool(QB,0,2))
        print("================================================")

    def Menu():
        print("OPTIONS:")
        print("1. Change poGiro.")
        print("2. Change poSentido.")
        print("3. EXIT")
        return input("Type in an option: ")

    #RACK = 0
    #SLOT = 1    

    plc = snap7.client.Client() #Creamos un cliente
    plc.connect(IP,RACK,SLOT)   #Nos conectamos

    QB = plc.ab_read(2,7)   #Parto de los valores del PLC

    exit = True
    while exit:
        Lectura()
        opc = Menu()
        if opc == '1':
            snap7.util.set_bool(QB,0,6,not snap7.util.get_bool(QB,0,6))
            plc.ab_write(2,QB)
        elif opc == '2':
            snap7.util.set_bool(QB,0,7,not snap7.util.get_bool(QB,0,7))
            plc.ab_write(2,QB)
        elif opc == '3':
            exit = False
        else:
            print("Please, type a value from 1 to 4.")
def packetReplay(IP,PKT):
    hex = binascii.unhexlify(str(PKT))
    pkt = Raw(hex)
    print(hexdump(pkt))

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    server_address = (IP, 102)
    sock.connect(server_address)
    sock.sendall(bytes(pkt)) 

def QReadWrite(IP, RACK = 0, SLOT = 1):
    def read():
        datos=[]
        QB = plc.ab_read(0,5)
        print("================================================")
        print("Value Q0.0: ", snap7.util.get_bool(QB,0,0))
        print("Value Q0.1: ", snap7.util.get_bool(QB,0,1))
        print("Value Q0.2: ", snap7.util.get_bool(QB,0,2))
        print("Value Q0.3: ", snap7.util.get_bool(QB,0,3))
        print("Value Q0.4: ", snap7.util.get_bool(QB,0,4))
        print("Value Q0.5: ", snap7.util.get_bool(QB,0,5))
        print("================================================")

    #IP = '192.168.1.10' #IP of the PLC that is connected to NetToPLCSim
    #For real testing with PLCs
    #IP = '192.168.56.15' Example ip of my PLC
    #For s7-1200 and s7-1500 always rack = 0 and slot = 1
    #RACK = 0
    #SLOT = 1    

    plc = snap7.client.Client() #Creates a client
    plc.connect(IP,RACK,SLOT)   #Connect to the client

    QB = plc.ab_read(0,5)   #Read the initial values from the PLC

    exit = True
    while exit:
        read()
        
        inputKeyboard = input("¿Would you like to continue? Press n/N to exit or any other key to continue: ")
        if(inputKeyboard.upper() == "N"):
            exit = False
        else:
            try:
                num = 7
                while num > 5 or num < 0:
                    num = int(input("Type the data address that you want to write into (0-5): "))
                value = 2
                write = False
                while ((value != 0) and (value != 1)):
                    value = int(input("Type 0 to change it to False or 1 for True: "))      
                if value == 1:
                    write = True
                snap7.util.set_bool(QB,0,num,write)    #Escribimos un True/False en la posición indicada
                plc.ab_write(0,QB)
                print("Value inserted successfully.")
            except:
                print("Type in a number please.")