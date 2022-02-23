from numpy import character
from S7comm import mainS7comm
from S7comm-plus import pr
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
            S7Comm-plus()
        elif option == 3:
            SCADA()
        elif option == 4:
            P&P()
        elif option == 5:
            print('Thanks for using the package. For more info, refer to the GitHub Repo.')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 5.\n\n')

