from numpy import character
from S7comm import mainS7comm

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
    intro()
    while(True):
        menu()
        option = ''
        try:
            option = int(input('Enter your choice: '))
        except:
            print('Wrong input. Please enter a number ...')
        #Check what choice was entered and act accordingly
        if option == 1:
            while(True):
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
                elif option == 5:
                    print('Thanks message before exiting')
                    exit()
                else:
                    print('Invalid option. Please enter a number between 1 and 4.\n\n')

        elif option == 2:
            S7Comm-plus()
        elif option == 3:
            SCADA()
        elif option == 4:
            P&P()
        elif option == 5:
            print('Thanks message before exiting')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 5.\n\n')

