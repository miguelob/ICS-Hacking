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
           mainS7comm.labProject('192.168.1.10',0,1)
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
            print('Invalid option. Please enter a number between 1 and 4.\n\n')

