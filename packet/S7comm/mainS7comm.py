import snap7

def labProject(IP, RACK, SLOT):
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