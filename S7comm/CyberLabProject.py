import snap7

#This is an example for my own project reading my project's variables
def Lectura():
    datos=[]
    QB = plc.ab_read(2,7)
    print("================================================")
    print("poGiro: ", snap7.util.get_bool(QB,0,6))
    print("poSentido: ", snap7.util.get_bool(QB,0,7))
    print("mClockPermiso: ", snap7.util.get_bool(QB,0,2))
    print("================================================")

def Menu():
    print("Introduzca la opcion que quiere ejecutar:")
    print("1. Modificar poGiro.")
    print("2. Modificar poSentido.")
    print("3. SALIR")
    return input("Introduzca la opción: ")

#IP = '192.168.1.10' #IP del PLC que contiene el NetToPLCSim
#Para el laboratorio sería el siguiente
IP = '192.168.56.15'
#Para s7-1200 y s7-1500 siempre rack = 0 y slot = 1
RACK = 0
SLOT = 1    

plc = snap7.client.Client() #Creamos un cliente
plc.connect(IP,RACK,SLOT)   #Nos conectamos

QB = plc.ab_read(2,7)   #Parto de los valores del PLC

exit = True
while exit:
    Lectura()
    opc = Menu()
    if opc == '1':
        #Invierte valor de poGiro
        snap7.util.set_bool(QB,0,6,not snap7.util.get_bool(QB,0,6))
        plc.ab_write(2,QB)
    elif opc == '2':
        #Invierte el valor de poSentido
        snap7.util.set_bool(QB,0,7,not snap7.util.get_bool(QB,0,7))
        plc.ab_write(2,QB)
    elif opc == '3':
        exit = False
    else:
        print("Por favor, introduzca un valor del 1 al 4.")
