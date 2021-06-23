import snap7


def Lectura():
    datos=[]
    QB = plc.ab_read(0,5)
    print("================================================")
    print("Valor Q0.0: ", snap7.util.get_bool(QB,0,0))
    print("Valor Q0.1: ", snap7.util.get_bool(QB,0,1))
    print("Valor Q0.2: ", snap7.util.get_bool(QB,0,2))
    print("Valor Q0.3: ", snap7.util.get_bool(QB,0,3))
    print("Valor Q0.4: ", snap7.util.get_bool(QB,0,4))
    print("Valor Q0.5: ", snap7.util.get_bool(QB,0,5))
    print("================================================")

IP = '192.168.1.10' #IP del PLC que contiene el NetToPLCSim
#Para el laboratorio sería el siguiente
#IP = '192.168.56.15'
#Para s7-1200 y s7-1500 siempre rack = 0 y slot = 1
RACK = 0
SLOT = 1    

plc = snap7.client.Client() #Creamos un cliente
plc.connect(IP,RACK,SLOT)   #Nos conectamos

QB = plc.ab_read(0,5)   #Parto de los valores del PLC

exit = True
while exit:
    Lectura()
    
    entrada = input("¿Desea Continuar? Pulse n/N para salir o cualquier otra para continuar: ")
    if(entrada.upper() == "N"):
        exit = False
    else:
        try:
            num = 7
            while num > 5 or num < 0:
                num = int(input("Introduzca la dirección donde quiere escribir (0-5): "))
            valor = 2
            escritura = False
            while ((valor != 0) and (valor != 1)):
                valor = int(input("Introduzca 0 si quiere ponerlo a false o 1 para true: "))      
            if valor == 1:
                escritura = True
            snap7.util.set_bool(QB,0,num,escritura)    #Escribimos un True/False en la posición indicada
            plc.ab_write(0,QB)
            print("VALOR INTRODUCIDO CORRECTAMENTE.")
        except:
            print("introduzca un número por favor.")
