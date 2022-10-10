import snap7, socket, pickle, struct,time, threading
from tkinter import *
from pymodbus.client.sync import ModbusTcpClient

def SCADA(IP,RACK,SLOT):
    plc = snap7.client.Client() #Creates a client
    plc.connect(IP,RACK,SLOT)   #Connects to the client
    QB = plc.ab_read(2,7)

    client = ModbusTcpClient(IP)

    g = GUI(plc, client)
    client.close()

def GUI(plc, client):
    Window = Tk()
    Window.withdraw()
    scada = Toplevel()

    scada.title("Sistema SCADA lab ciberseguridad")
    scada.resizable(width=False, height=False)
    scada.config(width=1000, height=700)

    valorGiro = StringVar()
    valorSentido = StringVar()
    valorMod0 = StringVar()
    valorMod1 = StringVar()

    labelGiro = Label(scada,textvariable=valorGiro)
    labelSentido = Label(scada,textvariable=valorSentido)
    labelMod0 = Label(scada,textvariable=valorMod0)
    labelMod1 = Label(scada,textvariable=valorMod1)

    labelGiro.place(relheight=0.15,relx=0.1,rely=0.2)
    labelSentido.place(relheight=0.15,relx=0.25,rely=0.2)
    labelMod0.place(relheight=0.15,relx=0.45,rely=0.2)
    labelMod1.place(relheight=0.15,relx=0.65,rely=0.2)

    btnGiro = Button(scada,text="Giro",font="Helvetica 14 bold",command= lambda:botones('1'))
    btnSentido = Button(scada,text="Sentido",font="Helvetica 14 bold",command= lambda:botones('2'))
    btnMod0 = Button(scada,text="Mod0",font="Helvetica 14 bold",command= lambda:botones('3'))
    btnMod1 = Button(scada,text="Mod1",font="Helvetica 14 bold",command= lambda:botones('4'))

    btnGiro.place(relx=0.2,rely=0.55)
    btnSentido.place(relx=0.4,rely=0.55)
    btnMod0.place(relx=0.6,rely=0.55)
    btnMod1.place(relx=0.8,rely=0.55)
    
    lectura()
    Window.mainloop()

    def botones(self,opc):
        if opc == '1':
            #Inverts the value of the variable poGiro
            snap7.util.set_bool(QB,0,6,not snap7.util.get_bool(QB,0,6))
            plc.ab_write(2,QB)
        elif opc == '2':
            #Inverts the value of the variable poSentido
            snap7.util.set_bool(QB,0,7,not snap7.util.get_bool(QB,0,7))
            plc.ab_write(2,QB)
        elif opc == '3':
            valor = 1
            result = client.read_coils(0,2)
            if result.bits[0]:
                valor = 0
            client.write_coil(0, valor)
        elif opc == '4':
            valor = 1
            result = client.read_coils(0,2)
            if result.bits[1]:
                valor = 0
            client.write_coil(1, valor)

    def lectura(self):
        rcv = threading.Thread(target=recibir)
        rcv.setDaemon(True)
        rcv.start()


    def recibir(self):
        while True:
            QB = plc.ab_read(2,7)
            result = client.read_coils(0,2)
            #print(QB)
            valorGiro.set("Giro: "+str(snap7.util.get_bool(QB,0,6)))
            valorSentido.set("Sentido: "+str(snap7.util.get_bool(QB,0,7)))
            valorMod0.set("Mod0: "+str(result.bits[0]))
            valorMod1.set("Mod1: "+str(result.bits[1]))
            time.sleep(0.5)