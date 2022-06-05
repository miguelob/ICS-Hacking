import snap7, socket, pickle, struct,time, threading
from tkinter import *
from pymodbus.client.sync import ModbusTcpClient


class GUI(plc, client):
    def __init__(self, plc, client):
        self.Window = Tk()
        self.Window.withdraw()
        self.scada = Toplevel()

        self.scada.title("Sistema SCADA lab ciberseguridad")
        self.scada.resizable(width=False, height=False)
        self.scada.config(width=1000, height=700)

        self.valorGiro = StringVar()
        self.valorSentido = StringVar()
        self.valorMod0 = StringVar()
        self.valorMod1 = StringVar()

        self.labelGiro = Label(self.scada,textvariable=self.valorGiro)
        self.labelSentido = Label(self.scada,textvariable=self.valorSentido)
        self.labelMod0 = Label(self.scada,textvariable=self.valorMod0)
        self.labelMod1 = Label(self.scada,textvariable=self.valorMod1)

        self.labelGiro.place(relheight=0.15,relx=0.1,rely=0.2)
        self.labelSentido.place(relheight=0.15,relx=0.25,rely=0.2)
        self.labelMod0.place(relheight=0.15,relx=0.45,rely=0.2)
        self.labelMod1.place(relheight=0.15,relx=0.65,rely=0.2)

        self.btnGiro = Button(self.scada,text="Giro",font="Helvetica 14 bold",command= lambda:self.botones('1'))
        self.btnSentido = Button(self.scada,text="Sentido",font="Helvetica 14 bold",command= lambda:self.botones('2'))
        self.btnMod0 = Button(self.scada,text="Mod0",font="Helvetica 14 bold",command= lambda:self.botones('3'))
        self.btnMod1 = Button(self.scada,text="Mod1",font="Helvetica 14 bold",command= lambda:self.botones('4'))

        self.btnGiro.place(relx=0.2,rely=0.55)
        self.btnSentido.place(relx=0.4,rely=0.55)
        self.btnMod0.place(relx=0.6,rely=0.55)
        self.btnMod1.place(relx=0.8,rely=0.55)
        
        self.lectura()
        self.Window.mainloop()

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
        rcv = threading.Thread(target=self.recibir)
        rcv.setDaemon(True)
        rcv.start()


    def recibir(self):
        while True:
            QB = plc.ab_read(2,7)
            result = client.read_coils(0,2)
            #print(QB)
            self.valorGiro.set("Giro: "+str(snap7.util.get_bool(QB,0,6)))
            self.valorSentido.set("Sentido: "+str(snap7.util.get_bool(QB,0,7)))
            self.valorMod0.set("Mod0: "+str(result.bits[0]))
            self.valorMod1.set("Mod1: "+str(result.bits[1]))
            time.sleep(0.5)

IP = '192.168.1.10' #Ip of the PLC inside NetToPLCSim
#For testing on a real PLC use your own PLC ip below
#IP = '192.168.56.15' --> My PLC IP
#For s7-1200 and s7-1500 always rack = 0 & slot = 1
RACK = 0
SLOT = 1    

plc = snap7.client.Client() #Creates a client
plc.connect(IP,RACK,SLOT)   #Connects to the client
QB = plc.ab_read(2,7)

client = ModbusTcpClient(IP)
#client.write_coil(0, 0)
client.close()

g = GUI(plc, client)
