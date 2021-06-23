import snap7
from snap7 import util
import binascii

from db_layouts import rc_if_db_1_layout
from db_layouts import tank_rc_if_db_layout

IP = "192.168.56.15"
RACK = 0
SLOT = 1

DB_NUMBER = 1
START_ADDRESS = 0
SIZE = 2

plc = snap7.client.Client()
plc.connect(IP,RACK,SLOT)

plc_info = plc.get_cpu_info()
print(f'Module type: {plc_info.ModuleTypeName}')

state = plc.get_cpu_state()
print(f'State: {state}')

db = plc.db_read(DB_NUMBER, START_ADDRESS, SIZE)

#print de la db en formato hexadecimal
print(db)
#print("texto: ",binascii.unhexlify(db))
#Descomposicion de la db, se hace a partir del print y los offset de tia
product_name = bool(db[0])
print("Boton: ", product_name)

product_value = bool(db[1])
print(f'luz: {product_value}')

plc.db_write(DB_NUMBER, START_ADDRESS, b'\x00')