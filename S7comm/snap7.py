import snap7
from snap7 import util

from db_layouts import rc_if_db_1_layout
from db_layouts import tank_rc_if_db_layout

IP = "192.168.56.15"
RACK = 0
SLOT = 1

DB_NUMBER = 100
START_ADDRESS = 0
SIZE = 259

plc = snap7.client.Client()
plc.connect(IP,RACK,SLOT)

plc_info = plc.get_cpu_info()
print(f'Module type: {plc_info.ModuleTypeName}')

state = plc.get_cpu_state()
print(f'State: {state}')

db = plc.db_read(DB_NUMBER, START_ADDRESS, SIZE)

#print de la db en formato hexadecimal
print(db)

#Descomposicion de la db, se hace a partir del print y los offset de tia
product_name = db[1:256].decode('UTF-8').strip('\x00')
print("Product name: ", product_name)

product_value = int.from_bytes(db[256:258], byteorder='big')
print(f'Product value: {product_value}')

product_status = bool(db[258])
print(f'Product status: {product_status}')

#plc.db_write(DB_NUMBER, START_ADDRESS+255, b'03')