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

#print of the internal DB in hex stream
print(db)
#print("text: ",binascii.unhexlify(db))
#Decompose of the DB from the print avobe and from the offsets of TIA PORTAL
product_name = bool(db[0])
print("Button: ", product_name)

product_value = bool(db[1])
print(f'LED: {product_value}')

plc.db_write(DB_NUMBER, START_ADDRESS, b'\x00')