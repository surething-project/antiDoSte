from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr
from scapy.all import *
import sys
import random
from Scapy_TcpSession import TcpSession
import time

dst = sys.argv[1]


while(1):

    rumNum = random.randint(0, 1000000000)
    strRumNum = str(rumNum)
    while len(strRumNum) < 10:
        strRumNum = "0" + strRumNum

    RESP  = "GET / HTTP/1.1\r\n"
    RESP += "Server: %s\r\n" % sys.argv[1]
    RESP += "Content-Length: 34\r\n"
    RESP += "\r\n"
    RESP += "Get Synchronization and %s" % strRumNum

    sess = TcpSession((dst,443))
    sess.connect()
    sess.send(RESP)

    time.sleep(1)
