from scapy.all import *

def spf():
    a = IP()                #ip object
    a.dst = '8.8.8.8'       #destination ip
    a.src = '10.10.5.5'     #spoofed ip
    prot = ICMP()           
    p = a/prot              #set the message to icmp echo
    send(p)
    
spf()
