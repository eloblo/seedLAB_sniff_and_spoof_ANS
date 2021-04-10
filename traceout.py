from scapy.all import *

def trace(i):    #create an icmp message with i ttl
    a = IP()
    a.dst = '8.8.8.8'
    a.ttl = i
    prot = ICMP()
    p = a/prot
    send(p)

def measure():   #create and messages with i ttl
    i = 1    
    while i < 64:  #max ttl 
        trace(i)
        #check if recived a reply from the destination ip
        pkt = sniff(filter = 'src 8.8.8.8 and icmp[icmptype] == icmp-echoreply', timeout = 1)
        if len(pkt) != 0:
            print("distance ", i)
            return
        i += 1    #else send again with longer ttl
        
measure()
