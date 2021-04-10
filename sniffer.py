from scapy.all import *

print("sniffing:...")

def print_pkt(pkt):
    pkt.show()
    
pkt = sniff(iface = 'br-0338c03034a9', filter = 'icmp', prn = print_pkt)
#pkt = sniff(iface = 'br-0338c03034a9', filter = 'tcp and dst port 23', prn = print_pkt)
#pkt = sniff(iface = 'br-0338c03034a9', filter = 'src net 128.230.0.0/16 or dst net 128.230.0.0/16', prn = print_pkt)
