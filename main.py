
import netifaces
import nmap #pip3 install python-nmap
import ipaddress 
import subprocess
import string
import random
import re
import socket
import os
from random import randint
from time import sleep
import argparse
import wifi



#Variable modifiable
NMAP_OPT = ['-n -sP','-sn -PS80,21,53','-sn -PA21,22,80'] #-n pas de résolution DNS / -sP juste des ping ; TCP SYN ; TCP ACK #https://hub.packtpub.com/discovering-network-hosts-with-tcp-syn-and-tcp-ack-ping-scans-in-nmaptutorial/
INTERFACE_WIFI = "wlan0"
WIFI_NAME = None #"SFR_3508"
WIFI_PASSWORD = None 
CHANGE_MAC = False

#Génère une adresse MAC aléatoire   
def get_random_mac_address():
    uppercased_hexdigits = ''.join(set(string.hexdigits.upper()))
    mac = ""
    for i in range(6):
        for j in range(2):
            if i == 0:
                mac += random.choice("02468ACE")
            else:
                mac += random.choice(uppercased_hexdigits)
        mac += ":"
    return mac.strip(":")

#Récupère l'adresse MAC actuelle
def get_current_mac_address():
    output = subprocess.check_output(f"ifconfig {current_interface}", shell=True).decode()
    return re.search("ether (.+) ", output).group().split()[1].strip()

#Change l'adresse MAC
def change_mac_address():
    new_mac = get_random_mac_address()
    subprocess.check_output(f"ifconfig {current_interface} down", shell=True)
    subprocess.check_output(f"ifconfig {current_interface} hw ether {new_mac}", shell=True)
    subprocess.check_output(f"ifconfig {current_interface} up", shell=True)

#Écrit les logs dans un fichier / un rapport   
def write_log(text):
    print(text)

#Récupère la liste des machines opérationnelles sur le réseau
def get_all_hosts(host,host_list):
    new_host_list = []
    option_dict = {key: [] for key in NMAP_OPT}
    
    for i in range(0,pow(256,level+1)):
        if str(host+i) not in host_list:
            for option in NMAP_OPT:
                nm.scan(hosts=str(host+i),arguments=option)
                sleep(randint(1,9)/100)
                if CHANGE_MAC:
                    change_mac_address()
                print(host+i)
                for h in nm.all_hosts():
                    option_dict[option].append(h)
                    host_list.append(h)
                    new_host_list.append(h)

            if str(host+i) in host_list:
                for opt in NMAP_OPT:
                    if str(host+i) not in option_dict[opt]:
                        write_log("Cette ip est protéger des scan "+opt+": "+str(host+i))

    return new_host_list,host_list

#Scanne les CVE
def scan_cve():
    host_list = []
    for level in range(0,2):
        host= ipaddress.IPv4Address(re.findall('(^([0-9]*.){'+str(3-level)+'})',local_ip)[0][0][:-1]+('.0'*(level+1)))
        new_host_list,host_list = get_all_hosts(host,host_list)
        write_log("List des hosts au level "+str(level)+" : "+str(new_host_list))
        #Attaque ici
       
#Scanne les accès Wifi disponibles
def wifi_scanner():
    wifilist = []
    cells = wifi.Cell.all(INTERFACE_WIFI)
    for cell in cells:
        wifilist.append(cell)
    return wifilist

#Recherche un accès Wifi
def get_wifi(cells):
    for cell in cells:
        if cell.ssid == WIFI_NAME:
            return cell
    return None

def Find_Saved_wifi(ssid):
    cell = wifi.Scheme.find('wlan0', ssid)

    if cell:
        return cell

    return False

def Add_wifi(cell, password=None):
    if not cell:
        return False

    scheme = wifi.Scheme.for_cell('wlan0', cell.ssid, cell, password)
    scheme.save()
    return scheme


def Delete_wifi(ssid):
    cell = Find_Saved_wifi(ssid)
    if cell:
        cell.delete()

def wifi_connect(cell,ssid, password=None):
    if cell is not None and ssid is not None:
        savedcell = Find_Saved_wifi(cell.ssid)
        if savedcell:
            savedcell.activate()
            return cell

        scheme = Add_wifi(cell, password)
        try:
            print(INTERFACE_WIFI,cell.ssid, cell, password)
            scheme.activate()
        except wifi.exceptions.ConnectionError:
            Delete_wifi(ssid)
            return False
        return cell
    return False

#Se connecter à un réseau connu
def wifi_known_connect(iprouter, ssid, password=None):
    
    #if
    
    f = open("/etc/wpa_supplicant/wpa_supplicant.conf")
    f.write("country=FR")
    f.write("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev")
    f.write("update_config=1")
    f.write("network={")
    f.write("    ssid='"+ssid+"'")
    f.write("    scan_ssid=1")
    f.write("    psk='"+password+"'")
    f.write("    key_mgmt=WPA-PSK")
    f.write("}")
    f.close()
    
    f = open("/etc/dhcpcd.conf", "a")
    f.write("interface wlan0")
    f.write("static ip_address=+iprouter/24") #Déterminer IP (À FAIRE)
    f.write("static routers="+iprouter)
    f.write("static domain_name_servers=8.8.8.8")
    f.close()
    
    os.system("sudo reboot")


#Programme principal
def prog():

    #Initialisation des variables
    current_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    nm = nmap.PortScanner()
    local_ip = socket.gethostbyname(socket.gethostname())
    local_ip = "192.168.1.0"

    #Si connecté en ethernet
    if "eth0" in current_interface:
        write_log("l'interface réseau est en ethernet : "+current_interface)
        write_log("l'ip actuel et : "+local_ip)
        host_list = attack_ethernet(host_list)

    #Wifi
    list_wifi = wifi_scanner()
    cell = wifi_connect(get_wifi(list_wifi),WIFI_NAME,WIFI_PASSWORD)
    if cell != False:
        scan_cve()
        list_wifi.remove(WIFI_NAME)

    for wifi in list_wifi:
        cell = brutforce_wifi(wifi)
        if cell != False:
            scan_cve()
    


if __name__ == '__main__':
    #Tourne en boucle en actualisant la liste des CVE si connecté
    while True:
        prog()
        if os.system("ping -c 1 google.com") == 0:
            #Actualise le fichier .json des CVE

