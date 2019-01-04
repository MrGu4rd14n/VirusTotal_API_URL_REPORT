#!/usr/share/env python3
import requests
import time
import json
import os
from pprint import pprint
import optparse
import subprocess
import colorama
from colorama import Fore, Back
colorama.init(autoreset=True)
clear = lambda: subprocess.call('cls||clear', shell=True)
clear()
def ascii_art():
    print(Fore.RED + '''
     _              _               _   
 ___| |_ __ _ _   _| |__   ___  ___| |_ 
/ __| __/ _` | | | | '_ \ / _ \/ __| __|
\__ \ || (_| | |_| | | | | (_) \__ \ |_ 
|___/\__\__,_|\__, |_| |_|\___/|___/\__|
              |___/                     

 ___  ___ __ _ _ __  _ __   ___ _ __    
/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|   
\__ \ (_| (_| | | | | | | |  __/ |      
|___/\___\__,_|_| |_|_| |_|\___|_|     

         Made with love by 0xCyb3r                                
''')


ascii_art()


# Function for arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--fichier", dest="fichier", help="Fichier [.txt] contenant les adresses IP")
    (options, arguments) = parser.parse_args()

    if not options.fichier:
        parser.error("[-] Erreur veuillez spécificer un fichier. Utilisez --help pour plus d'infos.")
    if ".txt" not in options.fichier:
        parser.error("[-] Erreur veuillez choisir un fichier texte. Utilisez --help pour plus d'infos.")
    return options


# Function for json data
def detections(url, params):
    json_data = requests.get(url, params=params).json()
    try:
        json_url = json_data['url']
        json_positives = json_data['positives']
        json_total = json_data['total']
        json_link = json_data['permalink']
    except:
        json_positives = -1
        json_url = json_data['url']
        json_date = json_data['scan_date']
        json_msg = json_data['verbose_msg']
        json_link = json_data['permalink']
    if json_positives > 0:
        detection_result = "__________________________________\n\n" + Fore.YELLOW + "Site:" + Fore.RESET + " {0}\n".format(json_url) + Fore.YELLOW + "Détections:" + Fore.RED + " {0}/{1} \n".format(json_positives, json_total) + Fore.YELLOW + "Lien VT:" + Fore.RESET + " {0}".format(json_link) + "\n__________________________________"
        file = open("ip_malveillantes.txt", "a+")
        file.write(
            "\n__________________________________\n\nSite: %s \nDétections: %s/%s \nLien VT: %s\n__________________________________" % (
            json_url, json_positives, json_total, json_link))
    elif json_positives == 0:
        detection_result = "__________________________________\n\n" + Fore.YELLOW + "Site:" + Fore.RESET + " {0}\n".format(json_url) + Fore.YELLOW + "Détections:" + Fore.GREEN + " {0}/{1} \n".format(json_positives, json_total) + Fore.YELLOW + "Lien VT:" + Fore.RESET + " {0}".format(json_link) + "\n__________________________________"
    else:
        detection_result = "__________________________________\n\n" + Fore.YELLOW + "Site:" + Fore.RESET + " {0}\n".format(json_url) + Fore.YELLOW + "Date:" + Fore.RESET + "{0}".format(json_date) + Fore.YELLOW + "\nMessage:" + Fore.RESET + " {0}".format(json_msg) + Fore.YELLOW + "\nLien VT:" + Fore.RESET + "{0}".format(json_link) + "\n__________________________________"
    return detection_result


# Reporting urls to VT
options = get_arguments()
try:
    os.remove("ip_malveillantes.txt")
except:
    print("")
print("Lancement du premier scan...")
with open(options.fichier) as f:
    for line in f:
        url_to_scan = line
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': '5f422fc028fb55e8c4ee1c3ddc52096eff492b36514ede97969284126279aad2', 'resource': url_to_scan, 'scan': 1}  # ApiKey à mettre ici
        print(detections(url, params))
        time.sleep(15.0)

clear = lambda: subprocess.call('cls||clear', shell=True)
clear()

# Detections results from VT
ascii_art()
try:
    os.remove("ip_malveillantes.txt")
except:
    print("")
print("Premier scan terminé... Lancement du deuxième scan")
with open(options.fichier) as f:
    for line in f:
        url_to_scan = line
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': '5f422fc028fb55e8c4ee1c3ddc52096eff492b36514ede97969284126279aad2', 'resource': url_to_scan, 'scan': 1}  # ApiKey à mettre ici
        print(detections(url, params))
        time.sleep(15.0)
