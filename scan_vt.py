#!/usr/share/env python
import requests
import time
import json
import os
from pprint import pprint
import optparse
#Fonction des arguments
try:
    os.system("clear")
except:
    os.system("cls")
def ascii_art():
    print('''\033[91m 
     _              _               _   
 ___| |_ __ _ _   _| |__   ___  ___| |_ 
/ __| __/ _` | | | | '_ \ / _ \/ __| __|
\__ \ || (_| | |_| | | | | (_) \__ \ |_ 
|___/\__\__,_|\__, |_| |_|\___/|___/\__|
              |___/                     
                                        
 ___  ___ __ _ _ __  _ __   ___ _ __    
/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|   
\__ \ (_| (_| | | | | | | |  __/ |      
|___/\___\__,_|_| |_|_| |_|\___|_|      \033[00m
               
         Made with love by 0xCyb3r                                
''')
ascii_art()
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--fichier", dest="fichier", help="Fichier [.txt] contenant les adresses IP")
    (options, arguments) = parser.parse_args()

    if not options.fichier:
        parser.error("[-] Erreur veuillez spécificer un fichier. Utilisez --help pour plus d'infos.")
    if ".txt" not in options.fichier:
        parser.error("[-] Erreur veuillez choisir un fichier texte. Utilisez --help pour plus d'infos.")
    return options
#Fonction des données
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
        detection_result = "__________________________________\n\n\033[33mSite:\033[00m %s \n\033[33mDétections:\033[00m \033[91m %s/%s \033[00m\n\033[33mLien VT:\033[00m %s\n__________________________________" %(json_url, json_positives, json_total, json_link)
        file = open("ip_malveillantes.txt","a+")
        file.write("\n__________________________________\n\nSite: %s \nDétections: %s/%s \nLien VT: %s\n__________________________________" %(json_url, json_positives, json_total, json_link))
    elif json_positives == 0:
        detection_result = "__________________________________\n\n\033[33mSite:\033[00m %s \n\033[33mDétections:\033[00m \033[92m %s/%s \033[00m\n\033[33mLien VT:\033[00m %s\n__________________________________" %(json_url, json_positives, json_total, json_link)
    else:
        detection_result = "__________________________________\n\n\033[33mSite:\033[00m %s \n\033[33mDate:\033[00m %s \n\033[33mMessage:\033[00m %s \n\033[33mLien VT:\033[00m %s\n__________________________________" %(json_url, json_date, json_msg, json_link)
    return detection_result

#Lancement du script
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
        params = {'apikey': 'a66e2e5116b8114b1ecff90a217b6744d1006b53ffab330b6b7f1c4c6f0c4fd7', 'resource': url_to_scan, 'scan': 1} #ApiKey à mettre ici
        print(detections(url, params))
        time.sleep(15.0)
try:
    os.system("clear")
except:
    os.system("cls")

#Résultat des analyses
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
        params = {'apikey': 'a66e2e5116b8114b1ecff90a217b6744d1006b53ffab330b6b7f1c4c6f0c4fd7', 'resource': url_to_scan, 'scan': 1} #ApiKey à mettre ici
        print(detections(url, params))
        time.sleep(15.0)

