#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
import hashlib
import requests
import json
import pygeoip
import time
import os
from virus_total_apis import PublicApi as VirusTotalPublicApi

rawdata = pygeoip.GeoIP('GeoLiteCity/GeoLiteCity.dat')
API_KEY = '07a3ca0b4cde90d586d3bdb65ddb282047a4d9cb8568290321eee9b9fd7a2fa0'
vt = VirusTotalPublicApi(API_KEY)

md5_ok = []

def ipquery(ip):
    data = rawdata.record_by_name(ip)
    country = data['country_name']
    city = data['city']
    result = str(str(city)+', ' +str(country))
    return(result)

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

FichList = [ f for f in os.listdir('.') if os.path.isfile(os.path.join('.',f)) ]
for elements in FichList:

    if elements == "HoneyBot.py":
        pass
    else:

        # hash = md5(elements)
        hash = "1cb3d083255c29501c6300db54164aeb"

        if hash in md5_ok:
            print("[-] Fichier déja scanné.")
            os.system('rm ' + elements)
        else :

            print("[+] Nouveau fichier : " + str(hash))

            response = vt.get_file_report(hash)
            re = str(json.dumps(response, sort_keys=False, indent=4))

            if "The requested resource is not among the finished, queued or pending scans" in str(re):
                print("[+] new sample found : " + str(elements))
                pass
            else:

                total = re.split('"total": ')[1][0:2]
                positive = re.split('"positives": ')[1][0:2]
                hash_md5 = hash
                hash_sha = re.split('"sha256": "')[1].replace('"', '')[0:64]
                score = str(positive) + "/" + str(total)
                r = requests.get('http://209.97.129.92/api/feed/?api_key=5e46d9260f4a422082b4c8472688120c&channel=dionaea.capture')
                infos_brute = r.text
                print(infos_brute)
                info = infos_brute.find(hash)
                add = infos_brute[info + 33 : info + 70].replace('"saddr": "','').replace('"','').replace(" ","").replace(",",'').replace("\n","")
                port = infos_brute[info - 25 : info - 8].replace('"',"").replace(",","").replace("\n","")
                capture_date = infos_brute[info + 259 : info + 310].replace('time": "',"").replace('"',"").replace(',','').replace("\n",'')
                try :
                    location = ipquery(add)
                    commentaire = " === Malware sample collect by my Honeypot === \n Capture date : " + capture_date + "\n" + "Md5 : " + hash_md5 + "\n" + "Sha256 : " + hash_sha + "\n" + "Score : " + positive + "/" + total + "\n" + "Port : " + port + "\n" + "IP source : " + add + "\n" + "Location : " + location
                    location_ok = True
                except:
                    commentaire = " === Malware sample collect by my Honeypot === \n Capture date : " + capture_date + "\n" + "Md5 : " + hash_md5 + "\n" + "Sha256 : " + hash_sha + "\n" + "Score : " + positive + "/" + total + "\n" + "Port : " + port + "\n" + "IP source : " + add + "\n" + "Location : " + "-"
                    location_ok = False
                print("Malware sample collect by my Honeypot = ")
                print("Capture date : " + capture_date)
                print("Md5 : " + hash_md5)
                print("Sha256 : " + hash_sha)
                print("Score : " + positive + "/" + total)
                print("Port : " + port)
                print("IP source : " + add)
                if location_ok == True:
                    print("Location : " + location)
                else:
                    print("Location : " + "-")
                print("========================================")

                params = {
                  'apikey': API_KEY,
                  'resource': hash_md5,
                  'comment': str(commentaire)
                }

                response = requests.post('https://www.virustotal.com/vtapi/v2/comments/put', params=params)
                response_json = response.json()

                md5_ok.append(hash_md5)
                os.system('mv ' + elements + ' archive/')
                time.sleep(20)