import requests 
import hashlib
import sys
import json
import time
import os
import properties

apikey = properties.apikey 

class ThreatReport:
    def __init__(self):
        self.filename = ""
        self.overall_status = ""
        self.scanresults = []

    def jsonToObj(self,jsonresponse):
        self.filename = jsonresponse["file_info"]["display_name"]
        for result in jsonresponse["scan_results"]["scan_details"]:
            d = {}
            d["engine"] = result
            threat = jsonresponse["scan_results"]["scan_details"][result]["threat_found"]
            if threat == "":
                d["threat_found"] = "Clean"
            else:
                d["threat_found"] = threat
            d["scan_result"] = jsonresponse["scan_results"]["scan_details"][result]["scan_result_i"]
            d["def_time"] = jsonresponse["scan_results"]["scan_details"][result]["def_time"]
            self.scanresults.append(d)
        if jsonresponse["scan_results"]["scan_all_result_i"] == 0:
            self.overall_status = "Clean"
        else:
            self.overall_status = "Infected"
    
    def __str__(self):
        string = "filename: " + self.filename + "\n" + "overall_status: " + self.overall_status + "\n" 
        
        for i in self.scanresults:
            string = string + "engine: " + i["engine"] + "\n" + \
            "threat_found: " + i["threat_found"] + "\n" + \
            "scan_result: " + str(i["scan_result"]) + "\n" + \
            "def_time: " + str(i["def_time"]) + "\n" 
        string  = string + "END" + "\n"
        return string

        
class OPSWAT_Challenge:

    def __init__(self):
        self.filepointer = None
        self.data_id = ""
        self.hashvalue = ""

    def upload_file(self,fp):
        data = fp.read()
        url = properties.commonurl
        headers = {'apikey':apikey,"Content-Type":"application/octet-stream","filename":self.filepointer,"callbackurl":properties.callbackurl}
        try:
            response = requests.post(url,data=data,headers=headers)
            jsonresponce = response.json()
            if response.status_code == 200:
                self.data_id = jsonresponce["data_id"]
                print("File not in cache, uploading now...")
                self.webhook()
        except requests.HTTPError as exception:
            print(exception)
        

    def lookupByDataID(self):
        url = properties.commonurl + self.data_id
        headers = {'apikey':apikey,'x-file-metadata':"1"}
        response = requests.get(url,headers = headers)
        try:
            jsonresponce = response.json()
            obj = ThreatReport()
            obj.jsonToObj(jsonresponce)
            print(obj)
        except requests.HTTPError as exception:
            print(exception)
        
    def genhash(self,file):
        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        try:
            with open(file, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
            self.hashvalue = hasher.hexdigest()
            self.hashlookup()
        except Exception:
            print('File not found, please provide a valid path')

    def genhashsha(self,file):
        filename = input("Enter the input file name: ")
        with open(file,"rb") as f:
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest();
            print(readable_hash)


    def hashlookup(self):
        url = "https://api.metadefender.com/v4/hash/" + self.hashvalue
        headers = {'apikey':apikey}
        response = requests.get(url,headers= headers)
        jsonresponse = response.json()
        self.filepointer = os.path.abspath(sys.argv[1])
        fp = open(self.filepointer,"rb")
        if response.status_code == 404:
            self.upload_file(fp)
        elif response.status_code == 200:
            print("Lookup Successfull")
            obj = ThreatReport()
            obj.jsonToObj(jsonresponse)
            print(obj)

    def webhook(self):
        url = properties.callbackmetadefender + self.data_id
        headers = {"apikey":apikey}
        response = requests.get(url,headers= headers)
        while response.status_code != 200:
            response = requests.get(url,headers = headers)
            time.sleep(2)
        if response.status_code == 200:
            self.lookupByDataID()
            
if __name__ == "__main__":
    filename = sys.argv[1]
    scanfile = OPSWAT_Challenge()
    scanfile.genhash(filename)