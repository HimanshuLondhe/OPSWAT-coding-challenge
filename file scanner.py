import requests 
import hashlib
import sys
import json
import time
import os
import properties

apikey = properties.apikey 

### Threat Report is generated as specified. returns the output as an object.
class ThreatReport:
    def __init__(self):
        self.filename = ""
        self.overall_status = ""
        self.scanresults = []

    ### Function which takes the json returned from data_id lookup or the hash lookup
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


    ### over-writing the string return to the specified format.
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

    ### Function to upload the file using the upload file API
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
            print("File not uploaded: ",exception)
        
    ### Looks up the scan results by the data_id
    def lookupByDataID(self):
        url = properties.commonurl + self.data_id
        headers = {'apikey':apikey,'x-file-metadata':"1"}
        response = requests.get(url,headers = headers)
        try:
            jsonresponce = response.json()
            obj = ThreatReport()
            obj.jsonToObj(jsonresponce)
            print(obj)
            s = str(obj)
            text_file = open("output.txt", "w")
            text_file.write(s)
        except requests.HTTPError as exception:
            print("Data ID not correct: " ,exception)

    ### Generates the md5 hash of the given file       
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
        except Exception as e:
            print('File not found, please provide a valid path',e)

    ### If has is found, the following function is called to retrieve info from the ThreatReport class.
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
            s = str(obj)
            text_file = open("output.txt", "w")
            text_file.write(s)


    ### Function to get the upload status from the callbackurl using Webhook.
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
    try:
        if len(sys.argv) != 2:
            raise ValueError("Enter right amount of arguments: Usage: python3 file_scanner.py <file to be uploaded>")
    except ValueError as e:
        print(e)
        sys.exit()
    ## Create an object of the main challenge class and calculate hash.
    filename = sys.argv[1]
    scanfile = OPSWAT_Challenge()
    scanfile.genhash(filename)