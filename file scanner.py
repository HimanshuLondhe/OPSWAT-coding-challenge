import requests 
import hashlib
import sys
import json
import time
import os

apikey = "584eb607b17a4634e1aa535188c69daa"

class ThreatReport:
    def __init__(self):
        self.filename = ""
        self.overall_status = ""
        self.scanresults = []

    def jsonToObj(self,jsonresponse):
        self.filename = jsonresponse["file_info"]["display_name"]
        print('Filename = ',self.filename)
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
        url = "https://api.metadefender.com/v4/file"
        headers = {'apikey':apikey,"Content-Type":"application/octet-stream","filename":self.filepointer,"callbackurl":"https://webhook.site/b003869b-f444-4787-88fa-5a99087c45d8"}
        response = requests.post(url,data=data,headers=headers)
        print("Post response: ",response.status_code)

        jsonresponce = response.json()
        print("upload_File" ,jsonresponce)
        if response.status_code == 200:
            self.data_id = jsonresponce["data_id"]
            self.webhook()

            # self.lookupByDataID()

        else:

            return -1

    def lookupByDataID(self):
        url = "https://api.metadefender.com/v4/file/"+self.data_id
    
        headers = {'apikey':apikey,'x-file-metadata':"1"}
        print("url for data lookup:", url)
        response = requests.get(url,headers = headers)
        # print("res:", response.text)
        jsonresponce = response.json()
        print("josn res in lookup ",jsonresponce)
        obj = ThreatReport()
        obj.jsonToObj(jsonresponce)
        print("indata lookup",obj.scanresults)
        print(obj)
        
    def genhash(self,file):
        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        with open(file, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        self.hashvalue = hasher.hexdigest()

    def hashlookup(self):
        url = "https://api.metadefender.com/v4/hash/" + self.hashvalue
        headers = {'apikey':apikey}
        response = requests.get(url,headers= headers)
        # print(response.text)
        jsonresponse = response.json()
        # print(json.dumps(jsonresponse, indent=1))
        self.filepointer = os.path.abspath(sys.argv[0])
        fp = open(self.filepointer,"r")
        if response.status_code == 404:
            self.upload_file(fp)
        elif response.status_code == 200:
            print("Lookup Successfull")
            obj = ThreatReport()
            obj.jsonToObj(jsonresponse)
            print(obj)

    def webhook(self):
        url = "https://api.metadefender.com/v4/file/webhooks/" + self.data_id
        headers = {"apikey":apikey}
        response = requests.get(url,headers= headers)
        print(response.text)
        while response.status_code != 200:
            response = requests.get(url,headers = headers)
            print(response.text)
            time.sleep(2)
        if response.status_code == 200:
            self.lookupByDataID()

if __name__ == "__main__":
    filename = sys.argv[1]
    scanfile = OPSWAT_Challenge()
    scanfile.genhash(filename)
    scanfile.hashlookup()


