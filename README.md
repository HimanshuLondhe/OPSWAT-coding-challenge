# OPSWAT Candidate Assessment Assignment
### [Himanshu Londhe](https://himanshu-londhe.me/)

## Getting Started
Download the code from Github
```git clone https://github.com/HimanshuLondhe/OPSWAT-coding-challenge.git```

Change the working directory
```cd OPSWAT-coding-challenge/```
## To run the code
1. Edit the properties.py file and replace the apikey variable with your own apikey.
2. Run the python file as ```python3 file_scanner.py <path to file>```
3. Retrieve output on the console or in the ```output.txt``` file


## Requirements 
1. Linux/Windows/Unix machine.
2. python3 
	#### Libraries 
		a. requests
		b. hashlib
		c. sys
		d. json
		e. time
		f. os

## Code Flow 
1. The program takes the file as an input argument in the console.
2. If the file exists, it calculates the md5 hash of the file and calls the lookup by hash API to check if the file is cached.
3. If not, the file is uploaded with the file upload API and the result is looked up with the lookup by data_id API.
4. While uploading, the status is available on the lookup url (found in ```properties.py```) with the help of Webhook.
5. Once, upload is complete, or if the hash is found, the ThreatReport class returns the obj that is the report which is printed as well as stored the ```output.txt``` (It will get over-written on every run)