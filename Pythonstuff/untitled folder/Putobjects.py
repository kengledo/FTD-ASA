
import json
import sys
import requests
import csv

server = "svrname/or ip"


username = "username"

if len(sys.argv) > 1:

    username = sys.argv[1]

password = "password"

if len(sys.argv) > 2:

    password = sys.argv[2]

filename = "filename"

if len(sys.argv) > 3:

    filename = sys.argv[2]



# turn off SSL warnings

requests.packages.urllib3.disable_warnings()





# do authentication work               

r = None

headers = {'Content-Type': 'application/json'}

api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"

auth_url = server + api_auth_path



print("Trying to authenticate on "+server+" ...")

try:

    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)

    auth_headers = r.headers

    auth_token = auth_headers.get('X-auth-access-token', default=None)

    if auth_token == None:

        print("auth_token not found. Exiting...")

        sys.exit()

    print("Authentication successful... move on...")

    print(".")

    

except Exception as err:

    print ("Error in generating auth token --> "+str(err))

    sys.exit()

 

headers['X-auth-access-token']=auth_token

 







# prepare input from file

hostsfile = open(filename, 'r')

reader = csv.reader(hostsfile)



hostlist = []

for line in reader:

 list_line= { 'name': str(line[0]),'type': 'Network','value': str(line[1]),'description': str(line[2]) }

 hostlist.append(list_line)

 





# POST OPERATION

 

print("Attempting to add Hosts from file "+filename+" ...")

try:



    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networks"

    url = server + api_path



    for host in hostlist:

       r = requests.post(url, headers=headers,data=json.dumps(host), verify=False)

      

       status_code = r.status_code

       resp = r.text



       if (status_code == 201):

        print("Host "+host['name']+" with IP "+host['value']+" successfully added")

        

       else:

        if (status_code == 400): 

         print("Host seems to exist already - skipping...")



except requests.exceptions.HTTPError as err:

    print ("Error in connection --> "+str(err)) 

finally:

    if r : r.close()
