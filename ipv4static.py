import json
import sys
import requests

server = "https://10.56.140.9"

username = "api"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = ""
if len(sys.argv) > 2:
    password = sys.argv[2]

r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
     # 2 ways of making a REST call are provided:
    # One with "SSL verification turned off" and the other with "SSL verification turned on".
    # The one with "SSL verification turned off" is commented out. If you like to use that then
    # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
    # REST call with SSL verification turned off:
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
    #r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)       
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print("Error in generating auth token --> " + str(err))
    sys.exit()

headers['X-auth-access-token'] = auth_token
    
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords/f589875c-b6f8-11e6-ba9c-d259b84bf2d6/routing/ipv4staticroutes"  # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]

# Post OPERATION

post_data = {
"interfaceName": "External",
"selectedNetworks": [
    {
     "type": "Network",
     "id": "843DC698-755A-0ed3-0000-068719478273",
     "name": "IPv4_any"
     }
],
  "gateway": {
    "object": {
      "type": "Host",
      "id": "843DC698-755A-0ed3-0000-068719477086",
      "name": "NGENA-GW"
    }
  },
  "metricValue": 1,
  "type": "IPv4StaticRoute",
  "isTunneled": 0
            }

try:
    # REST call with SSL verification turned off:
    r = requests.post(url, json=post_data, headers=headers, verify=False)
    # REST call with SSL verification turned on:
    # response = requests.request('POST',url,json = post_data)
    status_code = r.text
    print("Status code is: "+str(status_code))
    if status_code == 201 or status_code == 202:
        print ("Post was successful...")
        json_resp = json.loads(resp)
        print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
    else :
        r.raise_for_status()
        print ("Error occurred in POST --> "+resp)
except  requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))
finally:
    if r: r.close()

