#
# FTD/MFC API usage to get policy complexity
# Caretaker: Ana Peric <anperic@cisco.com>
#
 
import json
import argparse
import sys
import requests
import time
import logging
import logging.handlers
from requests.packages.urllib3.exceptions import InsecureRequestWarning


server = "https://10.56.140.9"
username = "api"
password = "apiapiapi"

#if len(sys.argv) > 1:
#    username = sys.argv[1]

#if len(sys.argv) > 2:
#    password = sys.argv[2]

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

r = None
headers = {'Content-Type': 'application/json'}

headers['X-auth-access-token'] = None


LOGFILE_NAME = 'fmc_policy_complexity.log'
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
logger.propagate = False

def generate_auth_token():

    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False) #verify='/path/to/ssl_certificate')
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print ("Error in generating auth token --> "+str(err))
        sys.exit()
    headers['X-auth-access-token'] = auth_token
    return(auth_token)


# General GET
def make_api_get_request(url,headers):
    #print("API Call to: {}").format(url)
    logger.debug("API Call to: %s",url)
    try:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            #print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            logger.debug(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r : r.close()
    return(json_resp)


# GET OPERATION

def get_rule_list(url, headers, accesspolicyid):
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accesspolicyid +"/accessrules?limit=200"
    #api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056A0-BF7B-0ed3-0000-034359751006/accessrules?limit=200"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    json_resp = make_api_get_request(url,headers)

    return(json_resp)


def get_network_object_group_complexity(id, complexity):
    #id: 005056A0-BF7B-0ed3-0000-034359748224
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/" + id    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    #time.sleep(1)
    json_resp = make_api_get_request(url, headers)
    # check if network object is built in or not
    if 'readOnly' in json_resp['metadata']:
        for elem in json_resp['literals']:
            if elem['type'] in ['Host', 'Network']:
                #print elem['type']
                complexity = complexity+1
            elif elem['type'] in 'NetworkGroup':
                #recursive call, help us universe
                get_network_object_group_complexity(elem['id'],complexity)
    # it is nomrmal cu configured object
    else:
        for elem in json_resp['objects']:
            if elem['type'] in ['Host', 'Network']:
                #print elem['type']
                complexity = complexity+1
            elif elem['type'] in 'NetworkGroup':
                #recursive call, help us universe
                get_network_object_group_complexity(elem['id'],complexity)
    return complexity

def get_port_object_group_complexity(id, complexity):
    #{"url":"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/portobjectgroups/005056A0-BF7B-0ed3-0000-034359750457"}
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/portobjectgroups/" + id    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    json_resp = make_api_get_request(url, headers)

    for elem in json_resp['objects']:
        if elem['type'] in 'PortObjectGroup':
            #recursive call, help us universe
            print("port object, dig into it")
            get_port_object_group_complexity(elem['id'],complexity)
        else:
            #print elem['type']
            complexity = complexity+1

    return complexity

def get_single_rule_complexity(ruleid, accesspolicyid):
    #print("Getting single rule complexity: " + ruleid)
    
    #url='/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056A0-BF7B-0ed3-0000-034359751006/accessrules/005056A0-BF7B-0ed3-0000-000268437834'
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accesspolicyid +"/accessrules/" + ruleid
    url = server + api_path
    
    total_complexity = 0
    src_zones = 0
    dst_zones = 0
    src_networks = 0
    dst_networks = 0
    dst_ports = 0
    vlan_tags = 1 # later usage, now its mainly not measured vlanTags:{}
    
    logger.info('Getting single rule complexity: %s' + ruleid)

    json_resp = make_api_get_request(url, headers)

    # do counting and return it
    if 'sourceZones' in json_resp:
        src_zones = len(json_resp['sourceZones']['objects'])
    else:
        src_zones = 1

    if 'destinationZones' in json_resp: 
        dst_zones =len(json_resp['destinationZones']['objects'])
    else:
        dst_zones = 1
   
    # for each obejct in soruce Network count further complexity. if type is NetworkGroup, we need to get network group resp by querying object
    if 'sourceNetworks' not in json_resp:
        src_networks = 1
    else:    
        for obj in json_resp['sourceNetworks']['objects']:
            if(obj["type"] in ['Host','Network']):
                # it is not a group, but net or host object, we don't need to count deeper
                src_networks = src_networks + 1
            elif obj["type"] in 'NetworkGroup':
                # get the into the group and see how many net object it has
                src_networks = src_networks + get_network_object_group_complexity(obj["id"], 0)

    # for each obejct in soruce Network count further complexity. if type is NetworkGroup, we need to get network group resp by querying object
    if 'destinationNetworks' not in json_resp:
        dst_networks = 1
    else:    
        for obj in json_resp['destinationNetworks']['objects']:
            if(obj["type"] in ['Host','Network']):
                # it is not a group, but net or host object, we don't need to count deeper
                dst_networks = dst_networks + 1
            elif obj["type"] in 'NetworkGroup':
                # get the into the group and see how many net object it has
                dst_networks = dst_networks + get_network_object_group_complexity(obj["id"], 0)

    # for each obejct in dst Ports  count further complexity. if type is NetworkGroup, we need to get network group resp by querying object
    if 'destinationPorts' not in json_resp:
        dst_ports = 1
    else:    
        for obj in json_resp['destinationPorts']['objects']:
            if obj["type"] in 'PortObjectGroup':
                # get the into the group and see how many net object it has
                dst_ports = dst_ports + get_port_object_group_complexity(obj["id"], 0)
            else:
                # it is not a group, but net or host object, we don't need to count deeper, just increment
                dst_ports = dst_ports + 1

    """print("===== Summary ======")
    print("Policy Name {}").format(json_resp['metadata']['accessPolicy']['name'])
    print("Rule Name {}").format(json_resp['name'])
    print("Rule ID {}").format(json_resp['id'])

    print("SrcZones: {}").format(src_zones)
    print("DstZones: {}").format(dst_zones)
    print("SrcNetworks: {}").format(src_networks)
    print("DstNetworks: {}").format(dst_networks)
    print("DstPorts: {}").format(dst_ports)
    comp = src_zones * dst_zones * src_networks * dst_networks * dst_ports
    print("Policy Complexity ACL: " + str(comp))
    """
    if src_networks == 0:
        src_networks = 1
    if dst_networks == 0:
        dst_networks = 1

    comp = src_zones * dst_zones * src_networks * dst_networks * dst_ports
    print("{} \t {} \t {} \t {} \t {} \t {} \t {} \t {} \t {}").format(json_resp['metadata']['accessPolicy']['name'],json_resp['name'], json_resp['id'], src_zones, dst_zones, src_networks, dst_networks, dst_ports, comp)

    return(json_resp)


def get_all_rule_complexity(accesspolicyid, headers):
    #005056A0-BF7B-0ed3-0000-034359751006
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accesspolicyid + "/accessrules?limit=200"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    json_resp = make_api_get_request(url,headers)
    # json_resp is already a dict
    #print(json_resp['items'])
    print("==== Policy Complexity Summary ====")
    print("Policy Name \t Rule Name \t Rule ID \t SourceZoneCount \t DestinationZoneCount \t SourceNetworkCount \t DestinationNetworkCount \t DestinationPortCount \t Total Complexity")
        
    for elem in json_resp['items']:
        #print("ID: {} | Name: {} | Link: {}").format(elem['id'], elem['name'], elem['links']['self'])
        res = get_single_rule_complexity(elem['id'], accesspolicyid)
        #print("sleeping not to kill API...")
        time.sleep(5)

def main():
    """
    Main function - used when called as a script directly
    Params:
        Processes multiple input parameters and switches
    """
    parser = argparse.ArgumentParser(
        description="FMC API usage - policy complexity")

    # Mandatory, positional arguments
    parser.add_argument("-ap", "--accesspolicy_id", help="access policy ID", default="005056A0-BF7B-0ed3-0000-034359751006")

    parser.add_argument("-r", "--rule_id", help="Get's complexity of rule ID inside policy")
    parser.add_argument("-no", "--network_object_id", help="Get network object ID")
    parser.add_argument("-po", "--port_object_id", help="Get port object ID")
    parser.add_argument("--list_all", help="Get complexity of all rules inside the policy")
    parser.add_argument("--incremental_rules", help="Calculate rule complexity starting rule id in -r, for policy specified in -ap, takes max increment cnt")

    args = parser.parse_args()
   
    logging.basicConfig(filename=LOGFILE_NAME,
                            level=logging.DEBUG,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.handlers.RotatingFileHandler(LOGFILE_NAME,
                                                   maxBytes=10 * 1024 * 1024,
                                                   backupCount=5)
    logger.addHandler(handler)

    #url='https://10.48.30.154/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056A0-BF7B-0ed3-0000-034359751006/accessrules/005056A0-BF7B-0ed3-0000-000268437834'

    accesspolicyid = args.accesspolicy_id #'005056A0-BF7B-0ed3-0000-034359751006'
    ruleid = '005056A0-BF7B-0ed3-0000-000268437889'
    
    if not headers['X-auth-access-token']:
        print("no x-auht token, generating it")
        generate_auth_token()

    if args.accesspolicy_id:
        accesspolicyid = args.accesspolicy_id

    if args.rule_id and not args.incremental_rules:
        print("Getting single rulle id: {}").format(args.rule_id)
        get_single_rule_complexity(ruleid=args.rule_id, accesspolicyid=accesspolicyid)

    if args.network_object_id:
        get_network_object_group_complexity(args.network_object_id, 0)

    if args.list_all:
        get_all_rule_complexity(accesspolicyid, headers)

    if args.incremental_rules:
        # incremental rule crawl starting form args.rule_id
        rules_max = int(args.incremental_rules)
        if not args.rule_id:
            print("you have to specify --rule_id to start from")
            sys.exit()
        if not args.accesspolicy_id:
            print("you have to specify --accesspolicy_id")
            sys.exit()

        rule_id_str = args.rule_id
        rule_id_static =  rule_id_str.split("-")[0] + "-" + rule_id_str.split("-")[1] + "-" + rule_id_str.split("-")[2] + "-" + rule_id_str.split("-")[3] + "-"
        
        for i in range(0, rules_max):
            get_single_rule_complexity(ruleid=rule_id_str, accesspolicyid=accesspolicyid)
        
            rule_id_int = rule_id_str.split("-")[4]
            rule_id_int = int(rule_id_int)
            rule_id_int = rule_id_int + 1
            rule_id_str = rule_id_static + "000" + str(rule_id_int)

        print(str(rule_id_int))

if __name__ == "__main__":
    main()
