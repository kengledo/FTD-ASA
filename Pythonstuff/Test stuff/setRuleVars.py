#!/bin/env python3.5
import getopt
from resources import *
from restClient import FMCRestClient
import json
import json
import requests
from datetime import datetime
import re
fmc_server_url = None
username = None
password = None
policy_name = None
rule_map_filename = None
def usage():
    print('script -s <fmc server url> -u <username> -p <password> -n <ac policy name> -f <rule_map_file>')
def parse_args(argv):
    global fmc_server_url
    global username
    global password
    global policy_name
    global rule_map_filename
    try:
        opts, args = getopt.getopt(argv,'hu:p:s:n:f:', ['file='])
    except getopt.GetoptError as e:
        print(str(e))
        usage()
        sys.exit(2)
    server_provided = False
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-u':
            username = arg
        elif opt == '-p':
            password = arg
        elif opt == '-s':
            fmc_server_url = arg
        elif opt == '-n':
            policy_name = arg
        elif opt == '-f':
            rule_map_filename = arg
        else:
            pass
    if not username or not password or not fmc_server_url or not policy_name or not rule_map_filename:
        usage()
        sys.exit(2)
def getPolicyByName(policyName, policyType):
    list = rest_client.list(globals()[policyType]())
    for policy in list: 
        if policyName == policy.name:
            return policy
"""
    Parameters:
        resource_json: json dict
        attrs: list of attrs to be removed from json dict
"""
def _remove_attrs(resource_json, attrs):
    for attr in attrs:
        if attr in resource_json:
            resource_json.pop(attr, None)
def validate_zone(zone, zones):
    rv = None
    for z in zones:
        if z.name == zone:
            rv = {}
            rv['name'] = z.name
            rv['id'] = z.id
            rv['type'] = z.type
            break

    if rv is None:
        print("Unable to find Security Zone with name", zone)

    return rv

def validate_ips_variable_set(ips, variable_set, ips_policies, variable_sets):
    rv = {}
    rv['ipsPolicy'] = None
    rv['variableSet'] = None

    for i in ips_policies:
        if i.name == ips:
            rv['ipsPolicy'] = {}
            rv['ipsPolicy']['name'] = i.name
            rv['ipsPolicy']['id'] = i.id
            rv['ipsPolicy']['type'] = i.type
            break

    if rv['ipsPolicy'] is None:
        print("Unable to find Intrusion Policy with name", ips)
    else:
        for v in variable_sets:
            if v.name == variable_set:
                rv['variableSet'] = {}
                rv['variableSet']['name'] = v.name
                rv['variableSet']['id'] = v.id
                rv['variableSet']['type'] = v.type

        if rv['variableSet'] is None:
            print("Unable to find variable set with name", variable_set)

    return rv

def build_rule_map(fname, security_zones, ips_policies, variable_sets):
    with open(fname) as f:
        lines = f.readlines()

    rule_map = []
    i = 1
    for line in lines:
        line = line.strip()
        cols = line.split(";")
        if len(cols) < 3:
            print("Invalid line \"", line, "\". Expect minimum of 3 semi-colon separated entries")
            return None

        index = cols[0].strip()
        if i != int(index):
            print("Input file is not sorted by rule index, or is missing entries")
            return None 

        rm = {}
        rm['index'] = index

        #source zone
        rm['sourceZones'] = []
        zones = cols[1].split(",");
        for zone in zones:
            zone = zone.strip()
            if zone == "any":
                if len(zones) == 1:
                    break
                else:
                    print("Cannot specify zone \"any\" in conjunction with other zones")
                    return None
            else:
                zone_obj = validate_zone(zone, security_zones)
                if zone_obj is None:
                    return None
                else:
                    rm['sourceZones'].append(zone_obj)

        #destination zone
        rm['destinationZones'] = []
        zones = cols[2].split(",")
        for zone in zones:
            zone = zone.strip()
            if zone == "any":
                if len(zones) == 1:
                    break
                else:
                    print("Cannot specify zone \"any\" in conjunction with other zones")
                    return None
            else:
                zone_obj = validate_zone(zone, security_zones)
                if zone_obj is None:
                    return None
                else:
                    rm['destinationZones'].append(zone_obj)

        if len(cols) > 3 and cols[3].strip() != "":
            ips_variable_set = cols[3].split(",")
            if len(ips_variable_set) != 2:
                print("Invalid IPS/Variable Set entry \"", cols[3], "\". Expect comma separated IPS and Variable Set")
                return None

            ips = ips_variable_set[0].strip()
            variable_set = ips_variable_set[1].strip()

            ips_varset_obj = validate_ips_variable_set(ips, variable_set, ips_policies, variable_sets)
            if ips_varset_obj['ipsPolicy'] is None or ips_varset_obj['variableSet'] is None:
                return None
            else:
                rm['ipsPolicy'] = ips_varset_obj['ipsPolicy']
                rm['variableSet'] = ips_varset_obj['variableSet']
        else:
            rm['ipsPolicy'] = None
            rm['variableSet'] = None

        rule_map.append(rm)
        i += 1

    return rule_map

def set_rule_vars(rule, rule_vars):
    url_path = rule.get_api_path()
    if rule.id:
        url_path += '/' + str(rule.id)
    url_path +='/'
    rule_json = rest_client.get(url_path)

    if rule_json:
        #sourceZones
        rule_json['sourceZones'] = {}
        rule_json['sourceZones']['objects'] = rule_vars['sourceZones']

        #destinationZones
        rule_json['destinationZones'] = {}
        rule_json['destinationZones']['objects'] = rule_vars['destinationZones']

        #ipsPolicy and variable set. Must be set together and only if rule action is allow
        if rule_vars['ipsPolicy'] is not None and rule_vars['variableSet'] is not None:
            if rule_json['action'] == 'ALLOW':
                rule_json['ipsPolicy'] = rule_vars['ipsPolicy']
                rule_json['variableSet'] = rule_vars['variableSet']
            else:
                print ("Cannot specify IPS Policy and Variable Set setting for rule \"", rule_json['name'], "\" because the rule action is not set to allow")
                return False

        #filter attrs not allowed by put/update operation
        resAttrs = ['metadata', 'links']
        resAttrs.append('commentHistoryList')
        _remove_attrs(rule_json, resAttrs)
        for value in ['sourcePorts', 'destinationPorts']:
            if value in rule_json:
                if 'objects' in rule_json[value]:
                    for objRef in rule_json[value]['objects']:
                        _remove_attrs(objRef,['protocol'])
        #update it
        rule_json = rest_client.put(url_path, json.dumps(rule_json))

    return True

if __name__ == "__main__":
    
    parse_args(sys.argv[1:])
    
    rest_client = FMCRestClient(fmc_server_url, username, password)
    acPolicy = getPolicyByName(policy_name, 'AccessPolicy')
    rules = rest_client.list(AccessRule(container=acPolicy))
    zones = rest_client.list(SecurityZone())
    ips_policies = rest_client.list(globals()['IntrusionPolicy']())
    variable_sets = rest_client.list(VariableSet())

    rule_map = build_rule_map(rule_map_filename, zones, ips_policies, variable_sets)

    if rule_map is None:
        print("Error building rule map from specified input file")
    else:
        if len(rules) != len(rule_map):
            print ("Number of specified rules in input file (", len(rule_map), ") does not match number of rules in AC policy (", len(rules), ")")
        else:
            i = 0
            fail = False;
            for rule in rules:
                rule_vars = rule_map[i]
                rule.container = acPolicy
                if not set_rule_vars(rule, rule_vars):
                    fail = True;
                    break
                i += 1
            if fail:
                print("Aborted due to some issue with a rule")
            else:
                print("Done!")
