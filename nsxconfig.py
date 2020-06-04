#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import json
import time
import yaml
import sys
import uuid
import argparse
import getpass
import base64
import socket
import hashlib
import ssl

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

filename = "config.yaml"

def colon(s):
    return ':'.join(s[i:i+2] for i in range(0, len(s), 2))

def get_vcenter_thumbprint(vcenter_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)

    try:
        wrappedSocket.connect((vcenter_name, 443))
    except:
        response = False
        wrappedSocket.close()
        return 0
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        formatted_sha256 = colon(sha256)
        wrappedSocket.close()
        return formatted_sha256

def register_vcenter(vcenter_name,user,passwd,sha256_tp):
    vcenter_payload = dict()
    vcenter_payload["server"] = vcenter_name
    vcenter_payload["origin_type"] = "vCenter"
    vcenter_payload["display_name"] = vcenter_name
    vcenter_payload["set_as_oidc_provider"] = True  
    vcenter_payload["credential"] = dict()
    vcenter_payload["credential"]["credential_type"] ="UsernamePasswordLoginCredential"
    vcenter_payload["credential"]["username"] = user
    vcenter_payload["credential"]["password"] = passwd
    vcenter_payload["credential"]["thumbprint"] = sha256_tp
    json_payload = json.loads(json.dumps(vcenter_payload))
    json_response = s.post('https://'+nsxmgr+'/api/v1/fabric/compute-managers',auth=HTTPBasicAuth(userid,password),json=json_payload)
    if not json_response.ok:
        print ("Unable to register vcenter :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        return results["id"]


    json_response = s.get('https://'+nsxmgr+'/api/v1/fabric/compute-managers/2d3580c7-d4b5-4caa-a94f-2d17e401f4ef',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Unable to register vcenter :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        return results["id"]

def get_nsx_cluster_status():
    json_response = s.get('https://'+nsxmgr+'/api/v1/cluster/status',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Session creation is failed, please check nsxmgr connection")
        return 0
    else: 
        results = json.loads(json_response.text)
        if results["detailed_cluster_status"]["overall_status"] == "STABLE":
            return 1
        else:
            return 0 

def get_transport_zone(t_type):
    json_response = s.get('https://'+nsxmgr+'/api/v1/transport-zones/',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Unable to get transport zone :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        for result in results["results"]:
            if result["transport_type"] == t_type:
                return result["id"]
        return 0    

def get_uplink_profile(p_name):
    json_response = s.get('https://'+nsxmgr+'/api/v1/host-switch-profiles',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Unable to get uplink profile :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        for result in results["results"]:
            if result["display_name"] == p_name:
                return result["id"]
        return 0    

def create_uplink_profile(p_name,vlan):
    switch_payload = dict()
    switch_payload["resource_type"] = "UplinkHostSwitchProfile"
    switch_payload["display_name"] = p_name
    switch_payload["transport_vlan"] = vlan
    switch_payload["teaming"] = dict()
    switch_payload["teaming"]["policy"] = "FAILOVER_ORDER"
    switch_payload["teaming"]["active_list"] = [ dict() ]
    switch_payload["teaming"]["active_list"][0]["uplink_name"] = "uplink-1"
    switch_payload["teaming"]["active_list"][0]["uplink_type"] = "PNIC"
    switch_payload["teaming"]["standby_list"] = [ dict() ]
    switch_payload["teaming"]["standby_list"][0]["uplink_name"] = "uplink-2"
    switch_payload["teaming"]["standby_list"][0]["uplink_type"] = "PNIC"
    json_payload = json.loads(json.dumps(switch_payload))
    json_response = s.post('https://'+nsxmgr+'/api/v1/host-switch-profiles',auth=HTTPBasicAuth(userid,password),json=json_payload)
    if not json_response.ok:
        print ("Unable to create Uplink Profile :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        return results["id"]

def create_ipaddr_pool(p_name,p_desc,start_ip, end_ip, gw, cidr):
    ippool_payload = dict()
    ippool_payload["display_name"] = p_name
    ippool_payload["description"] = p_desc
    ippool_payload["_revision"] = 0

    json_payload = json.loads(json.dumps(ippool_payload))
    
    subnet_payload = dict()
    subnet_payload["display_name"] = p_name+"ip_alloc"
    subnet_payload["resource_type"] = "IpAddressPoolStaticSubnet"
    subnet_payload["cidr"] = cidr
    subnet_payload["gateway_ip"] = gw
    subnet_payload["allocation_ranges"] = [dict()]
    subnet_payload["allocation_ranges"][0]["start"] = start_ip
    subnet_payload["allocation_ranges"][0]["end"] = end_ip   
    
    json_payload1 = json.loads(json.dumps(subnet_payload))
    
    json_response = s.patch('https://'+nsxmgr+'/policy/api/v1/infra/ip-pools/'+p_name,auth=HTTPBasicAuth(userid,password),json=json_payload)
    if not json_response.ok:
        print ("Unable to create IP pool :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        # Now create subnets
        json_response1 = s.patch('https://'+nsxmgr+'/policy/api/v1/infra/ip-pools/'+p_name+'/ip-subnets/'+p_name+'ip_alloc',auth=HTTPBasicAuth(userid,password),json=json_payload1)
        if not json_response1.ok:
            print ("Unable to create IP block :  "+json_response1.content.decode("utf-8"))
            return 0
        else:
            return 1

def get_ipaddr_pool(p_name):
    json_response = s.get('https://'+nsxmgr+'/api/v1/pools/ip-pools',auth=HTTPBasicAuth(userid,password))
    if json_response.ok:
        results = json.loads(json_response.text)
        for result in results["results"]:
            if result["display_name"] == p_name:
                return result["id"]
        return 0
    else:
        return 0
    
def get_transport_node_profile():
    json_response = s.get('https://'+nsxmgr+'/api/v1/transport-node-profiles/f04fa0a8-7cc2-4a5e-ab9a-c1ba7375a2ef',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Session creation is failed, please check nsxmgr connection")
        return 0
    else: 
        results = json.loads(json_response.text)
        print (json.dumps(results,indent=2,sort_keys=True))
        return 1

def get_transport_node():
    json_response = s.get('https://'+nsxmgr+'/api/v1/transport-nodes/b02ac314-d90a-42d5-a648-e674445feb7a',auth=HTTPBasicAuth(userid,password))
    if not json_response.ok:
        print ("Session creation is failed, please check nsxmgr connection")
        return 0
    else: 
        results = json.loads(json_response.text)
        print (json.dumps(results,indent=2,sort_keys=True))
        return 1

def create_transport_node_profile(name, mode, swtype, switch_profile_id, tz_id, ip_pool_id):
    profile_payload = dict()
    profile_payload["resource_type"] = "TransportNodeProfile"
    profile_payload["display_name"] = "ESXI Transport Node Profile"
    profile_payload["host_switch_spec"] = dict()
    profile_payload["host_switch_spec"]["resource_type"] = "StandardHostSwitchSpec"
    profile_payload["host_switch_spec"]["host_switches"] = [ dict() ]
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_name"] = name
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_mode"] = mode
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_type"] = swtype
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_profile_ids"] = [ dict()]
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_profile_ids"][0]["key"] = "UplinkHostSwitchProfile"
    profile_payload["host_switch_spec"]["host_switches"][0]["host_switch_profile_ids"][0]["value"] = switch_profile_id
    profile_payload["host_switch_spec"]["host_switches"][0]["pnics"] = [dict()]
    profile_payload["host_switch_spec"]["host_switches"][0]["pnics"][0]["uplink_name"] = "uplink-1"
    profile_payload["host_switch_spec"]["host_switches"][0]["pnics"][0]["device_name"] = "vmnic2"
    profile_payload["host_switch_spec"]["host_switches"][0]["transport_zone_endpoints"] = [dict()]
    profile_payload["host_switch_spec"]["host_switches"][0]["transport_zone_endpoints"][0]["transport_zone_id"] = tz_id
    profile_payload["host_switch_spec"]["host_switches"][0]["ip_assignment_spec"] = dict()
    profile_payload["host_switch_spec"]["host_switches"][0]["ip_assignment_spec"]["ip_pool_id"] = ip_pool_id
    profile_payload["host_switch_spec"]["host_switches"][0]["ip_assignment_spec"]["resource_type"] = "StaticIpPoolSpec"
    json_payload = json.loads(json.dumps(profile_payload))
    json_response = s.post('https://'+nsxmgr+'/api/v1/transport-node-profiles',auth=HTTPBasicAuth(userid,password),json=json_payload)
    if not json_response.ok:
        print ("Unable to create Uplink Profile :  "+json_response.content.decode("utf-8"))
        return 0
    else: 
        results = json.loads(json_response.text)
        return results["id"] 
        
s = "Global"
s=requests.Session()
s.verify=False

with open(filename,) as f:
    yamldocs = yaml.load_all(f, Loader=yaml.FullLoader)
    for yamldoc in yamldocs:

        # Read values from YAML
        vcenter = yamldoc["vcenter"]
        vcuserid = yamldoc["vcuserid"]
        vcpassword = yamldoc["vcpassword"]

        nsxmgr = "Global"
        userid = "Global"
        password = "Global"
        nsxmgr = yamldoc["nsxmgr"]
        userid = yamldoc["userid"]
        password = yamldoc["password"]

        edge_ip_pool_start_ip = yamldoc["edge_ip_pool_start_ip"]
        edge_ip_pool_end_ip = yamldoc["edge_ip_pool_end_ip"]
        edge_ip_pool_def_gw = yamldoc["edge_ip_pool_def_gw"]
        edge_ip_pool_def_cidr = yamldoc["edge_ip_pool_def_cidr"]
        edge_tep_vlan = yamldoc["edge_tep_vlan"]
        host_ip_pool_start_ip = yamldoc["host_ip_pool_start_ip"]
        host_ip_pool_end_ip = yamldoc["host_ip_pool_end_ip"]
        host_ip_pool_def_gw = yamldoc["host_ip_pool_def_gw"]
        host_ip_pool_def_cidr = yamldoc["host_ip_pool_def_cidr"]
        host_tep_vlan = yamldoc["host_tep_vlan"]

        # Starting  main loop
        #######################################################################
        # Check if NSX Manager is up and stable before proceeding. 
        
        if get_nsx_cluster_status():

           # get_transport_node_profile()
           # get_ipaddr_pool()
            aa = get_transport_node()
            # Get SHA256 thumbpring and register compute manager
            thumbprint = get_vcenter_thumbprint(vcenter)
            if not thumbprint:
                print ("Error getting VCenter thumbprint. Check connection")
                sys.exit(1)
            vcenter_id = register_vcenter(vcenter,vcuserid,vcpassword,thumbprint)
            if not vcenter_id:
               print ("Error Registering vcenter")
               sys.exit(1)
            print ("VCenter registerted to NSX manager")

            # Get IDs of default Transport Zones
            tz_overlay_id = get_transport_zone("OVERLAY")
            tz_vlan_id = get_transport_zone("VLAN")

            # Create IP Pools for Host and Edge TEPs
            if not create_ipaddr_pool("HOST_IP_POOL","IP Pool for Host TEP Interface",host_ip_pool_start_ip,host_ip_pool_end_ip,host_ip_pool_def_gw,host_ip_pool_def_cidr):
                print ("Error creating IP POOL")
                sys.exit(1)        
            print ("Host IP Pool created")
            if not create_ipaddr_pool("EDGE_IP_POOL","IP Pool for Edge TEP Interface",edge_ip_pool_start_ip,edge_ip_pool_end_ip,edge_ip_pool_def_gw,edge_ip_pool_def_cidr):
                print ("Error creating IP POOL")
                sys.exit(1)
            print ("Edge IP Pool created")

            # Create Host and edge uplink profiles
            host_profile_id = create_uplink_profile("nsx-demo-uplink-hostswitch-profile",host_tep_vlan)
            if not host_profile_id:
                print ("Error creatin host profile")
                sys.exit(1)
            print ("Host Switch profile created")
            edge_profile_id = create_uplink_profile("nsx-demo-uplink-edge-profile",edge_tep_vlan)
            if not edge_profile_id:
                print ("Error creatin edge profile")
                sys.exit(1)
            print ("Edge Switch profile created")

            # Retrive Host and Edge IP pools IDs 
            host_ip_pool_id = get_ipaddr_pool("HOST_IP_POOL")
            while not host_ip_pool_id:
                print ("Waiting for Host IP Pools to become ready")
                time.sleep(5)    
                host_ip_pool_id = get_ipaddr_pool("HOST_IP_POOL")
                
            edge_ip_pool_id = get_ipaddr_pool("EDGE_IP_POOL")
            while not edge_ip_pool_id:
                print ("Waiting for Edge IP Pool to become ready")
                time.sleep(5)
                edge_ip_pool_id = get_ipaddr_pool("EDGE_IP_POOL")
                
            # Create Host TN profile 
            transport_node_profile_id = create_transport_node_profile("ESX_TN_Profile", "STANDARD", "NVDS",host_profile_id,tz_overlay_id,host_ip_pool_id)
            if not transport_node_profile_id:
                print ("Error creating transport node host profile")
                sys.exit(1)
            print ("Transport Node switch profile created")
            
        #    get_transport_node_profile()  
        else:
            print("NSX Manager does not seem to be stable. This may happen if the appliance was just installed and is still configuraing and coming up. Please try again in a few minutes.")