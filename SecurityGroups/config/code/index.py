from __future__ import print_function
import logging
import boto3
import os
import collections
from collections import namedtuple
import urllib3
import csv
import cfnresponse as cfnr
import botocore.exceptions as exceptions

http = urllib3.PoolManager()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
responseData = {}
# Boto3 config
REGION = os.environ['AWS_REGION']
client = boto3.client('ec2', region_name=REGION)
OtherSecurityGroup = namedtuple(
    "OtherSecurityGroup",
    [
        "group_id"
    ],
)
PrefixLists = namedtuple(
    "PrefixLists",
    [
        "pl_id"
    ]
)
SgRuleIngress = namedtuple(
    "SgRuleIngress",
    (
        "cidrs",
        "ipv6_cidrs",
        "from_port",
        "to_port",
        "protocol",
        "other_security_groups",
        "prefix_list_id"
    )
)
SgRuleEgress = namedtuple(
    "SgRuleEgress",
    (
        "cidrs",
        "ipv6_cidrs",
        "from_port",
        "to_port",
        "protocol",
        "other_security_groups",
        "prefix_list_id"
    )
)
# Named tuple for Ingress rules
Ingress_Rules = [
    # (SgRuleIngress(cidrs=('172.16.0.0/16', '10.0.0.0/8'), ipv6_cidrs=(), from_port=80, to_port=85, protocol='tcp',
    #         other_security_groups=(), prefix_list_id=([]))),
    # (SgRuleIngress(cidrs=('172.16.0.0/16', '10.0.0.0/8'), ipv6_cidrs=(), from_port=443, to_port=443, protocol='tcp',
    #         other_security_groups=(), prefix_list_id=([])))
]
# Named tuple for Egress rules
Egress_Rules = [
    # (SgRuleEgress(cidrs=('172.16.0.0/16', '10.0.0.0/8'), ipv6_cidrs=(), from_port=81, to_port=81, protocol='tcp',
    #         other_security_groups=(), prefix_list_id=([]))),
    # (SgRuleEgress(cidrs=('172.16.0.0/16', '10.0.0.0/8'), ipv6_cidrs=(), from_port=8080, to_port=8080, protocol='tcp',
    #         other_security_groups=(), prefix_list_id=([])))
]
def csvParser():
#     s3 = boto3.resource('s3')
#     bucket = s3.Bucket(bucketName)
#     key = keyPath
#     local_file_name = '/tmp/config.csv'
#     s3.Bucket(bucketName).download_file(key,local_file_name)
    with open ('sg_config.csv', newline='') as csvfile:
        data = csv.reader(csvfile, delimiter=';')
        for row in data:
            cidr = []
            for i in row[1].split(","):
                cidr.append(i)
            if row[0] == "ingress":
                Ingress_Rules.append(SgRuleIngress(cidrs=tuple(cidr), ipv6_cidrs=row[2], from_port=int(row[3]), to_port=int(row[4]), protocol=row[5],
            other_security_groups=row[6], prefix_list_id=row[7]))
            elif row[0] == "egress":
                Egress_Rules.append(SgRuleIngress(cidrs=tuple(cidr), ipv6_cidrs=row[2], from_port=int(row[3]), to_port=int(row[4]), protocol=row[5],
            other_security_groups=row[6], prefix_list_id=row[7]))
        try:
            print("ingressRule", Ingress_Rules)
        except:
            pass
        try:
            print("egressRule",Egress_Rules)
        except:
            pass

            #cidrs;ipv6_cidrs;from_port;to_port;protocol;other_security_groups;prefix_list_id

# add the ingress rules that are required
def authorizeIngressRule(sg, rule):
    # print(sg, rule, authorize)
    # if authorize:
    permissions = []
    # print("add", rule)
    permission_set = {
        "IpProtocol": rule.protocol,
        "IpRanges": [{"CidrIp": cidr} for cidr in rule.cidrs],
        "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in rule.ipv6_cidrs],
        "UserIdGroupPairs": [{"GroupId": GroupId} for GroupId in rule.other_security_groups],
        "PrefixListIds": [{"PrefixListId": prefix} for prefix in rule.prefix_list_id],
    }
    _add_entry(permission_set, "FromPort", rule.from_port)
    _add_entry(permission_set, "ToPort", rule.to_port)
    permissions.append(permission_set)
    boto = boto3.client('ec2')
    try:
        response = boto.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[permission_set]
            )
    except client.exceptions.ClientError:
        print('Failed to add Ingress')
        pass

# remove the ingress rules that are not required
def revokeIngressRule(sg, rule):
    permissions = []
    permission_set = {
        "IpProtocol": rule.protocol,
        "IpRanges": [{"CidrIp": cidr} for cidr in rule.cidrs],
        "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in rule.ipv6_cidrs],
        "UserIdGroupPairs": [{"GroupId": GroupId} for GroupId in rule.other_security_groups],
        "PrefixListIds": [{"PrefixListId": prefix} for prefix in rule.prefix_list_id],
    }
    _add_entry(permission_set, "FromPort", rule.from_port)
    _add_entry(permission_set, "ToPort", rule.to_port)
    permissions.append(permission_set)
    boto = boto3.client('ec2')
    try:
        response = boto.revoke_security_group_ingress(
            GroupId=sg,
            IpPermissions=[permission_set])
    except client.exceptions.ClientError:
        print('Failed to remove Ingress')
        pass

# add the egress rules that are required
def authorizeEgressRule(sg, rule):
    # print(sg, rule, authorize)
    # if authorize:
    permissions = []
    # print("add", rule)
    permission_set = {
        "IpProtocol": rule.protocol,
        "IpRanges": [{"CidrIp": cidr} for cidr in rule.cidrs],
        "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in rule.ipv6_cidrs],
        "UserIdGroupPairs": [{"GroupId": GroupId} for GroupId in rule.other_security_groups],
        "PrefixListIds": [{"PrefixListId": prefix} for prefix in rule.prefix_list_id],
    }
    _add_entry(permission_set, "FromPort", rule.from_port)
    _add_entry(permission_set, "ToPort", rule.to_port)
    permissions.append(permission_set)
    boto = boto3.client('ec2')
    try:
        response = boto.authorize_security_group_egress(
            GroupId=sg,
            IpPermissions=[permission_set])
    except boto.exceptions.ClientError:
        print('Failed to add Egress')
        pass

# remove the egress rules that are not required
def revokeEgressRule(sg, rule):
    permissions = []
    permission_set = {
        "IpProtocol": rule.protocol,
        "IpRanges": [{"CidrIp": cidr} for cidr in rule.cidrs],
        "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in rule.ipv6_cidrs],
        "UserIdGroupPairs": [{"GroupId": GroupId} for GroupId in rule.other_security_groups],
        "PrefixListIds": [{"PrefixListId": prefix} for prefix in rule.prefix_list_id],
    }
    _add_entry(permission_set, "FromPort", rule.from_port)
    _add_entry(permission_set, "ToPort", rule.to_port)
    permissions.append(permission_set)
    boto = boto3.client('ec2')
    try:
        response = boto.revoke_security_group_egress(
            GroupId=sg,
            IpPermissions=[permission_set])
    except boto.exceptions.ClientError:
        print('Failed to remove Egress')
        pass
# compare the expected rules and the current rules of all sg's in the env
def compareSecurityGroupIngressRules(sg, current_ingress_rule_list, Ingress_Rules):
    authorizeRuleList = []
    revokeRuleList = []
    for i in current_ingress_rule_list:
        if i not in Ingress_Rules:
            revokeRuleList.append(i)
    for i in Ingress_Rules:
        if i not in current_ingress_rule_list:
            authorizeRuleList.append(i)
    print(sg, 'authorizeRuleList', authorizeRuleList)
    print(sg, 'revokeRuleList', revokeRuleList)
    for rule in revokeRuleList:
        try:
            revokeIngressRule(sg, rule)
        except Exception as e:
            logger.error('Something went wrong: ' + str(e))
    for rule in authorizeRuleList:
        try:
            authorizeIngressRule(sg, rule)
        except Exception as e:
            logger.error('Something went wrong: ' + str(e))
# compare the expected rules and the current rules of all sg's in the env
def compareSecurityGroupEgressRules(sg, current_egress_rule_list, Ingress_Rules):
    authorizeRuleList = []
    revokeRuleList = []
    for i in current_egress_rule_list:
        if i not in Egress_Rules:
            revokeRuleList.append(i)
    for i in Egress_Rules:
        if i not in current_egress_rule_list:
            authorizeRuleList.append(i)
    print(sg, 'authorizeRuleList', authorizeRuleList)
    print(sg, 'revokeRuleList', revokeRuleList)
    for rule in revokeRuleList:
        try:
            revokeEgressRule(sg, rule)
        except Exception as e:
            logger.error('Something went wrong: ' + str(e))
    for rule in authorizeRuleList:
        try:
            authorizeEgressRule(sg, rule)
        except Exception as e:
            logger.error('Something went wrong: ' + str(e))

def _add_entry(dictionary, key, value):
    if value is not None:
        dictionary[key] = value
def extract_other_security_group(sg_data):
    group_id = sg_data.get("GroupId")
    return group_id
def extract_prefix_list_id(sg_data):
    pl_id = sg_data.get("PrefixListId")
    return sg_data.get("PrefixListId")
# get the current ingress rules for security groups that exists
def currentIngressRule(sg):
    sg_response = client.describe_security_groups(GroupIds=[sg])
    print (sg_response)
    current_ingress_rule_list = []
    for permission_set in sg_response['SecurityGroups'][0]['IpPermissions']:
        protocol = permission_set["IpProtocol"]
        from_port = permission_set.get("FromPort")
        to_port = permission_set.get("ToPort")
        cidrs = tuple(
            ip_range["CidrIp"]
            for ip_range in permission_set.get("IpRanges", [])
        )
        ipv6_cidrs = tuple(
            ip_range["CidrIpv6"]
            for ip_range in permission_set.get("Ipv6Ranges", [])
        )
        other_security_groups = tuple(
            extract_other_security_group(group)
            for group in permission_set.get("UserIdGroupPairs", [])
        )
        prefix_list_id = tuple(
            extract_prefix_list_id(group)
            for group in permission_set.get("PrefixListIds", [])
        )
        current_ingress_rule_list.append(
            SgRuleIngress(
                cidrs,
                ipv6_cidrs,
                from_port,
                to_port,
                protocol,
                other_security_groups,
                list(prefix_list_id)
            )
        )
    return (current_ingress_rule_list)
# get the current egress rules for security groups that exists
def currentEgressRule(sg):
    sg_response = client.describe_security_groups(GroupIds=[sg])
    print (sg_response)
    current_egress_rule_list = []
    for permission_set in sg_response['SecurityGroups'][0]['IpPermissionsEgress']:
        protocol = permission_set["IpProtocol"]
        from_port = permission_set.get("FromPort")
        to_port = permission_set.get("ToPort")
        cidrs = tuple(
            ip_range["CidrIp"]
            for ip_range in permission_set.get("IpRanges", [])
        )
        ipv6_cidrs = tuple(
            ip_range["CidrIpv6"]
            for ip_range in permission_set.get("Ipv6Ranges", [])
        )
        other_security_groups = tuple(
            extract_other_security_group(group)
            for group in permission_set.get("UserIdGroupPairs", [])
        )
        prefix_list_id = tuple(
            extract_prefix_list_id(group)
            for group in permission_set.get("PrefixListIds", [])
        )
        current_egress_rule_list.append(
            SgRuleIngress(
                cidrs,
                ipv6_cidrs,
                from_port,
                to_port,
                protocol,
                other_security_groups,
                list(prefix_list_id)
            )
        )
    return (current_egress_rule_list)
# create a security group in the vpc if there is no pipeline-managed sg
def create_pipeline_managed_security_groups(vpc):
    response = client.create_security_group(
        Description="Pipeline_Managed_SG",
        GroupName="Pipeline_Managed_SG",
        VpcId=vpc,
        TagSpecifications=[{
            'ResourceType': 'security-group',
            'Tags': [{
                'Key': 'pipeline-managed',
                'Value': 'true'
            }]
        }]
    )
    return (response['GroupId'])  # Return newly created security group ID
def get_vpc_id(vpc_list_result):
    vpc_list = client.describe_vpcs()
    vpc_id_list_all = []
    for id in vpc_list['Vpcs']:
        vpc_id_list_all.append(id['VpcId'])
    missing_vpc_list = vpc_id_list_all
    for vpc in vpc_list_result:
        missing_vpc_list.remove(vpc)
    return missing_vpc_list
# describe sg's that are pipeline managed
def describe_pipeline_managed_security_groups(sg_response):
    sg_id = sg_response['SecurityGroups']
    sg_id_list = []
    vpc_id_list = []
    for sg in sg_id:
        if 'Tags' in sg.keys():
            for tags in sg['Tags']:
                if tags['Key'] == 'pipeline-managed':
                    sg_id_list.append(sg['GroupId'])
                    if sg['VpcId'] not in vpc_id_list:
                        vpc_id_list.append(sg['VpcId'])
        else:
            continue
    return sg_id_list, vpc_id_list

def lambda_handler(event, context):
    csvParser()
    try:
        sg_response = client.describe_security_groups()
        sg_list_result, vpc_list_result = describe_pipeline_managed_security_groups(sg_response)
        missing_vpc_list = get_vpc_id(vpc_list_result)
        if missing_vpc_list:
            for vpc in missing_vpc_list:
                sg = create_pipeline_managed_security_groups(vpc)  # This is adding new SG to the list of SG
                sg_list_result.append(sg)

        for sg in sg_list_result:
            current_ingress_rule_list = currentIngressRule(sg)  # Rules from the current security groups that have the tag pipeline-managed
            current_egress_rule_list = currentEgressRule(sg)
            compareSecurityGroupIngressRules(sg, current_ingress_rule_list, Ingress_Rules)
            compareSecurityGroupEgressRules(sg, current_egress_rule_list, Egress_Rules)
        cfnr.send(event, context, cfnr.SUCCESS, responseData)
    except Exception as e:
        logger.error('Something went wrong: ' + str(e))
        cfnr.send(event, context, cfnr.FAILED, responseData)
        return False