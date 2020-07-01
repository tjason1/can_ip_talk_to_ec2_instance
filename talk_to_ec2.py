import boto3
import botocore
from netaddr import IPNetwork, IPAddress

def validate_instance(id):
    "Examines a string and determines if it is a valid ec2 instance id"

    is_instance = True
    if id[0:3] != 'i-0':
        is_instance = False
    if len(id) != 19:
        is_instance = False
    
    return is_instance

def instance_sgs(id):
    "Given an instance ID, return a list of security group ID's that are associated with it"

    i = ec2.Instance(id)
    security_groups = i.security_groups
    sg_ids = []

    for group in security_groups:
        sg_ids.append(group.get('GroupId'))

    return (sg_ids)

def check_sg(port,protocol,group_ids): #(ip,port,protocol,group_ids,id):
    "Examines a list of security groups to determine if the given traffic flow is allowed by it"

    security_group = ec2.SecurityGroup(id)
    permissions = []
    port_match = False
    protocol_match = False
    ip_match = False
    matching_sgs =[]
    security_group_permitted = False
    traffic_permitted = False

    for sg in group_ids:
        security_group = ec2.SecurityGroup(sg)
        permissions = security_group.ip_permissions
        print('Testing Security Group {0} "{1}"...'.format(security_group.id,security_group.group_name))
        for rule in permissions:
            port_match = compare_port(port,protocol,rule)
            protocol_match = compare_protocol(protocol,rule)
            ip_match = compare_ip(ip,rule)
            if (port_match and protocol_match and ip_match):
                traffic_permitted = True
                security_group_permitted = True
        if security_group_permitted == True:
            print ('    Match found for rule in Security Group {0}\n'.format(security_group.id))
            matching_sgs.append(security_group.id)
            security_group_permitted = False
        else:
            print ('    No match found in Security Group {0}\n'.format(security_group.id))

    return traffic_permitted, matching_sgs

def compare_port(port,protocol,rule):

    "Returns True if the input port is allowed by the security group rule"

    rule_port_match = False

    if rule.get('IpProtocol') == '-1':
        #print('All ports allowed')
        rule_port_match = True
    elif ((int(rule.get('ToPort'))) - (int(rule.get('FromPort')))) == 0:
        #print('Rule port number: ',(rule.get('FromPort')))
        if (str(rule.get('FromPort'))) == port:
            rule_port_match = True
    else:
        #print('Rule port range of {0} to {1}'.format((int(rule.get('FromPort'))), (int(rule.get('ToPort')))))
        for number in range((int(rule.get('FromPort'))), (int(rule.get('ToPort')))):
            if str(number) == port:
                rule_port_match = True

    #print('rule port match: ', rule_port_match)
    return rule_port_match

def compare_protocol(protocol,rule):

    "Returns True if the input protocol is allowed by the security group rule"

    rule_protocol_match = False

    if rule.get('IpProtocol') == '-1':
    	rule_protocol_match = True
    else:
        if rule.get('IpProtocol') == protocol:
            rule_protocol_match = True

    #print('rule protocol match: ', rule_protocol_match)

    return(rule_protocol_match)

def compare_ip(ip,rule):

    "Returns True if the input IP address is allowed by the security group rule"

    rule_ip_match = False
    cidr_networks = []

    for range in (rule.get('IpRanges')):
	    cidr_networks.append(range.get('CidrIp'))

    for range in cidr_networks:
        if IPAddress(ip) in IPNetwork(range):
            rule_ip_match = True

    #print ('rule ip match: ',rule_ip_match)

    return (rule_ip_match)

session = boto3.Session(profile_name='pa')
ec2 = session.resource('ec2')    

### Main Program Logic ####

if __name__ == '__main__':
    ip = input ('Please enter the source IP address: ')
    id = input("Please enter the instance ID of the destination: ")
    is_valid_id = validate_instance(id)
    if is_valid_id == False:
        print ('\nThat is not a valid instance id\n')
        exit()
    port = input("Please enter the destination port number: ")
    protocol = input("Please enter the protocol in use - tcp, udp, or icmp: ")
    print ('\n')
    group_ids = instance_sgs(id)

    is_in_sg = check_sg(port,protocol,group_ids)

    if is_in_sg[0] == False:
        print ('\nNo rule allowing the entered flow was found in the security group')
    else:
        print ('\n\nThe follwing security group(s) had rules allowing the entered flow: \n{0}\n\n'.format(', '.join(is_in_sg[1])))  

