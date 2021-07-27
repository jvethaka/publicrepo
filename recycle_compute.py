#!/usr/bin/python3
#This script will run from new Jump server only


import subprocess
import boto3
import json
import logging


logging.basicConfig(filename='app.log', filemode='a+',format='%(asctime)s - %(message)s', level=logging.INFO)
flag = False
ip_region = " "
trop_ip = " "
instance_id = ""
nodes_to_enable = []
def set_trop_ip(region):
    command= "cat /home/ec2-user/efs/scripts/ssh/.ssh.cache | grep "+region+" | grep tropmgr"
    #print(command)
    ip = subprocess.check_output(command,shell=True,text=True)
    ip = ip.split(" ")[2]
    return ip
def command_run(command_input,output_flag):
    result = " "
    if output_flag == 1:
        result = subprocess.run(['bash','test.sh',ip_region,trop_ip,command_input],capture_output=True,text=True)
    elif output_flag == 0:
        subprocess.run(['bash','test.sh',ip_region,trop_ip,command_input])
    return result

def getnodeset(nodeip):
    command_output = "./tropmgr swarm node status "+nodeip+" | grep -i 'node set'"
    nodeset = command_run(command_output,1)
    nodeset = nodeset.stdout.split(":")[1].strip()
    print(f'nodeset is : {nodeset}')
    logging.info(f'nodeset is : {nodeset}')
    return nodeset
def get_users_app_count(nodeset,nodeip):
    command_output = "./tropmgr service status -n "+nodeset+" | grep "+nodeip+"| wc -l"
    user_count =  command_run(command_output,1)
    return int(user_count.stdout)
def node_reallocate(nodeset,nodeip):
    reallocate_output = ""
    user_apps_count = get_users_app_count(nodeset,nodeip)
    #print(user_apps_count)
    node_disable(nodeip)
    if user_apps_count > 0:
        print(f'The user apps are: {user_apps_count}')
        logging.info(f'The user apps before reallocation are: {user_apps_count}')
        command_output = "./tropmgr swarm node reallocate "+nodeip+" "
        proc = Popen(['bash','test.sh',ip_region,trop_ip,command_output], stdout=PIPE, encoding='utf-8')
        while proc.poll() is None:
            text = proc.stdout.readline()
            sys.stdout.write(text)
            reallocate_output = reallocate_output + text
            #sys.stdout.write(text)
        logging.info(reallocate_output[-500:])
        if "Reallocate success without error" in reallocate_output:
            user_apps_count = get_users_app_count(nodeset,nodeip)
            print(f'The user apps are: {user_apps_count}')
            logging.info(f'The user apps after reallocation are: {user_apps_count}')
            flag = True
        else:
            node_enable(nodeip)
            print("error with reallocate , please proceed with manual approach")
    else:
        print(f'The user apps are: {user_apps_count}')
        logging.info(f'The user apps are: {user_apps_count} ,good to go for termination')
        flag = True
    return flag
def instance_scale_in(asg,instance_id):
    subprocess.check_call("aws autoscaling set-instance-protection --auto-scaling-group-name "+asg+" --instance-ids "+instance_id+" --no-protected-from-scale-in",shell=True)

def node_enable(nodeip):
    command_enable =  "./tropmgr swarm node enable "+nodeip+" "
    subprocess.run(['bash','test.sh',ip_region,trop_ip,command_enable])

def instance_terminate(instance_id):
    subprocess.check_call("aws ec2 terminate-instances --instance-ids "+ instance_id+"",shell=True)

def node_disable(nodeip):
    command_disable =  "./tropmgr swarm node disable "+nodeip+" "
    subprocess.run(['bash','test.sh',ip_region,trop_ip,command_disable])

def main_func():
    global ip_region
    global trop_ip
    choice = " "
    key_list = set()
    ip_list = []
    old_ami = ""
    old_ami_us = "ami-ba7e89c2"+","+"ami-4e914836"+","+"ami-7353ef0b"+","+"ami-04f1bdcd926794d2a"+","+"ami-0b2428295c4226b58"
    old_ami_eu = "ami-f3eb598a"+","+"ami-968ce8ef"+","+"ami-6c844215"+","+"ami-04a13d4b664580631"+","+"ami-022169e8e47564ede"
    old_ami_ap = "ami-07ca2e65"+","+"ami-19ce3b7b"+","+"ami-7fd52b1d"+","+"ami-045d985a659cb3b3e"+","+"ami-00cc9b22f00f6a649"
    ec2 = boto3.client("ec2")
    region = subprocess.check_output("aws configure get region",shell=True,text=True)
    region = region.strip()
    print(region)
    if region == "us-west-2":
        old_ami = old_ami_us
    elif region == "eu-west-1":
        old_ami = old_ami_eu
    elif region == "ap-southeast-2":
        old_ami = old_ami_ap
    try:
        instance_data = subprocess.check_output("aws ec2 describe-instances --filter 'Name=image-id ,Values="+old_ami+"'  --query 'Reservations[*].Instances[*].{IpAddress:PrivateIpAddress,Name:Tags[?Key==`Name`].Value}' --output json",shell=True)
        data = json.loads(instance_data)
        for data1 in data:
            count = 0
            for data2 in data1:
                if (data2['Name'][0].find("Compute") != -1):
                    key_list.update(data2['Name'])
        for key in key_list:
            count = count+1
            print(f'{count} : {key}')
        choice = input(" Please select the instance name\n")
        for data1 in data:
            count = 0
            for data2 in data1:
                if (data2['Name'][0] == choice):
                    ip_list.append(data2['IpAddress'])
        print(f'The instance count running for {choice} are : {len(ip_list)}')
        logging.info(f'The instance count running for {choice} are : {len(ip_list)}')
        batch_count = input("Please enter count of instances you want to procced, Press Enter to proceed with all \n")
        if not batch_count:
            batch_count= len(ip_list)
        print(f'Proceding with {choice} and instance count {batch_count}')
        logging.info(f'Proceding with {choice} and instance count {batch_count}')
        batch_count = int(batch_count)
        for ip in ip_list:
            ip = ip.strip()
            print(ip)
            logging.info(f'IP address is : {ip}')
            #aws:autoscaling:groupName
            response = ec2.describe_instances(Filters=[
                    {
                    'Name': 'private-ip-address',
                    'Values': [
                        ip,
                    ]}])
            for instances in response['Reservations']:
                for key in instances['Instances']:
                    instance_id = key['InstanceId']
                    for tags in key['Tags']:
                        if tags['Key'] == 'aws:autoscaling:groupName':
                            asg = tags['Value']
            print(f'Instance id is : {instance_id}')
            logging.info(f'Instance id is : {instance_id}')
            print(f'Autoscaling group name: {asg}')
            logging.info(f'Autoscaling group name: {asg}')
            trop_ip = set_trop_ip(region)
            print(f'tropmgr ip is: {trop_ip}')
            ip_region = region.split("-")[0]
            nodeset = getnodeset(ip)
            flag = node_reallocate(nodeset,ip)
            if flag == True:
                instance_scale_in(asg,instance_id)
                instance_terminate(instance_id)
                node_enable(ip)
            batch_count = batch_count-1
            if batch_count == 0:
                break
    except Exception as e:
        print(e)
main_func()