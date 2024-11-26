import json
import paramiko
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import ProximityPlacementGroup, DiskCreateOptionTypes, ImageReference, OSProfile, LinuxConfiguration, SshConfiguration, SshPublicKey
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule


load_dotenv()
username = os.getenv('AZURE_USERNAME')

with open('config.json') as config_file:
    config = json.load(config_file)

for key, value in config.items():
    if isinstance(value, str) and value.startswith("$"):
        env_var = value[1:]
        config[key] = os.getenv(env_var)
    if isinstance(value, str) and "{username}" in value:
        config[key] = value.replace("{username}", username)

SUBSCRIPTION_ID = config['subscription_id']
RESOURCE_GROUP_NAME = config['resource_group_name']

resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

def delete_resources():
    print(f"Deleting Resource Group: {RESOURCE_GROUP_NAME}")
    resource_client.resource_groups.begin_delete(RESOURCE_GROUP_NAME).result()

    print("All resources deleted successfully.")