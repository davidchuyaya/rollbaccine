import json
import paramiko
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

load_dotenv()
# Load paramaters
with open('config/vm_parameters.json') as f:
    vm_params = json.load(f)
with open('config/network_parameters.json') as f:
    network_params = json.load(f)
subscription_id = os.getenv('SUBSCRIPTION_ID')
print(subscription_id, "hello")
# Initialize clients
resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
# compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
# network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)

resource_group_name = 'rollbaccine_network'
location = vm_params['location']

resource_client.resource_groups.create_or_update(resource_group_name, {'location': location})

# # Create Virtual Network and Subnet
# vnet_params = {x
#     'location': location,
#     'address_space': {
#         'address_prefixes': [network_params['address_space']]
#     }
# }
# network_client.virtual_networks.begin_create_or_update(resource_group_name, network_params['vnet_name'], vnet_params).result()
# subnet_params = {'address_prefix': network_params['subnet_prefix']}
# subnet_info = network_client.subnets.begin_create_or_update(resource_group_name, network_params['vnet_name'], network_params['subnet_name'], subnet_params).result()

# # Create VMs
# for i in range(3):
#     vm_name = f"vm_{i}"
#     vm_parameters = vm_params.copy()
#     vm_parameters['os_profile']['computer_name'] = vm_name
#     vm_parameters['network_profile'] = {
#         'network_interfaces': [{'id': subnet_id}]
#     }
#     compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm_parameters).result()

# Run setup script on VM using SSH and Paramiko