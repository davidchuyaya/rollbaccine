import json
import paramiko
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import ProximityPlacementGroup
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
compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)

RESOURCE_GROUP_NAME = 'rollbaccine_network'
PPG_NAME = 'rollbaccine_placement_group'
USERNAME = 'admin'
VM_SIZE = 'Standard_DC16ads_v5'
NUM_VMS = 2
LOCATION = vm_params['location']

resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {'location': LOCATION})

ppg_params = ProximityPlacementGroup(location=LOCATION, proximity_placement_group_type='Standard')
network_client.proximity_placement_groups.begin_create_or_update(RESOURCE_GROUP_NAME, PPG_NAME, ppg_params)

# # Create VMs
# for i in range(NUM_VMS):
#     vm_name = f"vm_{i}"
#     vm_parameters = vm_params.copy()
#     vm_parameters['os_profile']['computer_name'] = vm_name
#     vm_parameters['network_profile'] = {
#         'network_interfaces': [{'id': subnet_id}]
#     }
#     compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm_parameters).result()

# Run setup script on VM using SSH and Paramiko