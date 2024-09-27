import json
import paramiko
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import ProximityPlacementGroup
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

load_dotenv()
SUBSCRIPTION_ID = os.getenv('SUBSCRIPTION_ID')# Initialize clients

resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

RESOURCE_GROUP_NAME = 'rollbaccine_adit'
PPG_NAME = 'rollbaccine_placement_group'
USERNAME = 'admin'
VM_SIZE = 'Standard_DC16ads_v5'
NUM_VMS = 3
LOCATION = "northeurope"
VNET_NAME = f"{RESOURCE_GROUP_NAME}_vnet"
SUBNET_NAME = f"{RESOURCE_GROUP_NAME}_subnet"
INTERFACE_NAME = f"{RESOURCE_GROUP_NAME}_interface"

# Load paramaters
vm_params = {
    "location": LOCATION,
    "hardware_profile": {
        "vm_size": VM_SIZE
    },
    "storage_profile": {
        "image_reference": {
            "publisher": "Canonical",
            "offer": "UbuntuServer",
            "sku": "24_04-lts",
            "version": "latest"
        }
    },
    "os_profile": {
        "admin_username": "rollbaccine",
        "linux_configuration": {
            "disable_password_authentication": True,
            "ssh": {
                "public_keys": [{
                    "path": f"/home/{USERNAME}/.ssh/authorized_keys",
                    "key_data": f"{os.getenv('SSH_KEY')}"
                }]
            }
        }
    }
}

# Create resource group
resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {'location': LOCATION})

# Create PPG
ppg_params = ProximityPlacementGroup(location=LOCATION, proximity_placement_group_type='Standard')
compute_client.proximity_placement_groups.create_or_update(RESOURCE_GROUP_NAME, PPG_NAME, ppg_params)

# Create vnet
vnet_creation = network_client.virtual_networks.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    VNET_NAME,
    {
        'location': LOCATION,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16']
        }
    }
).result()

# Create subnet
subnet_creation = network_client.subnets.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    VNET_NAME,
    SUBNET_NAME,
    {
        'address_prefix': '10.0.0.0/24'
    }
).result()

# Create Network Interface
network_client.network_interfaces.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    INTERFACE_NAME,
    {
        'location': LOCATION,
        'ip_configurations': [{
            'name': 'ip_config',
            'subnet': {
                'id': subnet_creation.id
            }
        }]
    } 
).result()

# Create VMs
# for i in range(NUM_VMS):
#     vm_name = f"vm_{i}"
#     vm_parameters = vm_params.copy()
#     vm_parameters['os_profile']['computer_name'] = vm_name
#     # Create a network interface (NIC) for each VM
#     nic_name = f"{vm_name}_nic"
#     nic_params = {
#         'location': LOCATION,
#         'ip_configurations': [{
#             'name': f'{nic_name}_ip_config',
#             'subnet': {
#                 'id': f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/default"  # Replace with your VNet ID
#             }
#         }]
#     }
    
#     network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME, nic_name, nic_params)
#     network_interface_ids.append(f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Network/networkInterfaces/{nic_name}")

# Run setup script on VM using SSH and Paramiko