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
SUBSCRIPTION_ID = os.getenv('SUBSCRIPTION_ID')

resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

RESOURCE_GROUP_NAME = 'rollbaccine_adit'
PROXIMITY_PLACEMENT_GROUP_NAME = 'rollbaccine_placement_group'
USERNAME = 'adit'
VM_SIZE = 'Standard_DC16ads_v5'
NUM_VMS = 3
LOCATION = "eastus"
ZONE = 2
NSG_NAME = f"{RESOURCE_GROUP_NAME}_nsg"
VNET_NAME = f"{RESOURCE_GROUP_NAME}_vnet"
SUBNET_NAME = f"{RESOURCE_GROUP_NAME}_subnet"
INTERFACE_NAME = f"{RESOURCE_GROUP_NAME}_interface"

def delete_resources():
    # Check and delete Virtual Machines
    vms = compute_client.virtual_machines.list(resource_group_name=RESOURCE_GROUP_NAME)
    for vm in vms:
        print(f"Deleting VM: {vm.name}")
        compute_client.virtual_machines.begin_delete(RESOURCE_GROUP_NAME, vm.name).wait()
        print(f"Deleted VM: {vm.name}")
    print("Disassociating Public IPs from Network Interfaces")
    for nic in network_client.network_interfaces.list(RESOURCE_GROUP_NAME):
        nic_config = network_client.network_interfaces.get(RESOURCE_GROUP_NAME, nic.name)
        for ip_config in nic_config.ip_configurations:
            if ip_config.public_ip_address is not None:
                ip_config.public_ip_address = None
        network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME, nic.name, nic_config).result()
    # Delete Public IPS
    print(f"Deleting public IPs")
    for public_ip in network_client.public_ip_addresses.list(RESOURCE_GROUP_NAME):
        network_client.public_ip_addresses.begin_delete(RESOURCE_GROUP_NAME, public_ip.name).result()
    # Delete Network Interfaces
    print(f"Deleting network interface: {INTERFACE_NAME}")
    for nic in network_client.network_interfaces.list(RESOURCE_GROUP_NAME):
        network_client.network_interfaces.begin_delete(RESOURCE_GROUP_NAME, nic.name).result()
    # Delete Subnet
    print(f"Deleting subnet: {SUBNET_NAME}")
    network_client.subnets.begin_delete(RESOURCE_GROUP_NAME, VNET_NAME, SUBNET_NAME).result()

    # Delete VNet
    print(f"Deleting VNet: {VNET_NAME}")
    network_client.virtual_networks.begin_delete(RESOURCE_GROUP_NAME, VNET_NAME).result()

    # Delete Network Security Group
    print(f"Deleting Network Security Group: {NSG_NAME}")
    network_client.network_security_groups.begin_delete(RESOURCE_GROUP_NAME, NSG_NAME).result()

    # Delete Proximity Placement Group
    print(f"Deleting Proximity Placement Group: {PROXIMITY_PLACEMENT_GROUP_NAME}")
    compute_client.proximity_placement_groups.delete(RESOURCE_GROUP_NAME, PROXIMITY_PLACEMENT_GROUP_NAME)

    # Delete Resource Group
    print(f"Deleting Resource Group: {RESOURCE_GROUP_NAME}")
    resource_client.resource_groups.begin_delete(RESOURCE_GROUP_NAME).result()

    print("All resources deleted successfully.")
delete_resources()