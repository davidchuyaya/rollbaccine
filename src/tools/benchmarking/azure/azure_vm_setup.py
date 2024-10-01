import json
import paramiko
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import ProximityPlacementGroup, DiskCreateOptionTypes, NetworkInterfaceReference, SecurityProfile, ImageReference, OSProfile, LinuxConfiguration, SshConfiguration, SshPublicKey


load_dotenv()
print(os.getenv('SSH_KEY'))
SUBSCRIPTION_ID = os.getenv('SUBSCRIPTION_ID')# Initialize clients

resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

RESOURCE_GROUP_NAME = 'rollbaccine_adit'
PROXIMITY_PLACEMENT_GROUP_NAME = 'rollbaccine_placement_group'
USERNAME = 'adit'
VM_SIZE = 'Standard_DC16ads_v5'
NUM_VMS = 2
LOCATION = "northeurope"
ZONE = 3
VNET_NAME = f"{RESOURCE_GROUP_NAME}_vnet"
SUBNET_NAME = f"{RESOURCE_GROUP_NAME}_subnet"
INTERFACE_NAME = f"{RESOURCE_GROUP_NAME}_interface"

print(f"Creating Resource Group: {RESOURCE_GROUP_NAME}")
# Create resource group
resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {'location': LOCATION})
print(f"Resource Group created: {RESOURCE_GROUP_NAME}")

print(f"Creating Proximity Placement Group: {PROXIMITY_PLACEMENT_GROUP_NAME}")
# Create PPG
ppg_params = ProximityPlacementGroup(location=LOCATION, proximity_placement_group_type='Standard')
compute_client.proximity_placement_groups.create_or_update(RESOURCE_GROUP_NAME, PROXIMITY_PLACEMENT_GROUP_NAME, ppg_params)
print(f"Proximity Placement Group created: {PROXIMITY_PLACEMENT_GROUP_NAME}")

print(f"Creating Virtual Network: {VNET_NAME}")
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

print(f"Virtual Network created: {vnet_creation.id}")

print(f"Creating Subnet: {SUBNET_NAME}")

# Create subnet
subnet_creation = network_client.subnets.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    VNET_NAME,
    SUBNET_NAME,
    {
        'address_prefix': '10.0.0.0/24'
    }
).result()

print(f"Subnet created: {subnet_creation.id}")

# Create Network Interface (Ensure this step happens before VM creation)
print(f"Creating Network Interface: {INTERFACE_NAME}")

# Create Network Interface
network_interface_creation = network_client.network_interfaces.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    INTERFACE_NAME,
    {
        'location': LOCATION,
        'ip_configurations': [{
            'name': 'ip_config',
            'subnet': {
                'id': subnet_creation.id
            },
            'private_ip_allocation_method': 'Dynamic'
        }]
    } 
).result()

print(f"Network Interface created: {network_interface_creation.id}")


# Create VMs
for i in range(NUM_VMS):
    vm_name = f"rollbaccineNum{i}"
    print(f"Creating VM: {vm_name}")
    
    # VM parameters
    vm_parameters = {
        "location": LOCATION,
        "hardware_profile": {
            "vm_size": VM_SIZE
        },
        "storage_profile": {
            "image_reference": ImageReference(
                publisher="Canonical",
                offer="ubuntu-24_04-lts",
                sku="cvm",
                version="latest"
            ),
            "os_disk": {
                "create_option": DiskCreateOptionTypes.FROM_IMAGE,
                "delete_option": "Delete",
                "managed_disk": {
                    "security_profile": {
                        "security_encryption_type": "VMGuestStateOnly"  # Ensure that encryption type is set for the managed disk
                    }
                }
            }
        },
        "os_profile": OSProfile(
            computer_name=vm_name,
            admin_username=USERNAME,
            linux_configuration=LinuxConfiguration(
                disable_password_authentication=True,
                ssh=SshConfiguration(
                    public_keys=[
                        SshPublicKey(
                            path=f"/home/{USERNAME}/.ssh/authorized_keys",
                            key_data=os.getenv('SSH_KEY')  # Public key from env var
                        )
                    ]
                )
            )
        ),
        "networkProfile": {
            "networkInterfaces": [
                {
                    "id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Network/networkInterfaces/{INTERFACE_NAME}",
                    "properties": {
                        "primary": True
                    }
                }
            ]
    },
        "security_profile": {
            "security_type": "ConfidentialVM",
            "uefi_settings": {
                "secureBootEnabled": False,  # Adjust based on your needs
                "vtpmEnabled": True  # This must be true for VMGuestStateOnly
            }
        },
        "zones": [ZONE],
        "proximity_placement_group": {
            "id": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Compute/proximityPlacementGroups/{PROXIMITY_PLACEMENT_GROUP_NAME}"
        }
    }

    # Create the VM
    creation_result = compute_client.virtual_machines.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        vm_name,
        vm_parameters
    ).result()

    print(f"Created VM: {vm_name}")
    
# Run setup script on VM using SSH and Paramiko