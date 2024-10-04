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

# Now the `config` dictionary has the actual environment variables injected
print(config)

SUBSCRIPTION_ID = config['subscription_id']
RESOURCE_GROUP_NAME = config['resource_group_name']
PROXIMITY_PLACEMENT_GROUP_NAME = config['proximity_placement_group_name']
USERNAME = config['username']
VM_SIZE = config['vm_size']
NUM_VMS = config['num_vms']
LOCATION = config['location']
ZONE = config['zone']
NSG_NAME = config['nsg_name']
VNET_NAME = config['vnet_name']
SUBNET_NAME = config['subnet_name']
INTERFACE_NAME = config['interface_name']
PRIVATE_KEY_PATH = config['ssh_key_path']
SCRIPT_PATH = config['install_script_path']
vm_ip_data = {}


resource_client = ResourceManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

print(f"Creating Resource Group: {RESOURCE_GROUP_NAME}")
# Create resource group
resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {'location': LOCATION})
print(f"Resource Group created: {RESOURCE_GROUP_NAME}")

print(f"Creating Proximity Placement Group: {PROXIMITY_PLACEMENT_GROUP_NAME}")
# Create PPG
ppg_params = ProximityPlacementGroup(
    location=LOCATION,
    proximity_placement_group_type='Standard',
)
compute_client.proximity_placement_groups.create_or_update(RESOURCE_GROUP_NAME, PROXIMITY_PLACEMENT_GROUP_NAME, ppg_params)
print(f"Proximity Placement Group created: {PROXIMITY_PLACEMENT_GROUP_NAME}")

print(f"Creating Network Security Group: {NSG_NAME}")
nsg_params = NetworkSecurityGroup(location=LOCATION)
nsg_result = network_client.network_security_groups.begin_create_or_update(
    RESOURCE_GROUP_NAME, 
    NSG_NAME, 
    nsg_params
).result()

print(f"Network Security Group with rules created: {NSG_NAME}")

# Define inbound SSH rule (Allow SSH on port 22)
ssh_rule_params = SecurityRule(
    protocol='Tcp',
    source_address_prefix='*',
    destination_address_prefix='*',
    access='Allow',
    direction='Inbound',
    source_port_range='*',
    destination_port_range='22', 
    priority=1000,
    name='Allow_SSH'
)

# Create the security rule in the NSG
nsg_rule_result = network_client.security_rules.begin_create_or_update(
    RESOURCE_GROUP_NAME, 
    NSG_NAME, 
    'Allow_SSH',
    ssh_rule_params
).result()

print("SSH rule added to NSG.")

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
        'address_prefix': '10.0.0.0/24',
        'network_security_group': {'id': nsg_result.id}
    }
).result()

print(f"Subnet created: {subnet_creation.id}")


# Create VMs
for i in range(NUM_VMS):
    vm_name = f"rollbaccineNum{i}"
    nic_name = f"{INTERFACE_NAME}_vm{i}"
    public_ip_name = f"{vm_name}_public_ip"

    print(f"Creating Public IP Address: {public_ip_name}")
    # Create Public IP Address
    public_ip_creation = network_client.public_ip_addresses.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        public_ip_name,
        {
            'location': LOCATION,
            'public_ip_allocation_method': 'Static',
            'sku': {
                'name': 'Standard'
            },
            'zones': [ZONE] 
        }
    ).result()
    print(f"Public IP Address created: {public_ip_creation.ip_address}")
    print(f"Creating Network Interface: {nic_name}")
    
    # Create Network Interface for this VM
    network_interface_creation = network_client.network_interfaces.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        nic_name,
        {
            'location': LOCATION,
            'ip_configurations': [{
                'name': 'ip_config',
                'subnet': {
                    'id': subnet_creation.id
                },
                'private_ip_allocation_method': 'Dynamic',
                'public_ip_address': {
                    'id': public_ip_creation.id
                }
            }]
        }
    ).result()
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
                    "id": network_interface_creation.id,
                    "properties": {
                        "primary": True
                    }
                }
            ]
    },
        "security_profile": {
            "security_type": "ConfidentialVM",
            "uefi_settings": {
                "secureBootEnabled": False,
                "vtpmEnabled": True
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

    # Fetch NIC and IP addresses
    nic = network_client.network_interfaces.get(RESOURCE_GROUP_NAME, nic_name)
    private_ip = nic.ip_configurations[0].private_ip_address
    
    # Fetch the public IP address object to retrieve the IP
    public_ip = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, public_ip_name).ip_address

    # Store VM's public and private IP in the dictionary
    vm_ip_data[vm_name] = {
        "public_ip": public_ip,
        "private_ip": private_ip
    }

    print(f"Created VM: {vm_name}")

# Save the data to a JSON file
with open('vm_ips.json', 'w') as json_file:
    json.dump(vm_ip_data, json_file, indent=4)

print("Public and Private IPs saved to vm_ips.json")



