import wmi
import time
import random
import socket
import ssl
from paramiko import SSHClient, AutoAddPolicy

# Function to create a virtual machine
def create_virtual_machine(name, memory_mb, vhd_path, iso_path):
    conn = wmi.WMI(namespace="root/virtualization/v2")

    vhd_disk = conn.Msvm_VirtualHardDiskSettingData.new()
    vhd_disk.BlockSize = 0
    vhd_disk.MaximumSize = 40 * 1024 * 1024 * 1024  # 40GB
    vhd_disk.Path = vhd_path
    vhd_disk.Type = 3  # Dynamic expanding

    vm = conn.Msvm_VirtualSystemSettingData.new()
    vm.ElementName = name
    vm.VirtualSystemType = "Microsoft:Hyper-V:System:Realized"

    memory = conn.Msvm_MemorySettingData.new()
    memory.VirtualQuantity = memory_mb
    memory.Limit = memory_mb
    memory.Reservation = memory_mb

    ide_controller = conn.Msvm_ResourceAllocationSettingData.new()
    ide_controller.ResourceType = 5  # IDE Controller
    ide_controller.Address = "0"

    dvd_drive = conn.Msvm_ResourceAllocationSettingData.new()
    dvd_drive.ResourceType = 16  # DVD Drive
    dvd_drive.Parent = ide_controller.path
    dvd_drive.Address = "0"
    dvd_drive.Connection = [iso_path]

    vhd_drive = conn.Msvm_ResourceAllocationSettingData.new()
    vhd_drive.ResourceType = 21  # Hard Disk
    vhd_drive.Parent = ide_controller.path
    vhd_drive.Address = "1"
    vhd_drive.Connection = [vhd_path]

    vm_service = conn.Msvm_VirtualSystemManagementService()[0]
    result = vm_service.DefineSystem(SystemSettings=vm.GetText_(1), ResourceSettings=[memory.GetText_(1), ide_controller.GetText_(1), dvd_drive.GetText_(1), vhd_drive.GetText_(1)])
    if result[0].ReturnValue != 0:
        raise Exception("Failed to create virtual machine")

    print(f"Virtual machine '{name}' created successfully!")

# Function to get the IP address of a virtual machine
def get_vm_ip_address(vm_name):
    conn = wmi.WMI(namespace="root/virtualization/v2")
    
    vm = None
    for v in conn.Msvm_ComputerSystem(ElementName=vm_name):
        vm = v
        break

    if not vm:
        raise Exception(f"Virtual machine '{vm_name}' not found.")

    nic_settings = conn.query(f"Associators of {{Msvm_ComputerSystem.InstanceID='{vm.InstanceID}'}} "
                              f"Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_SyntheticEthernetPortSettingData")

    for nic in nic_settings:
        ip_addresses = conn.query(f"Associators of {{Msvm_SyntheticEthernetPortSettingData.InstanceID='{nic.InstanceID}'}} "
                                  f"Where AssocClass=Msvm_BindsToLANEndpoint ResultClass=Msvm_LANEndpoint")

        for ip in ip_addresses:
            ip_info = conn.query(f"Associators of {{Msvm_LANEndpoint.InstanceID='{ip.InstanceID}'}} "
                                 f"Where AssocClass=Msvm_ActiveConnection ResultClass=Msvm_KvpExchangeComponent")

            for info in ip_info:
                if hasattr(info, 'GuestIntrinsicExchangeItems'):
                    kvp_data = info.GuestIntrinsicExchangeItems
                    for item in kvp_data:
                        if "IPAddress" in item:
                            ip_address = item.split("=")[1].strip('"')
                            return ip_address

    return None

# Function to get the local IP address
def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    finally:
        sock.close()
    
    return local_ip

# Function to connect to a VM via SSH using a key file
def ssh_connect(ip_address, username, password, command):
    try:
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        ssh.connect(ip_address, username=username, password=password)

        stdin, stdout, stderr = ssh.exec_command(command)
        print("Output:", stdout.read().decode())
        print("Errors:", stderr.read().decode())

        ssh.close()

    except Exception as e:
        print(f"Error connecting to {ip_address}: {e}")

# Function to install Tor on a VM
def install_tor_on_vm(ip, username, password):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(ip, username=username, password=password)


    commands = [
        "sudo apt-get update",
        "sudo apt-get install -y tor",
        "sudo service tor start"
    ]

    for cmd in commands:
        stdin, stdout, stderr = client.exec_command(cmd)
        print(stdout.read().decode())
        print(stderr.read().decode())

    client.close()

# Function to set up port forwarding on a VM
def setup_port_forwarding(ip_address, username, password, host_ip):
    try:
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(ip_address, username=username, password=password)

        commands = [
            f"sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination {host_ip}:80",
            f"sudo iptables -t nat -A POSTROUTING -p tcp -d {host_ip} --dport 80 -j MASQUERADE",
            f"sudo iptables -A FORWARD -p tcp -d {host_ip} --dport 80 -j ACCEPT",
            "sudo apt-get install -y iptables-persistent",
            "sudo netfilter-persistent save"
        ]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            print("Output:", stdout.read().decode())
            print("Errors:", stderr.read().decode())

        ssh.close()

    except Exception as e:
        print(f"Error setting up port forwarding: {e}")

# Function to create an SSL connection
def create_ssl_connection(host, port):
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(sock, server_hostname=host)
    ssl_sock.connect((host, port))
    return ssl_sock

# Function to send a request through a chain of proxies
def send_request(proxy_list, target_host, target_port, request):
    for proxy in proxy_list:
        print(f"Connecting to proxy: {proxy['host']}:{proxy['port']}")
        sock = create_ssl_connection(proxy['host'], proxy['port'])
        sock.sendall(request.encode())
        response = sock.recv(4096)
        request = response.decode()
    return request

def main():
    while True:
        user = input("IAP> ")
        if user == "enable":
            print("ENABLING : Creating VMs...")
            # Create 15 virtual machines
            for i in range(1, 16):
                create_virtual_machine(f"VM{i}", 2048, f"./VM{i}.vhdx", "./ubuntu-24.04.1-live-server-amd64.iso")
                print(f"Created VM{i}")
                
            print("ENABLING : Getting VMs' IPs...")
            ips = {}
            for j in range(1, 16):
                ip = get_vm_ip_address(f"VM{j}")
                ips[ip] = f"VM{j}"
                
            print("ENABLING : Doing SSH on VMs and installing Tor on them")
            time.sleep(0.4)
            username = "username"
            password = "password"
            print(f"Doing SSH to VMs...")
            for ip, vm in ips.items():
                install_tor_on_vm(ip, username, password)
                
            print("ENABLING : Creating Orwell router...")
            router_ip = random.choice(list(ips.keys()))
            ssh_connect(router_ip, username, password, "sudo apt-get update && sudo apt-get install -y frr && sudo systemctl enable frr && sudo systemctl start frr")
            time.sleep(0.5)
            print("ENABLING : Setting up port forwarding...")
            setup_port_forwarding(router_ip, username, password, get_local_ip())

if __name__ == "__main__":
    main()