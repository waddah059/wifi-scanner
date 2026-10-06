import subprocess
import socket
import re
import platform
import netifaces
from typing import List, Dict, Optional
import psutil

class NetworkScanner:
    def __init__(self):
        self.system = platform.system()
        
    def get_local_network_info(self) -> Dict:
        """Get local network interface and subnet"""
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface.startswith(('lo', 'docker', 'veth')):
                continue
                
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and addr['addr'] != '127.0.0.1':
                        netmask = addr.get('netmask', '255.255.255.0')
                        # Calculate network address
                        ip_parts = addr['addr'].split('.')
                        mask_parts = netmask.split('.')
                        network_parts = []
                        for i in range(4):
                            network_parts.append(str(int(ip_parts[i]) & int(mask_parts[i])))
                        network = '.'.join(network_parts)
                        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        
                        return {
                            'interface': interface,
                            'ip': addr['addr'],
                            'netmask': netmask,
                            'network': f"{network}/{cidr}"
                        }
        return {'network': '192.168.1.0/24'}  # Fallback
    
    def scan_nmap(self, network_range: str = None) -> List[Dict]:
        """Scan network using Nmap"""
        try:
            import nmap
        except ImportError:
            print("Python-nmap not installed. Installing...")
            subprocess.check_call(['pip', 'install', 'python-nmap'])
            import nmap
            
        if not network_range:
            network_info = self.get_local_network_info()
            network_range = network_info['network']
            
        nm = nmap.PortScanner()
        
        # Quick ping scan to discover hosts
        nm.scan(hosts=network_range, arguments='-sn -T4')
        
        devices = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                device_info = {
                    'ip': host,
                    'mac': nm[host]['addresses'].get('mac', 'Unknown'),
                    'hostname': nm[host].hostname() if hasattr(nm[host], 'hostname') else 'Unknown',
                    'vendor': nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown'),
                    'status': nm[host].state()
                }
                
                # Try to get hostname via reverse DNS
                if device_info['hostname'] == 'Unknown':
                    try:
                        device_info['hostname'] = socket.gethostbyaddr(host)[0]
                    except (socket.herror, socket.gaierror):
                        pass
                
                devices.append(device_info)
                
        return devices
    
    def scan_arp(self) -> List[Dict]:
        """Scan using ARP requests (requires root/admin privileges)"""
        try:
            from scapy.all import ARP, Ether, srp
            import scapy.all as scapy
        except ImportError:
            print("Scapy not installed. Using alternative method...")
            return self.scan_arp_command()
            
        network_info = self.get_local_network_info()
        ip_range = network_info['network']
        
        # Create ARP request
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet and get responses
        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': 'Unknown',
                'vendor': 'Unknown',
                'status': 'up'
            })
            
        # Try to get hostnames
        for device in devices:
            try:
                hostname = socket.gethostbyaddr(device['ip'])[0]
                device['hostname'] = hostname
            except (socket.herror, socket.gaierror):
                pass
                
        return devices
    
    def scan_arp_command(self) -> List[Dict]:
        """Use system ARP command as fallback"""
        devices = []
        
        try:
            if self.system == "Windows":
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
                lines = output.split('\n')
                for line in lines:
                    if 'dynamic' in line.lower() or 'static' in line.lower():
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1]
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'hostname': 'Unknown',
                                'vendor': 'Unknown',
                                'status': 'up'
                            })
            else:  # Linux/Mac
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
                lines = output.split('\n')
                for line in lines:
                    if '(' in line and ')' in line:
                        # Extract IP from between parentheses
                        ip_start = line.find('(') + 1
                        ip_end = line.find(')')
                        ip = line[ip_start:ip_end]
                        
                        # Extract MAC (usually after "at")
                        if 'at' in line:
                            mac_start = line.find('at ') + 3
                            mac_end = line.find(' ', mac_start)
                            if mac_end == -1:
                                mac_end = len(line)
                            mac = line[mac_start:mac_end]
                            
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'hostname': 'Unknown',
                                'vendor': 'Unknown',
                                'status': 'up'
                            })
        except Exception as e:
            print(f"ARP command failed: {e}")
            
        return devices
    
    def get_connected_devices(self, method: str = 'nmap') -> List[Dict]:
        """Get all connected devices"""
        try:
            if method == 'nmap':
                return self.scan_nmap()
            elif method == 'arp':
                return self.scan_arp()
            else:
                # Try both methods
                devices = self.scan_nmap()
                if not devices:
                    devices = self.scan_arp()
                return devices
        except Exception as e:
            print(f"Scan error: {e}")
            return []