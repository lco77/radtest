#!/usr/bin/env python3
"""
Cisco ISE Radius Authentication Test Script

This script tests Radius authentication against a Cisco ISE server by:
1. Creating a temporary network device in ISE using a local IP and a Radius secret
2. Reading test cases from a JSON input file
3. Sending Radius tests to the server and reporting results
4. Removing the temporary network device from ISE

Credentials can be provided via command line arguments or environment variables:
- ISE_URL: URL or IP of the ISE server (e.g., "https://ise.example.com")
- ISE_USERNAME: Username for API authentication
- ISE_PASSWORD: Password for API authentication

CAUTION: It doesn't work on Windows but you can use WSL as workaround
"""

import os
import re
import sys
import json
import socket
import argparse
import ipaddress
import logging

from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Any, Optional
import asyncio
import httpx
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import colorama
from colorama import Fore, Style
from urllib.parse import urlparse

# Initialize colorama for cross-platform colored output
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# CiscoISEClient
###############################################################################

@dataclass
class CiscoISENetworkDevice:
    name:str
    ip_address:str
    mask:int = 32
    id:str = None
    device_groups: list[str] = field(default_factory=[])
    description:str = "Network Device"
    key_input_format:str = "ASCII"
    radius_shared_secret:str = "RadiusTest123"
    enable_key_wrap:bool = False
    profile:str = "Cisco"
    network_protocol:str = "RADIUS"
    coa_port:int = 1700
    data:Any = None
    
    def to_api(self):
        return {
        "NetworkDevice": {
            "profileName": self.profile,
            "NetworkDeviceGroupList": self.device_groups,
            "name": self.name,
            "description": self.description,
            "authenticationSettings": {
                "keyInputFormat": self.key_input_format,
                "networkProtocol": self.network_protocol,
                "radiusSharedSecret": self.radius_shared_secret,
                "enableKeyWrap": self.enable_key_wrap
            },
            "coaPort": self.coa_port,
            "NetworkDeviceIPList": [
                    {
                        "ipaddress": self.ip_address,
                        "mask": self.mask
                    }
                ]
        }
    }

class CiscoISEClient:
    def __init__(self, host: str, username: str, password: str, verify: bool = False):
        self.base_url = f"https://{host}" if not host.startswith(('http://', 'https://')) else f"{host}"
        self.auth = (username, password)
        self.verify = verify
        self.client = None
        
    async def __aenter__(self):
        """Create client when used as context manager"""
        self.client = httpx.AsyncClient(
            auth=self.auth,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            verify=self.verify
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close client when exiting context manager"""
        if self.client:
            await self.client.aclose()

    def connect(self):
        self.client = httpx.AsyncClient(
            auth=self.auth,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            verify=self.verify
        )
        return self
    
    async def close(self):
        if self.client:
            await self.client.aclose()

    async def create_network_device(self, device:CiscoISENetworkDevice) -> CiscoISENetworkDevice:
        # create device
        url = f"{self.base_url}/ers/config/networkdevice"
        response = await self.client.post(url, json=device.to_api())
        if response.status_code != 201:
            raise Exception(f"Error {response.status_code}: Failed to create network device: {response.text}")

        # get its ID by name
        url = f"{self.base_url}/ers/config/networkdevice/name/{device.name}"
        response = await self.client.get(url)
        if response.status_code != 200:
            raise Exception(f"Error {response.status_code}: Failed to get network device ID: {response.text}")

        # extract ID and return
        response_data = response.json()
        device.id = response_data.get("NetworkDevice").get("id")
        device.data = response_data
        logger.info(f"Created network device: {device.name} with ID {device.id}")
        print(f"Network device created:")
        print(f'\tID = {device.id}')
        print(f'\tName = {device.name}')
        print(f'\tIP = {device.ip_address}/{device.mask}')
        print(f'\tGroups = {device.device_groups}')
        return device
            
    async def delete_network_device(self, device:CiscoISENetworkDevice) -> bool:
        url = f"{self.base_url}/ers/config/networkdevice/{device.id}"
        response = await self.client.delete(url)
        if response.status_code != 204:
            raise Exception(f"Error {response.status_code}: Failed to delete network device: {response.text}")
        logger.info(f"Deleted network device: {device.id}")
        return True

# RadiusClient
###############################################################################

@dataclass
class RadiusTestCase:
    name:str
    attributes:dict[str,str]
    create_network_device:bool=False
    network_device_groups:list[str]=field(default_factory=[])
    expected_result:str="ACCESS_ACCEPT"

class RadiusClient:
    """Client for sending RADIUS test requests"""
    
    def __init__(self, server: str, secret: str, dictionary: Dictionary):
        # Extract hostname if full URL is provided
        if server.startswith(('http://', 'https://')):
            parsed_url = urlparse(server)
            server = parsed_url.netloc
        self.server = server
        self.secret = secret.encode('utf-8')
        self.dictionary = dictionary
        self.client = None
        
    def initialize(self):
        self.client = Client(
            server=self.server,
            secret=self.secret,
            dict=self.dictionary
        )
        logger.info(f"Radius client initialized (server={self.server} secret={self.secret})")
        
    def test_authentication(self, test_case: RadiusTestCase) -> Dict[str, Any]:
        # Create request packet
        print(f'Attributes sent:')
        packet = self.client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
        # Add request attributes
        for key, value in test_case.attributes.items():
            if re.search("password", key, re.IGNORECASE):
                packet[key] = packet.PwCrypt(value)
                print(f'\t{key} = {packet.PwCrypt(value)}')
            else:
                packet[key] = value
                print(f'\t{key} = {value}')
        try:
            # Send request / get reply
            reply = self.client.SendPacket(packet)
            # Parse reply
            result = {
                "test_name": test_case.name,
                "success": reply.code == pyrad.packet.AccessAccept,
                "response_code": reply.code,
                "response_type": "ACCESS_ACCEPT" if reply.code == pyrad.packet.AccessAccept else "ACCESS_REJECT",
                "attributes": {}
            }
            # Add reply attributes, if any
            for attr in reply.keys():
                result["attributes"][attr] = reply[attr]
            return result
        except Exception as e:
            return {
                "test_name": test_case.name,
                "success": False,
                "error": str(e),
                "response_type": "ERROR"
            }

# display_test_result()
###############################################################################

def show_result(result: Dict[str, Any]):

    # Display response attributes if present
    if "attributes" in result and result["attributes"]:
        print("Response Attributes:")
        for key, value in result["attributes"].items():
            print(f"\t{key} = {value}")

    # Apply color based on response type
    response_type = result.get("response_type", "UNKNOWN")
    if response_type == "ACCESS_ACCEPT":
        status_text = f"{Fore.GREEN}{response_type}{Style.RESET_ALL}"
    elif response_type == "ACCESS_REJECT":
        status_text = f"{Fore.RED}{response_type}{Style.RESET_ALL}"
    else:
        status_text = f"{Fore.YELLOW}{response_type}{Style.RESET_ALL}"    
    print(f"Result: {status_text}\n")

# load_dictionary()
###############################################################################

def load_dictionary(folder: Path) -> Dictionary:
    # Create a base dictionary
    base_dictionary = Dictionary()
    
    # Check if the path is a file or directory
    if folder.is_file():
        logger.info(f"Loading single dictionary file: {folder}")
        try:
            # If it's a single file, load it directly
            base_dictionary.ReadDictionary(str(folder))
        except Exception as e:
            logger.error(f"Failed to load dictionary {folder}: {e}")
    else:
        # If it's a directory, look for dictionary files
        files = sorted(list(folder.glob("*")))
        
        if not files:
            raise FileNotFoundError(f"No RADIUS dictionary files found in {folder}")
            
        # Load each dictionary file
        for file in files:
            if file.is_file():
                try:
                    logger.info(f"Loading dictionary: {file}")
                    base_dictionary.ReadDictionary(str(file))
                except Exception as e:
                    logger.error(f"Failed to load dictionary {file}: {e}")
    
    return base_dictionary

# get_local_ip()
###############################################################################

def get_local_ip() -> str:
    """Get the local machine's IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # We don't actually connect to this address, it's just to determine interface
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

# parse_arguments()
###############################################################################

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Cisco ISE RADIUS Authentication Test Tool")
    
    parser.add_argument(
        "--ise-url", 
        help="Hostname or URL of the Cisco ISE server (can also be set with ISE_URL env var)"
    )
    
    parser.add_argument(
        "--ise-username", 
        help="Username for Cisco ISE API (can also be set with ISE_USERNAME env var)"
    )
    
    parser.add_argument(
        "--ise-password", 
        help="Password for Cisco ISE API (can also be set with ISE_PASSWORD env var)"
    )
    
    parser.add_argument(
        "--radius-secret", 
        default="RadiusTest123",
        help="RADIUS shared secret (default: RadiusTest123)"
    )
    
    parser.add_argument(
        "--radius-server", 
        help="RADIUS server (default: <Cisco ISE IP>)"
    )
    
    parser.add_argument(
        "--device-name",
        default="TEST-DEVICE",
        help="Custom name for the test device (default: TEST-DEVICE)"
    )
    
    parser.add_argument(
        "--device-ip",
        help="Custom IP for the test device (default: <auto-detect>)"
    )

    parser.add_argument(
        "--test-file", 
        type=Path,
        required=True,
        help="Path to JSON file containing test definitions"
    )
    
    parser.add_argument(
        "--dictionary", 
        type=Path,
        default=Path("./dictionary"),
        help="Path to RADIUS dictionary folder or file (default: ./dictionary)"
    )
    
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS certificate verification"
    )
    
    args = parser.parse_args()
    
    # Check ISE credentials
    if not args.ise_url:
        args.ise_url = os.environ.get("ISE_URL")
        if not args.ise_url:
            parser.error("ISE URL must be provided via --ise-url argument or ISE_URL environment variable")
    
    if not args.ise_username:
        args.ise_username = os.environ.get("ISE_USERNAME")
        if not args.ise_username:
            parser.error("ISE Username must be provided via --ise-username argument or ISE_USERNAME environment variable")
    
    if not args.ise_password:
        args.ise_password = os.environ.get("ISE_PASSWORD")
        if not args.ise_password:
            parser.error("ISE Password must be provided via --ise-password argument or ISE_PASSWORD environment variable")
    
    # Check RADIUS server IP
    if not args.radius_server:
        if not args.ise_url:
            parser.error("Radius server IP must be provided via --radius-server argument")
        else:
            args.radius_server = args.ise_url

    # Check if dictionary path exists
    if not args.dictionary.exists():
        parser.error(f"RADIUS dictionary path not found: {args.dictionary}")

    if not args.test_file.exists():
        parser.error(f"Test file not found: {args.test_file}")
        sys.exit(1)

    # Auto-detect local IP
    if not args.device_ip:
        args.device_ip = get_local_ip()
        logger.info(f"Using local IP address {args.device_ip} to create {args.device_name}")

    return args

# main()
###############################################################################

async def main():
    # Get and check command line arguments
    args = parse_arguments()
    
    # Load RADIUS dictionary
    dictionary = load_dictionary(args.dictionary)

    # Load test cases
    with open(args.test_file) as f:
        json_data = json.load(f)
    test_cases = [ RadiusTestCase(**test_case) for test_case in json_data]
    logger.info(f"Loaded {len(test_cases)} test cases from {args.test_file}")

    # Initialize RADIUS client
    radius_client = RadiusClient(args.radius_server, args.radius_secret, dictionary)
    radius_client.initialize()

    # Run test cases
    ise = CiscoISEClient(host=args.ise_url,username=args.ise_username,password=args.ise_password,verify=not args.no_verify)
    ise.connect()
    for test_case in test_cases:
        print(f"\n\n{Fore.CYAN}{test_case.name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        # Create network device
        network_device = CiscoISENetworkDevice(
                name = args.device_name,
                ip_address = args.device_ip,
                device_groups = test_case.network_device_groups,
                radius_shared_secret = args.radius_secret
            )
        if test_case.create_network_device:
            network_device = await ise.create_network_device(network_device)

        # Test authentication
        await asyncio.sleep(5)
        result = radius_client.test_authentication(test_case)
        show_result(result)

        # Delete network device
        if test_case.create_network_device:
            result = await ise.delete_network_device(network_device)
            if not result:
                raise


if __name__ == "__main__":
    # Fix event loop on Windows
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nCanceled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)