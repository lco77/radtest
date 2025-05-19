# radtest.py

RADTest allows you run multiple RADIUS authentication/authorization test cases against your RADIUS server.

For convience it is also capable of creating a Network Device in Cisco ISE and removing it afterwards.


# Usage

```Powershell
python3 ./radtest.py -h
usage: radtest.py [-h] [--ise-url ISE_URL] [--ise-username ISE_USERNAME] [--ise-password ISE_PASSWORD] [--radius-secret RADIUS_SECRET] [--radius-server RADIUS_SERVER] [--device-name DEVICE_NAME]
                  [--device-ip DEVICE_IP] --test-file TEST_FILE [--dictionary DICTIONARY] [--no-verify]

Cisco ISE RADIUS Authentication Test Tool

options:
  -h, --help            show this help message and exit
  --ise-url ISE_URL     Hostname or URL of the Cisco ISE server (can also be set with ISE_URL env var)
  --ise-username ISE_USERNAME
                        Username for Cisco ISE API (can also be set with ISE_USERNAME env var)
  --ise-password ISE_PASSWORD
                        Password for Cisco ISE API (can also be set with ISE_PASSWORD env var)
  --radius-secret RADIUS_SECRET
                        RADIUS shared secret (default: RadiusTest123)
  --radius-server RADIUS_SERVER
                        RADIUS server (default: <Cisco ISE IP>)
  --device-name DEVICE_NAME
                        Custom name for the test device (default: TEST-DEVICE)
  --device-ip DEVICE_IP
                        Custom IP for the test device (default: <auto-detect>)
  --test-file TEST_FILE
                        Path to JSON file containing test definitions
  --dictionary DICTIONARY
                        Path to RADIUS dictionary folder or file (default: ./dictionary)
  --no-verify           Disable TLS certificate verification
```

Note that:

- you can use environment variables **ISE_URL**, **ISE_USERNAME** and **ISE_PASSWORD** to configure the Cisco ISE connection without command line parameters
- **--device-ip** defaults to your local computer IP since it is sending the RADIUS packets. You may have to set it manually if you have multiple network interfaces and IPs
- **--radius-server** defaults to the Cisco ISE IP. However you can change it to a dedicated PSN node if your PAN does not answer RADIUS requests
- place your dictionary files into **--dictionary**. Default to ./dictionary

Example usage with default params and environment variables:

```powershell
python3 ./radtest.py --test-file ./radtest.json --no-verify
```

# JSON Tests file

It is just a JSON-list of RADIUS test objects, each one having:
- a unique **name**
- **create_network_device** controls if the script should automatically create the Network Device in Cisco ISE
- **network_device_groups** controls Network Device group membership on Cisco ISE
- **expected_result** helps determnine if the test is successful or not
- request **attributes** can then be configured. Note that User-Password is automatically encrypted so you can use a clear text value here

```json
[
    {
      "name": "Basic Authentication Test",
      "create_network_device": true,
      "network_device_groups": ["Location#All Locations#CH01", "Device Type#All Device Types#Router"],
      "expected_result": "ACCESS_ACCEPT",
      "attributes": {
        "User-Name": "testuser",
        "User-Password": "password123",
        "NAS-IP-Address": "10.0.0.91",
        "Service-Type": "Login-User"
      }
    },
    {
      "name": "Admin Authentication Test",
      "create_network_device": true,
      "network_device_groups": ["Location#All Locations#CH01", "Device Type#All Device Types#Switch"],
      "expected_result": "ACCESS_ACCEPT",
      "attributes": {
        "User-Name": "admin",
        "User-Password": "adminpass",
        "NAS-IP-Address": "10.0.0.91",
        "Service-Type": "Administrative-User"
      }
    }
  ]
```


# Sample output

```shell
$ python3 ./radtest.py --test-file ./radtest.json --no-verify --device-ip 10.0.0.91 --radius-server 10.0.0.10


Basic Authentication Test
================================================================================
Network device created:
        ID = 824783d0-0e9b-11f0-9354-aa0a36f440c7
        Name = TEST-DEVICE
        IP = 10.0.0.91/32
        Groups = ['Location#All Locations#CH01', 'Device Type#All Device Types#Router']
Attributes sent:
        User-Name = testuser
        User-Password = b'\xf0)\xd6\\ru\xc2\x0b(\x1b\xfal\xaeT\x91\x08'
        NAS-IP-Address = 10.0.0.91
        Service-Type = Login-User
Result: ACCESS_REJECT



Admin Authentication Test
================================================================================
Network device created:
        ID = 85a83b00-0e9b-11f0-9354-aa0a36f440c7
        Name = TEST-DEVICE
        IP = 10.0.0.91/32
        Groups = ['Location#All Locations#CH01', 'Device Type#All Device Types#Switch']
Attributes sent:
        User-Name = admin
        User-Password = b'\x0cXiP\x9d\x13jQ\xac\x15\xb3\x12\\B=\xc0'
        NAS-IP-Address = 10.0.0.91
        Service-Type = Administrative-User
Result: ACCESS_REJECT
```
