#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
module: ipam_site_ip_address_pools_id_info
short_description: Information module for Ipam Site Ip Address Pools Id Info
description:
- This module represents an alias of the module ipam_site_ip_address_pools_id_v1_info
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
    - Id path parameter. The `id` of the IP address subpool to retrieve.
    type: str
requirements:
- dnacentersdk >= 2.4.9
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Network Settings RetrievesAnIPAddressSubpoolV1
  description: Complete reference of the RetrievesAnIPAddressSubpoolV1 API.
  link: https://developer.cisco.com/docs/dna-center/#!retrieves-an-ip-address-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.retrieves_an_ip_address_subpool_v1,

  - Paths used are
    get /dna/intent/api/v1/ipam/siteIpAddressPools/{id},
  - It should be noted that this module is an alias of ipam_site_ip_address_pools_id_v1_info

"""

EXAMPLES = r"""
- name: Get Ipam Site Ip Address Pools Id Info by id
  cisco.dnac.ipam_site_ip_address_pools_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
  register: result

"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "id": "string",
        "ipV4AddressSpace": {
          "subnet": "string",
          "prefixLength": 0,
          "gatewayIpAddress": "string",
          "dhcpServers": [
            "string"
          ],
          "dnsServers": [
            "string"
          ],
          "totalAddresses": "string",
          "unassignableAddresses": "string",
          "assignedAddresses": "string",
          "defaultAssignedAddresses": "string",
          "slaacSupport": true,
          "globalPoolId": "string"
        },
        "ipV6AddressSpace": {
          "subnet": "string",
          "prefixLength": 0,
          "gatewayIpAddress": "string",
          "dhcpServers": [
            "string"
          ],
          "dnsServers": [
            "string"
          ],
          "totalAddresses": "string",
          "unassignableAddresses": "string",
          "assignedAddresses": "string",
          "defaultAssignedAddresses": "string",
          "slaacSupport": true,
          "globalPoolId": "string"
        },
        "name": "string",
        "poolType": "string",
        "siteId": "string",
        "siteName": "string"
      },
      "version": "string"
    }
"""