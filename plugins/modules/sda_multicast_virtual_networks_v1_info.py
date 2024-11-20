#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_multicast_virtual_networks_v1_info
short_description: Information module for Sda Multicast Virtual Networks V1
description:
- Get all Sda Multicast Virtual Networks V1.
- Returns a list of multicast configurations for virtual networks that match the provided query parameters.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
    - FabricId query parameter. ID of the fabric site where multicast is configured.
    type: str
  virtualNetworkName:
    description:
    - VirtualNetworkName query parameter. Name of the virtual network associated to the multicast configuration.
    type: str
  offset:
    description:
    - Offset query parameter. Starting record for pagination.
    type: float
  limit:
    description:
    - Limit query parameter. Maximum number of records to return.
    type: float
requirements:
- dnacentersdk >= 2.4.9
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for SDA GetMulticastVirtualNetworksV1
  description: Complete reference of the GetMulticastVirtualNetworksV1 API.
  link: https://developer.cisco.com/docs/dna-center/#!get-multicast-virtual-networks
notes:
  - SDK Method used are
    sda.Sda.get_multicast_virtual_networks_v1,

  - Paths used are
    get /dna/intent/api/v1/sda/multicast/virtualNetworks,

"""

EXAMPLES = r"""
- name: Get all Sda Multicast Virtual Networks V1
  cisco.dnac.sda_multicast_virtual_networks_v1_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
    virtualNetworkName: string
    offset: 0
    limit: 0
  register: result

"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "fabricId": "string",
          "virtualNetworkName": "string",
          "ipPoolName": "string",
          "ipv4SsmRanges": [
            "string"
          ],
          "multicastRPs": [
            {
              "rpDeviceLocation": "string",
              "ipv4Address": "string",
              "ipv6Address": "string",
              "isDefaultV4RP": true,
              "isDefaultV6RP": true,
              "networkDeviceIds": [
                "string"
              ],
              "ipv4AsmRanges": [
                "string"
              ],
              "ipv6AsmRanges": [
                "string"
              ]
            }
          ]
        }
      ],
      "version": "string"
    }
"""