#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
module: application_visibility_network_devices_enable_app_telemetry
short_description: Resource module for Application Visibility Network Devices Enable App Telemetry
description:
- This module represents an alias of the module application_visibility_network_devices_enable_app_telemetry_v1
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  networkDevices:
    description: Application Visibility Network Devices Enable App Telemetry's networkDevices.
    elements: dict
    suboptions:
      id:
        description: Network device identifier.
        type: str
      includeGuestSsids:
        description: Flag to indicate whether guest SSIDs should be included for application
          telemetry enablement. Applicable only for wireless devices. Default value
          is false.
        type: bool
      includeWlanModes:
        description: Types of WLAN modes which needs to be included for enablement.
          Applicable and mandatory only for wireless devices. Available values LOCAL
          or NON_LOCAL.
        elements: str
        type: list
    type: list
requirements:
- dnacentersdk >= 2.4.9
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Application Policy EnableApplicationTelemetryFeatureOnMultipleNetworkDevicesV1
  description: Complete reference of the EnableApplicationTelemetryFeatureOnMultipleNetworkDevicesV1 API.
  link: https://developer.cisco.com/docs/dna-center/#!enable-application-telemetry-feature-on-multiple-network-devices
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.enable_application_telemetry_feature_on_multiple_network_devices_v1,

  - Paths used are
    post /dna/intent/api/v1/applicationVisibility/networkDevices/enableAppTelemetry,
  - It should be noted that this module is an alias of application_visibility_network_devices_enable_app_telemetry_v1

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.application_visibility_network_devices_enable_app_telemetry:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    networkDevices:
    - id: string
      includeGuestSsids: true
      includeWlanModes:
      - string

"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""