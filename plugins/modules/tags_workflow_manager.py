#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Archit Soni, Madhan Sankaranarayanan")


DOCUMENTATION = r"""
# TODO : change documentation here
---
module: sda_fabric_sites_zones_workflow_manager
short_description: Manage fabric site(s)/zone(s) and update the authentication profile template in Cisco Catalyst Center.
description:
  - Creating fabric site(s) for the SDA operation in Cisco Catalyst Center.
  - Updating fabric site(s) for the SDA operation in Cisco Catalyst Center.
  - Creating fabric zone(s) for the SDA operation in Cisco Catalyst Center.
  - Updating fabric zone(s) for the SDA operation in Cisco Catalyst Center.
  - Deletes fabric site(s) from Cisco Catalyst Center.
  - Deletes fabric zone(s) from Cisco Catalyst Center.
  - Configure the authentication profile template for fabric site/zone in Cisco Catalyst Center.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abhishek Maheshwari (@abmahesh)
        Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center configuration after applying the playbook configuration.
    type: bool
    default: false
  state:
    description: The desired state of Cisco Catalyst Center after the module execution.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: A list containing detailed configurations for creating, updating, or deleting fabric sites or zones
        in a Software-Defined Access (SDA) environment. It also includes specifications for updating the authentication
        profile template for these sites. Each element in the list represents a specific operation to be performed on
        the SDA infrastructure, such as the addition, modification, or removal of fabric sites/zones, and modifications
        to authentication profiles.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_sites:
        description: A dictionary containing detailed configurations for managing REST Endpoints that will receive Audit log
            and Events from the Cisco Catalyst Center Platform. This dictionary is essential for specifying attributes and
            parameters required for the lifecycle management of fabric sites, zones, and associated authentication profiles.
        type: dict
        suboptions:
          site_name_hierarchy:
            description: This name uniquely identifies the site for operations such as creating, updating, or deleting fabric
                sites or zones, as well as for updating the authentication profile template. This parameter is mandatory for
                any fabric site/zone management operation.
            type: str
            required: true
          fabric_type:
            description: Specifies the type of site to be managed within the SDA environment. The acceptable values are 'fabric_site'
                and 'fabric_zone'. The default value is 'fabric_site', indicating the configuration of a broader network area, whereas
                'fabric_zone' typically refers to a more specific segment within the site.
            type: str
            required: true
          authentication_profile:
            description: The authentication profile applied to the specified fabric. This profile determines the security posture and
                controls for network access within the site. Possible values include 'Closed Authentication', 'Low Impact',
                'No Authentication', and 'Open Authentication'. This setting is critical when creating or updating a fabric site or
                updating the authentication profile template.
            type: str
          is_pub_sub_enabled:
            description: A boolean flag that indicates whether the pub/sub mechanism is enabled for control nodes in the fabric site.
                This feature is relevant only when creating or updating fabric sites, not fabric zones. When set to True,
                pub/sub facilitates more efficient communication and control within the site. The default is True for fabric sites,
                and this setting is not applicable for fabric zones.
            type: bool
          update_authentication_profile:
            description: A dictionary containing the specific details required to update the authentication profile template associated
                with the fabric site. This includes advanced settings that fine-tune the authentication process and security controls
                within the site.
            type: dict
            suboptions:
              authentication_order:
                description: Specifies the primary method of authentication for the site. The available methods are 'dot1x' (IEEE 802.1X)
                    and 'mac' (MAC-based authentication). This setting determines the order in which authentication mechanisms are attempted.
                type: str
              dot1x_fallback_timeout:
                description: The timeout duration, in seconds, for falling back from 802.1X authentication. This value must be within the
                    range of 3 to 120 seconds. It defines the period a device waits before attempting an alternative authentication method
                    if 802.1X fails.
                type: int
              wake_on_lan:
                description: A boolean value indicating whether the Wake-on-LAN feature is enabled. Wake-on-LAN allows the network to
                    remotely wake up devices that are in a low-power state.
                type: bool
              number_of_hosts:
                description: Specifies the number of hosts allowed per port. The available options are 'Single' for one device per port or
                    'Unlimited' for multiple devices. This setting helps in controlling the network access and maintaining security.
                type: str
              enable_bpu_guard:
                description: A boolean setting that enables or disables BPDU Guard. BPDU Guard provides a security mechanism by disabling
                    a port when a BPDU (Bridge Protocol Data Unit) is received, protecting against potential network loops. This setting
                    defaults to true and is applicable only when the authentication profile is set to "Closed Authentication".
                type: bool


requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9

notes:
  - To ensure the module operates correctly for scaled sets, which involve creating or updating fabric sites/zones and handling
    the updation of authentication profile template, please provide valid input in the playbook. If any failure is encountered,
    the module will and halt execution without proceeding to further operations.
  - When deleting fabric sites, make sure to provide the input to remove the fabric zones associated with them in the
    playbook. Fabric sites cannot be deleted until all underlying fabric zones have been removed and it can be any order as per
    the module design fabric zones will be deleted first followed by fabric sites.
  - Parameter 'site_name' is updated to 'site_name_hierarchy'.
  - SDK Method used are
    ccc_fabric_sites.FabricSitesZones.get_site
    ccc_fabric_sites.FabricSitesZones.get_fabric_sites
    ccc_fabric_sites.FabricSitesZones.get_fabric_zones
    ccc_fabric_sites.FabricSitesZones.add_fabric_site
    ccc_fabric_sites.FabricSitesZones.update_fabric_site
    ccc_fabric_sites.FabricSitesZones.add_fabric_zone
    ccc_fabric_sites.FabricSitesZones.update_fabric_zone
    ccc_fabric_sites.FabricSitesZones.get_authentication_profiles
    ccc_fabric_sites.FabricSitesZones.update_authentication_profile
    ccc_fabric_sites.FabricSitesZones.delete_fabric_site_by_id
    ccc_fabric_sites.FabricSitesZones.delete_fabric_zone_by_id

"""

EXAMPLES = r"""
Write example playbooks here #TODO

"""

RETURN = r"""

dnac_response:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
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


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class Tags(DnacBase):
    """Class containing member attributes for tags workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        # self.create_site, self.update_site, self.no_update_site = [], [], []
        # self.create_zone, self.update_zone, self.no_update_zone = [], [], []
        # self.update_auth_profile, self.no_update_profile = [], []
        # self.delete_site, self.delete_zone, self.absent_site, self.absent_zone = [], [], [], []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        temp_spec = {
            'tags': {
                'type': 'list',
                'elements': 'dict',
                'name': {'type': 'str', 'required': True},
                'description': {'type': 'str'},
                'system_tag': {'type': 'bool', 'default': False},
                'force_delete': {'type': 'bool', 'default': False},
                'device_rules': {
                    'type':'dict',
                    'elements': 'dict',
                    'rule_descriptions': {
                        'type': 'list',
                        'elements': 'dict',
                        'required': True,
                        'rule_name': {'type': 'str', 'required': True, 'choices':['device_name', 'device_family', 'device_series', 'ip_address', 'location', 'version']},
                        'search_pattern': {'type': 'str', 'required': True, 'choices':['contains', 'equals', 'starts_with', 'ends_with']},
                        'value': {'type':'str', 'required': True},
                        'operation': {'type':'str', 'default':'ILIKE', 'choices':['ILIKE', 'LIKE']}
                    }
                },
                'port_rules': {
                    'type':'dict',
                    'elements': 'dict',
                    'scope_description': {
                        'type': 'dict',
                        'elements': 'dict',
                        'required': True,
                        'grouping_category': {'type': 'str'},
                        'inherit': {'type': 'bool', 'default': False},
                        'group_members': {
                            'type':'list',
                            'elements': 'str'
                        }
                    },
                    'rule_descriptions': {
                        'type': 'list',
                        'elements': 'dict',
                        'required': True,
                        'rule_name': {'type': 'str','required': True, 'choices':['speed', 'admin_status', 'port_name', 'operational_status', 'description']},
                        'search_pattern': {'type': 'str', 'required': True, 'choices':['contains', 'equals', 'starts_with', 'ends_with']},
                        'value': {'type':'str', 'required': True},
                        'operation': {'type':'str', 'default':'ILIKE', 'choices':['ILIKE', 'LIKE']}
                    }
                },
                'assign_members': {
                    'type':'dict',
                    'elements': 'dict',
                    'device_details': {
                        'type':'list',
                        'elements': 'dict',
                        'ip': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'hostname': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'mac_address': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'serial_number': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'port_names': {
                            'type': 'list',
                            'elements': 'str',
                        }    
                    },
                    'site_details': {
                        'type':'list',
                        'elements': 'dict',
                        'site_names': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'port_names': {
                            'type': 'list',
                            'elements': 'str',
                        }    
                    }
                },
            },
            'tags_membership': {
                'type': 'list',
                'tags': {
                    'type': 'list',
                    'elements': 'str',
                    'required': True
                },
                'device_details': {
                    'type':'list',
                    'elements': 'dict',
                    'ip': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'hostname': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'mac_address': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'serial_number': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'port_names': {
                        'type': 'list',
                        'elements': 'str',
                    }    
                },
                'site_details': {
                    'type':'list',
                    'elements': 'dict',
                    'site_names': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'port_names': {
                        'type': 'list',
                        'elements': 'str',
                    }    
                }
            }

        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self
        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )

        self.debugg(invalid_params)
    
        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(str(valid_temp))
        self.log(self.msg, "INFO")

        return self


    def int_fail(self, msg ="Intentional Fail "):
        self.msg = msg
        self.set_operation_result("failed", False, self.msg, "ERROR")
        self.check_return_status()

    def debugg(self, msg ="Sample Debug Message"):
        self.log(msg,"DEBUG")
        
    

def main():
    """ main entry point for module execution
    """

    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.3.7.9'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    ccc_tags = Tags(module)
    # ccc_tags.log("STARTING MESSAGE", "DEBUG")
    #TODO: Change this to 2.3.7.9 in future when you get 2379 TB
    # TODO: Ask which version is minimum.
    if ccc_tags.compare_dnac_versions(ccc_tags.get_ccc_version(), "2.3.7.6") < 0:
        ccc_tags.msg = (
            "The specified version '{0}' does not support the tagging feature. Supported versions start "
            "  from '2.3.7.6' onwards. Version '2.3.7.6' introduces APIs for creating, updating and deleting the "
            "Fabric Sites/Zones and updating the Authentication profiles."
            .format(ccc_tags.get_ccc_version())
        )
        ccc_tags.set_operation_result("failed", False, ccc_tags.msg, "ERROR").check_return_status()

    state = ccc_tags.params.get("state")

    if state not in ccc_tags.supported_states:
        ccc_tags.status = "invalid"
        ccc_tags.msg = "State {0} is invalid".format(state)
        ccc_tags.check_return_status()
    ccc_tags.debugg("PRECHECK at 407")
    ccc_tags.validate_input().check_return_status()
    ccc_tags.log(ccc_tags.validated_config, "DEBUG")


    ccc_tags.int_fail()
    config_verify = ccc_tags.params.get("config_verify")
    # ccc_tags.msg = "INTENTIONAL FAILING AT 374"
    # ccc_tags.set_operation_result("failed", False, ccc_tags.msg, "ERROR")
    # ccc_tags.check_return_status()



    # for config in ccc_tags.validated_config:
    #     ccc_tags.reset_values()
    #     ccc_tags.get_want(config).check_return_status()



    #     ccc_tags.get_have(config).check_return_status()
    #     ccc_tags.get_diff_state_apply[state](config).check_return_status()
    #     if config_verify:
    #         ccc_tags.verify_diff_state_apply[state](config).check_return_status()

    # # Invoke the API to check the status and log the output of each site/zone and authentication profile update on console.
    # ccc_tags.update_site_zones_profile_messages().check_return_status()

    module.exit_json(**ccc_tags.result)


if __name__ == '__main__':
    main()
