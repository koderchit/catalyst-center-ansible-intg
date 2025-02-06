#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


#  TODO: check all the get functions and check that if NONE CASE IS HANDELLED OR NOT
#  TODO: add proper logs to each function.
#  TODO: Check all the logs and remove unnecessary logs
#  TODO: check for all the pass statements and remove where not needed.
#  TODO: remove all the TODO statements as well.

from __future__ import absolute_import, division, print_function
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common import validation

from collections import defaultdict

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


class Tags(DnacBase):
    """Class containing member attributes for tags workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created_tag, self.updated_tag, self.not_updated_tag = [], [], []


    #  List of member_details
    #  Member details is: Dict of
    # {
    #     "id": device_id, 
    #     "device_type": "networkdevice"/"interface",
    #     "device_identifier": "hostname", etc
    #     "device_value": device_name, etc
    #     "interface_name": interface_name/None
    #     "site_name": site_name/None
    #     "reason": Failing Reason.
    #     "Tags":[List of tag names]
    # }

        self.updated_tags_memberships, self.not_updated_tags_memberships=[], []
        self.deleted_tag, self.absent_tag = [], []
        self.deleted_tags_memberships, self.not_deleted_tags_memberships=[], []
        self.absent_site=[]
        self.result["changed"]= False

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
                'type': 'dict',
                'elements': 'dict',
                'name': {'type': 'str', 'required': True},
                'description': {'type': 'str'},
                'system_tag': {'type': 'bool', 'default': False},
                'force_delete': {'type': 'bool', 'default': False},
                'device_rules': {
                    'type': 'dict',
                    'elements': 'dict',
                    'rule_descriptions': {
                        'type': 'list',
                        'elements': 'dict',
                        'required': True,
                        'rule_name': {'type': 'str', 'required': True},
                        'search_pattern': {'type': 'str', 'required': True},
                        'value': {'type': 'str', 'required': True},
                        'operation': {'type': 'str', 'default': 'ILIKE'}
                    }
                },
                'port_rules': {
                    'type': 'dict',
                    'elements': 'dict',
                    'scope_description': {
                        'type': 'dict',
                        'elements': 'dict',
                        'grouping_category': {'type': 'str','required': True},
                        'inherit': {'type': 'bool', 'default': True},
                        'group_members': {
                            'type': 'list',
                            'elements': 'str',
                            'required': True
                        }
                    },
                    'rule_descriptions': {
                        'type': 'list',
                        'elements': 'dict',
                        'required': True,
                        'rule_name': {'type': 'str', 'required': True},
                        'search_pattern': {'type': 'str', 'required': True},
                        'value': {'type': 'str', 'required': True},
                        'operation': {'type': 'str', 'default': 'ILIKE'}
                    }
                },
                'assign_members': {
                    'type': 'dict',
                    'elements': 'dict',
                    'device_details': {
                        'type': 'list',
                        'elements': 'dict',
                        'ip_addresses': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'hostnames': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'mac_addresses': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'serial_numbers': {
                            'type': 'list',
                            'elements': 'str',
                        },
                        'port_names': {
                            'type': 'list',
                            'elements': 'str',
                        }
                    },
                    'site_details': {
                        'type': 'list',
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
                'type': 'dict',
                'tags': {
                    'type': 'list',
                    'elements': 'str',
                    'required': True
                },
                'device_details': {
                    'type': 'list',
                    'elements': 'dict',
                    'ip_addresses': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'hostnames': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'mac_addresses': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'serial_numbers': {
                        'type': 'list',
                        'elements': 'str',
                    },
                    'port_names': {
                        'type': 'list',
                        'elements': 'str',
                    }
                },
                'site_details': {
                    'type': 'list',
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
        valid_temp, invalid_params = self.validate_list_of_dicts(
            self.config, temp_spec
        )

        self.debugg(invalid_params)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp))
        self.log(self.msg, "INFO")

        return self

    def validate_str(self,item, param_spec, param_name, invalid_params, module= None):
        """
        This function checks that the input `item` is a valid string and confirms to
        the constraints specified in `param_spec`. If the string is not valid or does
        not meet the constraints, an error message is added to `invalid_params`.

        Args:
            item (str): The input string to be validated.
            param_spec (dict): The parameter's specification, including validation constraints.
            param_name (str): The name of the parameter being validated.
            invalid_params (list): A list to collect validation error messages.

        Returns:
            str: The validated and possibly normalized string.

        Example `param_spec`:
            {
                "type": "str",
                "length_max": 255 # Optional: maximum allowed length
            }
        """

        item = validation.check_type_str(item)
        if param_spec.get("length_max"):
            if 1 <= len(item) <= param_spec.get("length_max"):
                return item
            else:
                invalid_params.append(
                    "{0}:{1} : The string exceeds the allowed "
                    "range of max {2} char".format(param_name, item, param_spec.get("length_max"))
                )
        return item

    def validate_integer_within_range(self,item, param_spec, param_name, invalid_params, module= None):
        """
        This function checks that the input `item` is a valid integer and conforms to
        the constraints specified in `param_spec`. If the integer is not valid or does
        not meet the constraints, an error message is added to `invalid_params`.

        Args:
            item (int): The input integer to be validated.
            param_spec (dict): The parameter's specification, including validation constraints.
            param_name (str): The name of the parameter being validated.
            invalid_params (list): A list to collect validation error messages.

        Returns:
            int: The validated integer.

        Example `param_spec`:
            {
                "type": "int",
                "range_min": 1,     # Optional: minimum allowed value
                "range_max": 100    # Optional: maximum allowed value
            }
        """
        try:
            item = validation.check_type_int(item)
        except TypeError as e:
            invalid_params.append("{0}: value: {1} {2}".format(param_name, item, str(e)))
            return item

        min_value = param_spec.get("range_min", 1)
        if param_spec.get("range_max") and not (min_value <= item <= param_spec["range_max"]):
            invalid_params.append(
                "{0}: {1} : The item exceeds the allowed range of min: {2} and max: {3}".format(
                    param_name, item, param_spec.get("range_min"), param_spec.get("range_max"))
            )

        return item

    def validate_bool(self,item, param_spec, param_name, invalid_params, module= None):
        """
        This function checks that the input `item` is a valid boolean value. If it does
        not represent a valid boolean value, an error message is added to `invalid_params`.

        Args:
            item (bool): The input boolean value to be validated.
            param_spec (dict): The parameter's specification, including validation constraints.
            param_name (str): The name of the parameter being validated.
            invalid_params (list): A list to collect validation error messages.

        Returns:
            bool: The validated boolean value.
        """

        return validation.check_type_bool(item)

    def validate_list(self,item, param_spec, param_name, invalid_params, module= None):
        """
        This function checks if the input `item` is a valid list based on the specified `param_spec`.
        It also verifies that the elements of the list match the expected data type specified in the
        `param_spec`. If any validation errors occur, they are appended to the `invalid_params` list.

        Args:
            item (list): The input list to be validated.
            param_spec (dict): The parameter's specification, including validation constraints.
            param_name (str): The name of the parameter being validated.
            invalid_params (list): A list to collect validation error messages.

        Returns:
            list: The validated list, potentially normalized based on the specification.
        """

        # import epdb;
        # epdb.serve(port=9889)
        try:
            if param_spec.get("type") == type(item).__name__:
                keys_list = []
                for dict_key in param_spec:
                    keys_list.append(dict_key)
                if len(keys_list) == 1:
                    return validation.check_type_list(item)
                
                temp_dict = {keys_list[1]: param_spec[keys_list[1]]}
                try:
                    if param_spec['elements']:
                        if param_spec['elements']=='dict':
                            common_defaults = {'type', 'elements', 'required', 'default', 'choices', 'no_log'}
                            filtered_param_spec = {key: value for key, value in param_spec.items() if key not in common_defaults}
                            if filtered_param_spec:
                                item, list_invalid_params = self.validate_list_of_dicts(item, filtered_param_spec)
                                invalid_params.extend(list_invalid_params)
                        
                        get_spec_type = param_spec['type']
                        get_spec_element = param_spec['elements']
                        if type(item).__name__ == get_spec_type:
                            for element in item:
                                if type(element).__name__ != get_spec_element:
                                    invalid_params.append(
                                        "{0} is not of the same datatype as expected which is {1}".format(element, get_spec_element)
                                    )
                        else:
                            invalid_params.append(
                                "{0} is not of the same datatype as expected which is {1}".format(item, get_spec_type)
                            )
                except Exception as e:
                    item, list_invalid_params = self.validate_list_of_dicts(item, temp_dict)
                    invalid_params.extend(list_invalid_params)
            else:
                invalid_params.append("{0} : is not a valid list".format(item))
        except Exception as e:
            invalid_params.append("{0} : comes into the exception".format(e))

        return item

    def validate_dict(self,item, param_spec, param_name, invalid_params, module=None):
        """
        This function checks if the input `item` is a valid dictionary based on the specified `param_spec`.
        If the dictionary does not match the expected data type specified in the `param_spec`,
        a validation error is appended to the `invalid_params` list.

        Args:
            item (dict): The input dictionary to be validated.
            param_spec (dict): The parameter's specification, including validation constraints.
            param_name (str): The name of the parameter being validated.
            invalid_params (list): A list to collect validation error messages.

        Returns:
            dict: The validated dictionary.
        """
        # import epdb;
        # epdb.serve(port=9889)
        if param_spec.get("type") != type(item).__name__:
            invalid_params.append("{0} : is not a valid dictionary".format(item))
        
        if param_spec.get("type") == 'dict':
            common_defaults = {'type', 'elements', 'required', 'default', 'choices', 'no_log'}
            filtered_param_spec = {key: value for key, value in param_spec.items() if key not in common_defaults} 

            valid_params_dict = {}
        
            if filtered_param_spec: 
                for param in filtered_param_spec:
                    curr_item = item.get(param)
                    if curr_item is None:
                        if filtered_param_spec[param].get("required"):
                            invalid_params.append(
                                "{0} : Required parameter not found".format(param)
                            )
                        else:
                            curr_item = filtered_param_spec[param].get("default")
                            valid_params_dict[param] = curr_item
                        continue
                    data_type = filtered_param_spec[param].get("type")
                    switch = {
                        "str": self.validate_str,
                        "int": self.validate_integer_within_range,
                        "bool": self.validate_bool,
                        "list": self.validate_list,
                        "dict": self.validate_dict,
                    }

                    validator = switch.get(data_type)
                    if validator:
                        curr_item = validator(curr_item, filtered_param_spec[param], param, invalid_params, module)
                    else:
                        invalid_params.append(
                            "{0}:{1} : Unsupported data type {2}.".format(param, curr_item, data_type)
                        )

                    choice = filtered_param_spec[param].get("choices")
                    if choice:
                        if curr_item not in choice:
                            invalid_params.append(
                                "{0} : Invalid choice provided".format(curr_item)
                            )

                    no_log = filtered_param_spec[param].get("no_log")
                    if no_log:
                        if module is not None:
                            module.no_log_values.add(curr_item)
                        else:
                            msg = "\n\n'{0}' is a no_log parameter".format(param)
                            msg += "\nAnsible module object must be passed to this "
                            msg += "\nfunction to ensure it is not logged\n\n"
                            raise Exception(msg)

                    valid_params_dict[param] = curr_item
                item = valid_params_dict    

        return validation.check_type_dict(item)

    def validate_list_of_dicts(self,param_list, spec, module=None):
        """Validate/Normalize playbook params. Will raise when invalid parameters found.
        param_list: a playbook parameter list of dicts
        spec: an argument spec dict
            e.g. spec = dict(ip=dict(required=True, type='bool'),
                            foo=dict(type='str', default='bar'))
        return: list of normalized input data
        """

        v = validation
        normalized = []
        invalid_params = []
        # import epdb;
        # epdb.serve(port=9889)
        for list_entry in param_list:
            valid_params_dict = {}
            if not spec:
                # Handle the case when spec becomes empty but param list is still there
                invalid_params.append("No more spec to validate, but parameters remain")
                break
            for param in spec:
                item = list_entry.get(param)
                if item is None:
                    if spec[param].get("required"):
                        invalid_params.append(
                            "{0} : Required parameter not found".format(param)
                        )
                    else:
                        item = spec[param].get("default")
                        valid_params_dict[param] = item
                    continue
                data_type = spec[param].get("type")
                switch = {
                    "str": self.validate_str,
                    "int": self.validate_integer_within_range,
                    "bool": self.validate_bool,
                    "list": self.validate_list,
                    "dict": self.validate_dict,
                }

                validator = switch.get(data_type)
                if validator:
                    item = validator(item, spec[param], param, invalid_params, module)
                else:
                    invalid_params.append(
                        "{0}:{1} : Unsupported data type {2}.".format(param, item, data_type)
                    )

                choice = spec[param].get("choices")
                if choice:
                    if item not in choice:
                        invalid_params.append(
                            "{0} : Invalid choice provided".format(item)
                        )

                no_log = spec[param].get("no_log")
                if no_log:
                    if module is not None:
                        module.no_log_values.add(item)
                    else:
                        msg = "\n\n'{0}' is a no_log parameter".format(param)
                        msg += "\nAnsible module object must be passed to this "
                        msg += "\nfunction to ensure it is not logged\n\n"
                        raise Exception(msg)

                valid_params_dict[param] = item
            normalized.append(valid_params_dict)

        return normalized, invalid_params

    def validate_device_rules(self, config):
        """
        Validates and processes device rules provided in the configuration dictionary.

        Args:
            config (dict): A configuration dictionary containing a "tags" key with 
                        "device_rules" under it. Each device rule should include:
                        - "rule_name" (str): Name of the device attribute to match.
                        - "search_pattern" (str): Matching pattern type.
                        - "value" (str): Value to match.
                        - "operation" (str, optional): Matching operation (default is "ILIKE").

        Returns:
            dict: A dictionary containing the validated device rules.

        Description:
            The method ensures all provided device rules are valid, adhering to expected 
            fields and constraints. Logs errors for missing or invalid parameters and sets 
            default values where applicable. If validation fails at any step, it logs an 
            error and stops execution.
        """
        device_rules=config.get("tags").get("device_rules")

        if not device_rules:
            self.msg = (
                "No Device Rule is provided"
                )
            self.log(self.msg, "INFO")
            return device_rules
        rule_descriptions = device_rules.get("rule_descriptions")
        if not rule_descriptions:
            self.msg = (
                "Device Rules does not contain rule descriptions. Required parameter for defining dynamic rules."
                )
            self.log(self.msg, "INFO")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        
        validated_rule_descriptions=[]
        
        # Choices
        rule_name_choices = ['device_name', 'device_family', 'device_series', 'ip_address', 'location', 'version']
        search_pattern_choices = ['contains', 'equals', 'starts_with', 'ends_with']
        operation_choices = ['ILIKE', 'LIKE']
        
        for device_rule in rule_descriptions:
            valudated_device_rule={}
            rule_name= device_rule.get("rule_name")
            if not rule_name:
                self.msg = (
                "Rule Name not provided. Required parameter for defining dynamic rules."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            rule_name = rule_name.lower()
            if rule_name not in rule_name_choices:
                self.msg = (
                f"Rule Name provided: {rule_name} is Invalid. Rulename should be one of {rule_name_choices}"
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            search_pattern= device_rule.get("search_pattern")
            if not search_pattern:
                self.msg = (
                "Search Pattern not provided. Required parameter for defining dynamic rules."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            search_pattern = search_pattern.lower()
            if search_pattern not in search_pattern_choices:
                self.msg = (
                f"Search pattern provided: {search_pattern} is Invalid. Search Pattern should be one of {search_pattern_choices}"
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            value = device_rule.get("value")
            if not value:
                self.msg = (
                    "Value not provided. Required parameter for defining dynamic rules."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            operation= device_rule.get("operation")
            if not operation:
                operation= "ILIKE"
                self.msg = (
                    f"Operation not provided. Setting it to its default value of {operation}"
                )
                self.log(self.msg, "INFO")

            operation = operation.upper()
            if operation not in operation_choices:
                self.msg = (
                    f"Operation provided: {operation} is Invalid. Operation should be one of {operation_choices}"
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            valudated_device_rule["rule_name"]= rule_name
            valudated_device_rule["search_pattern"]= search_pattern
            valudated_device_rule["value"]= value
            valudated_device_rule["operation"]= operation

            validated_rule_descriptions.append(valudated_device_rule)

        validated_device_rules={
            "rule_descriptions":validated_rule_descriptions
        }

        self.msg = (
            f"Device Rules validation completed. Validated device rules: {validated_device_rules}"
        )
        self.log(self.msg, "DEBUG")
                
        return validated_device_rules

    def validate_port_rules(self, config):
        """
        Validates and processes port rules provided in the configuration dictionary.

        Args:
            config (dict): A configuration dictionary containing a "tags" key with 
                        "port_rules" under it. Port rules should include:
                        - "rule_descriptions" (list): List of rule objects defining port attributes.
                        - "scope_description" (dict, optional): Specifies grouping details for the port rules.

        Returns:
            dict: A dictionary containing the validated port rules.

        Description:
            This method ensures all provided port rules and scope descriptions are valid. 
            It checks for missing or invalid fields and logs errors when necessary. Default 
            values are assigned to optional fields if missing. The validation halts with an 
            error if critical fields are invalid or missing.
        """
        port_rules=config.get("tags").get("port_rules")

        if not port_rules:
            self.msg = (
                "No Port Rules are provided"
                )
            self.log(self.msg, "INFO")
            return port_rules
        rule_descriptions = port_rules.get("rule_descriptions")
        scope_description = port_rules.get("scope_description")
        validated_port_rules={}



        if not rule_descriptions and not scope_description:
            self.msg = (
                "Port Rules does not contain rule descriptions and scope description."
                "Both are required for creation of dynamic rules and atleast one is required for updation or deletion."
                )
            self.log(self.msg, "INFO")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
    

        if not scope_description:
            self.msg = (
                f"Port Rules Rules does not contain scope descrption."
            )
            self.log(self.msg, "INFO")
        else:
            grouping_category = scope_description.get("grouping_category")
            grouping_category_choices=["TAG", "SITE"]
            grouping_category = grouping_category.upper()
            if grouping_category and grouping_category not in grouping_category_choices:
                self.msg = (
                    f"Grouping category provided: {grouping_category} is Invalid. Grouping category should be one of {grouping_category}"
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            inherit = scope_description.get("inherit")
            group_members= scope_description.get("group_members")

            if not group_members:
                self.msg = (
                    f"No Group members provided for grouping catagory: {grouping_category}"
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            validated_scope_description={
                "grouping_category": grouping_category,
                "inherit": inherit,
                "group_members": group_members
            }
            validated_port_rules["scope_description"]=validated_scope_description

        if not rule_descriptions:
            self.msg = (
                f"Port Rules Rules does not contain rule descriptions."
            )
            self.log(self.msg, "INFO")
        else:
            validated_rule_descriptions=[]
            rule_name_choices = ['speed', 'admin_status', 'port_name', 'operational_status', 'description']
            search_pattern_choices = ['contains', 'equals', 'starts_with', 'ends_with']
            operation_choices = ['ILIKE', 'LIKE']
            for port_rule in rule_descriptions:
                rule_name= port_rule.get("rule_name")
                if not rule_name:
                    self.msg = (
                        "Rule Name not provided. Required parameter for defining dynamic rules."
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                rule_name = rule_name.lower()
                if rule_name not in rule_name_choices:
                    self.msg = (
                        f"Rule Name provided: {rule_name} is Invalid. Rule Name should be one of {rule_name_choices}"
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                search_pattern= port_rule.get("search_pattern")
                if not search_pattern:
                    self.msg = (
                    "Search Pattern not provided. Required parameter for defining dynamic rules."
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                search_pattern = search_pattern.lower()
                if search_pattern not in search_pattern_choices:
                    self.msg = (
                    f"Search pattern provided: {search_pattern} is Invalid. Search Pattern should be one of {search_pattern_choices}"
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                value = port_rule.get("value")
                if not value:
                    self.msg = (
                        "Value not provided. Required parameter for defining dynamic rules."
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                operation= port_rule.get("operation")
                if not operation:
                    operation= "ILIKE"
                    self.msg = (
                        f"Operation not provided. Setting it to its default value of {operation}"
                    )
                    self.log(self.msg, "INFO")

                operation = operation.upper()
                if operation not in operation_choices:
                    self.msg = (
                        f"Operation provided: {operation} is Invalid. Operation should be one of {operation_choices}"
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                valudated_port_rule={
                    "rule_name": rule_name,
                    "search_pattern": search_pattern,
                    "value": value,
                    "operation": operation
                }
                validated_rule_descriptions.append(valudated_port_rule)

            validated_port_rules["rule_descriptions"] = validated_rule_descriptions
            

        self.msg = (
            f"Port Rules validation completed. Validated Port rules: {validated_port_rules}"
        )
        self.log(self.msg, "DEBUG")
                
        return validated_port_rules

    def validate_assign_members(self, config):
        """
        Validates and processes the assign members details provided in the configuration dictionary.

        Args:
            config (dict): Configuration dictionary containing "assign_members" under the "tags" key.

        Returns:
            dict: A dictionary containing the validated assign members details.

        Description:
            Ensures the presence of "assign_members" with either "device_details" or "site_details". 
            Validates required fields in each detail, logs errors for missing or invalid data, 
            and halts execution for critical validation failures.
        """
        assign_members = config.get("tags").get("assign_members")

        if not assign_members:
            self.msg = (
                " Assign members details not provided" 
                )
            self.log(self.msg, "INFO")
            return assign_members

        device_details= assign_members.get("device_details")
        site_details= assign_members.get("site_details")

        if not device_details and not site_details:
            self.msg = (
                "None of device details or site details are provided. Atleast one is needed to assign members"
            )
            self.log(self.msg, "INFO")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        
        if not device_details:
            self.msg = (
                " Device details are not provided" 
                )
            self.log(self.msg, "INFO")
        else:

            for device_detail in device_details:    
                ip_addresses = device_detail.get("ip_addresses")
                hostnames = device_detail.get("hostnames")
                mac_addresses = device_detail.get("mac_addresses")
                serial_numbers = device_detail.get("serial_numbers")
                
                if not ip_addresses and not hostnames and not mac_addresses and not serial_numbers:
                    self.msg = (
                        "None of ip addresses, hostnames, mac addresses or serial numbers are provided. Atleast one is needed to assign members"
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    
                port_names = device_detail.get("port_names")

        if not site_details:
            self.msg = (
                " Site details are not provided" 
                )
            self.log(self.msg, "INFO")
        else:

            for site_detail in site_details:    
                site_names = site_detail.get("site_names")
                if not site_names:
                    self.msg = (
                        "Site Names not provided. Required to assign the tag to members"
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    
                port_names = site_detail.get("port_names")

        self.msg = (
            f"Assign members validation completed. Validated Assign members: {assign_members}"
        )
        self.log(self.msg, "DEBUG")
        
        return assign_members    

    def get_tag_id(self, tag_name):
        """
        Retrieves the tag ID for a given tag name from the Cisco Catalyst Center.

        Args:
            tag_name (str): The name of the tag whose ID needs to be retrieved.

        Returns:
            str or None: The tag ID if found, otherwise None.

        Description:
            This method initiates an API call to retrieve tag details using the provided tag name. 
            If the response is empty or an error occurs, it logs the issue and returns None.
        """

        self.log("Initiating retrieval of tag details for tag name: '{0}'.".format(tag_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="tag",
                function='get_tag',
                op_modifies=True,
                params={"name": tag_name},
            )

            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_tag' for the tag '{0}': {1}".format(tag_name, str(response)), "DEBUG")

            if not response:
                self.msg = "No tag details retrieved for tag name: {0}, Response empty.".format(tag_name)
                self.log(self.msg, "DEBUG")
                return None
            tag_id = response[0].get("id")
            
            return tag_id

        except Exception as e:
            self.msg = """Error while getting the details of Tag with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(tag_name, str(e))
            self.fail_and_exit(self.msg)

        return None
            
    def get_site_id(self, site_name):
        self.log("Initiating retrieval of site details for site name: '{0}'.".format(site_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="site_design",
                function='get_sites',
                op_modifies=True,
                params={"name_hierarchy": site_name},
            )

            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_site' for the site '{0}': {1}".format(site_name, str(response)), "DEBUG")

            if not response:
                self.msg = "No Site details retrieved for Site name: {0}, Response empty.".format(site_name)
                self.log(self.msg, "DEBUG")
                return None
            site_id = response[0].get("id")

            return site_id

        except Exception as e:
            self.msg = """Error while getting the details of Site with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(site_name, str(e))
            self.fail_and_exit(self.msg)

        return None

    def get_want(self, config):
        """
        Collects and validates the desired state configuration for fabric sites and zones from the given playbook configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration for the desired state of fabric sites and zones.
                        It should include a key "fabric_sites" with a list of dictionaries.
        Returns:
            self (object): The instance of the class with the updated `want` attribute containing the validated desired state
                of fabric sites and zones and updating authentication profile template.
        Description:
            This function processes the provided playbook configuration to determine the desired state of fabric sites
            and zones in the Cisco Catalyst Center.
            The validated site information is stored in the `want` dictionary under the key "fabric_sites".
            The `want` attribute of the instance is updated with this dictionary, representing the desired state
            of the system. The function returns the instance for further processing or method chaining.
        """

        self.log("Get Want function", "DEBUG")

        want={}
        
        tags = config.get("tags")
        tags_membership = config.get("tags_membership")

        if not tags and not tags_membership:
            self.msg = (
                "No input provided in the playbook for tag operation or updating tag memberships in Cisco Catalysyt Center."
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR").check_return_status()

        if not tags:
            self.msg = (
                "Tags not provided."
            )
            self.log(self.msg, "INFO")
        else:
            tag_name = tags.get("name")
            if not tag_name:
                self.msg = (
                "No Tag Name provided or Provided Tag Name is empty."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR").check_return_status()
            
            description= tags.get("description")
            if not description:
                self.msg= "No Description is provided"
                self.log(self.msg, "INFO")

            system_tag= tags.get("system_tag")
            if not system_tag:
                system_tag= False
                self.msg= f"system tag not provided, setting it to its default value: {system_tag}"
                self.log(self.msg, "INFO")

            force_delete = tags.get("force_delete")
            if not force_delete:
                force_delete= False
                self.msg= f"force delete not provided, setting it to its default value: {force_delete}"
                self.log(self.msg, "INFO")

            device_rules = self.validate_device_rules(config)
            port_rules = self.validate_port_rules(config)
            assign_members = self.validate_assign_members(config)
            validated_tags={
                "name": tag_name,
                "description": description,
                "system_tag": system_tag,
                "force_delete": force_delete,
                "device_rules": device_rules,
                "port_rules": port_rules,
                "assign_members": assign_members
            }
            # Creating dictionary again as the dynamic rules might be modified for casing changes.

            want['tags']= validated_tags
            self.msg = (
                f"Tags validation completed. Validated Tags: {validated_tags}"
            )
            self.log(self.msg, "DEBUG")
                
        if not tags_membership:
            self.msg = (
                "Tags membership not provided."
            )
            self.log(self.msg, "INFO")
        else:
            tags = tags_membership.get("tags")
            device_details= tags_membership.get("device_details")
            site_details= tags_membership.get("site_details")
            if not tags:
                self.msg = (
                    "No tags provided in tags_membership. Required Parameter."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            if not device_details:
                self.msg = (
                    " Device details are not provided" 
                    )
                self.log(self.msg, "INFO")
            else:
                for device_detail in device_details:    
                    ip_addresses = device_detail.get("ip_addresses")
                    hostnames = device_detail.get("hostnames")
                    mac_addresses = device_detail.get("mac_addresses")
                    serial_numbers = device_detail.get("serial_numbers")
                    if not ip_addresses and not hostnames and not mac_addresses and not serial_numbers:
                        self.msg = (
                            "None of ip, hostname, mac address or serial number are provided. Atleast one is needed to assign members"
                        )
                        self.log(self.msg, "INFO")
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    port_names = device_detail.get("port_names")

            if not site_details:
                self.msg = (
                    " Site details are not provided" 
                    )
                self.log(self.msg, "INFO")
            else:
                for site_detail in site_details:    
                    site_names = site_detail.get("site_names")
                    if not site_names:
                        self.msg = (
                            "Site Names not provided. Required to assign the tag to members"
                        )
                        self.log(self.msg, "INFO")
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()    
                    port_names = site_detail.get("port_names")

            want["tags_membership"]= tags_membership
            self.msg = (
                f"Tags membership validation completed. Validated Tags membership: {tags_membership}"
            )
            self.log(self.msg, "DEBUG")

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook for creating/updating tags and tags memberships"
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
            Retrieves the tag ID based on the provided config, and stores it in the 'have' dictionary.

            Args:
                config (dict): Configuration dictionary containing the 'tags' key with 'name' as a subkey.

            Returns:
                self: Returns the instance of the class for method chaining.

            Description:
                This method extracts the tag name from the config, retrieves the tag ID, 
                and stores it in the 'have' dictionary. If the tag ID is not found, it logs an debug message.
        """
        have={}
        tags = config.get("tags")
        if tags:
            tag_name= tags.get("name")
            tag_info= self.get_tag_info(tag_name)
            if not tag_info:
                self.msg= "Tag Details for {0} are not available in Cisco Catalyst Center".format(tag_name)
                self.log(self.msg, "DEBUG")
            else:
                have["tag_info"]= tag_info
        self.have= have

        return self

    def format_rule_representation(self, rule):

        search_pattern= rule.get("search_pattern")
        operation= rule.get("operation")
        value = rule.get("value")
        name = rule.get("rule_name")

        name_selector = {
            # Device Rule_names
            "device_name": "hostname",
            "device_family": "family", 
            "device_series": "series",
            "ip_address": "managementIpAddress",
            "location": "groupNameHierarchy", 
            "version": "softwareVersion",

            # Port rule_names
            "speed": "speed",
            "admin_status": "adminStatus", 
            "port_name": "portName", 
            "operational_status": "status", 
            "description": "description"
        }
        name =  name_selector.get(name)
        self.log(rule, "DEBUG")
        if search_pattern== "equals":
            pass  #No change in value is required
        elif search_pattern== "contains":
            value= "%"+value+"%"
        elif search_pattern == "starts_with":
            value= value + "%"
        elif search_pattern =="ends_with":
            value= "%" + value
        
        formatted_rule = {
            "operation" : operation,
            "name" : name,
            "value" : value
        }

        self.log("Formatted rule representation for Input:{0} is Output:{1}".format(rule, formatted_rule), "INFO")
        return formatted_rule
    
    def sorting_rule_descriptions(self, rule_descriptions):
        sort_order = {
            "hostname": 0,
            "family": 1,
            "series": 2,
            "managementIpAddress": 3,
            "groupNameHierarchy": 4,
            "softwareVersion": 5,
            "speed": 6,
            "adminStatus": 7,
            "portName": 8,
            "status": 9,
            "description": 10
        }
        
        # Sort based on the `name` order and then by `value` within the same `name`
        sorted_rule_descriptions = sorted(
            rule_descriptions,
            key=lambda x: (sort_order.get(x['name'], float('inf')), x['value'])
        )
        return sorted_rule_descriptions

    def group_rules_into_tree(self, rule_descriptions):
        """
            Groups leaf nodes by 'name' and creates a hierarchical dictionary structure
            according to the specified rules.

            Args:
                leaf_nodes (list): List of leaf nodes (base rules).

            Returns:
                dict: Hierarchical dictionary structure.
        """

        if not rule_descriptions:
            return None
        leaf_nodes = rule_descriptions
        # Group leaf nodes by 'name'
        grouped_nodes = defaultdict(list)
        for node in leaf_nodes:
            grouped_nodes[node['name']].append(node)
        
        # Helper function to limit items to two per group and branch
        def branch_conditions(conditions, operation):
            while len(conditions) > 2:
                conditions = [{
                    'operation': operation,
                    'items': [conditions.pop(0), conditions.pop(0)]
                }] + conditions
            return conditions

        # Build the hierarchical structure for grouped nodes
        grouped_conditions = []
        for name, nodes in grouped_nodes.items():
            if len(nodes) > 1:
                # Create an OR operation for nodes with the same name
                or_group = {
                    'operation': 'OR',
                    'items': branch_conditions(nodes, 'OR')
                }
                grouped_conditions.append(or_group)
            else:
                # Single node remains as is
                grouped_conditions.append(nodes[0])


        # Combine all grouped conditions with AND
        while len(grouped_conditions) > 2:
            grouped_conditions = [{
                'operation': 'AND',
                'items': [grouped_conditions.pop(0), grouped_conditions.pop(0)]
            }] + grouped_conditions

        if len(grouped_conditions) > 1:
            return {
                'operation': 'AND',
                'items': grouped_conditions
            }
        else:
            return grouped_conditions[0]

    def format_device_rules(self, device_rules):

        if device_rules is None:
            self.log("device_rules is {0}. Returning None".format(device_rules), "DEBUG")
            return None
        
        rule_descriptions = device_rules.get("rule_descriptions")
        
        formatted_rule_descriptions=[]
        for device_rule in rule_descriptions:
            formatted_rule_description= self.format_rule_representation(device_rule)
            formatted_rule_descriptions.append(formatted_rule_description)

        # Sorting it so that its uniform and easier to compare with future updates.
        formatted_rule_descriptions_list= self.sorting_rule_descriptions(formatted_rule_descriptions)

        self.log("Formatted Rule Descriptions In List Format:{0}".format(formatted_rule_descriptions_list), "INFO")

        grouped_device_rules= self.group_rules_into_tree(formatted_rule_descriptions_list)
        
        formatted_device_rules = {
            "memberType" : "networkdevice",
            "rules": grouped_device_rules
        }
        self.log("Formatted Device rules for Input:{0} is Output:{1}".format(device_rules, formatted_device_rules), "INFO")
        return formatted_device_rules

    def format_scope_description(self, scope_description):
        
        if not scope_description:
            self.log("scope_description is {0}. Returning None".format(scope_description), "INFO")
            return formatted_scope_description
        
        grouping_category= scope_description.get("grouping_category")
        group_members= scope_description.get("group_members")
        group_members_ids=[]
        if grouping_category == "TAG":
            for tag in group_members:
                tag_id= self.get_tag_id(tag)
                if tag_id is None:
                    self.msg= (
                        "Group Member provided: {0} is Not present in Cisco Catalyst Center."
                        "Please ensure that the group_members are present and grouping category is provided are valid"
                    ).format(tag)
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                group_members_ids.append(tag_id)
        elif grouping_category == "SITE":
            for site in group_members:
                site_id= self.get_site_id(site)
                self.log(site_id, "DEBUG")
                if site_id is None:
                    self.msg= (
                        "Grouping Member provided: {0} is Not present in Cisco Catalyst Center."
                        "Please ensure that the group_members and grouping category provided are valid"
                    ).format(tag)
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                group_members_ids.append(site_id)

        formatted_scope_description={
            "memberType": "networkdevice",
            "inherit": scope_description.get("inherit"),
            "groupType": grouping_category,
            "scopeObjectIds": group_members_ids
        }

        self.log("Formatted Scope Description for Input:{0} is Output:{1}".format(scope_description, formatted_scope_description), "INFO")

        return formatted_scope_description
        
    def format_port_rules(self, port_rules):
        
        if port_rules is None:
            self.log("port_rules is {0}. Returning None".format(port_rules), "DEBUG")
            return None
        
        rule_descriptions= port_rules.get("rule_descriptions")
        scope_description= port_rules.get("scope_description")

        formatted_rule_descriptions=[]

        # Checking if rule_desctiptions exist because in case of updation, only one of scope/rules can be given.
        if rule_descriptions:
            for port_rule in rule_descriptions:
                formatted_rule_description= self.format_rule_representation(port_rule)
                formatted_rule_descriptions.append(formatted_rule_description)
            
            # Sorting it so that its easier to compare.
            formatted_rule_descriptions_list= self.sorting_rule_descriptions(formatted_rule_descriptions)
            
            # Converting the sorted list to tree structure.
            formatted_rule_descriptions= self.group_rules_into_tree(formatted_rule_descriptions_list)

        formatted_scope_description= []
        if scope_description:
            formatted_scope_description= self.format_scope_description(scope_description)

        formatted_port_rules = {
            "memberType" : "interface",
            "rules": formatted_rule_descriptions,
            "scopeRule" : formatted_scope_description
        }
        self.log("Formatted Port rules for Input:{0} is Output:{1}".format(port_rules, formatted_port_rules), "INFO")
        return formatted_port_rules
        
    def combine_device_port_rules(self, device_rules, port_rules):
        
        dynamic_rules=[]
        if port_rules:
            dynamic_rules.append(port_rules)
        if device_rules:
            dynamic_rules.append(device_rules)

        self.log("Combined dynamic_rules for device_rules:{0}, port_rules:{1} are: {2}".format(device_rules, port_rules, dynamic_rules))
        return dynamic_rules

    def create_tag(self, tags):

        tag_name= tags.get("name")
        description= tags.get("description")
        device_rules = tags.get("device_rules")
        port_rules = tags.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)
        formatted_port_rules = self.format_port_rules(port_rules)
        if formatted_port_rules:
            rule_descriptions= port_rules.get("rule_descriptions")
            scope_description= port_rules.get("scope_description")
            if not rule_descriptions or not scope_description:
                self.msg="""Either of rule_description:{0} or scope_description:{1} is empty in port_rules. 
                Both are required for port rule creation""".format(rule_descriptions, scope_description)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

        dynamic_rules= self.combine_device_port_rules(formatted_device_rules, formatted_port_rules)
        tag_payload={
            "name": tag_name,
            "description": description,
            "dynamicRules": dynamic_rules
        }

        task_name = "create_tag"
        paramaters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, paramaters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.result["changed"]= True
        success_msg = "Tag: '{0}' created successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.created_tag.append(tag_name)

        return self

    def get_tag_info(self, tag_name):

        self.log("Initiating retrieval of tag details for tag name: '{0}'.".format(tag_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="tag",
                function='get_tag',
                op_modifies=True,
                params={"name": tag_name},
            )

            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_tag' for the tag '{0}': {1}".format(tag_name, str(response)), "DEBUG")

            if not response:
                self.msg = "No tag details retrieved for tag name: {0}, Response empty.".format(tag_name)
                self.log(self.msg, "DEBUG")
                return None
            tag_info = response[0]
            
            return tag_info

        except Exception as e:
            self.msg = """Error while getting the details of Tag with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(tag_name, str(e))
            self.fail_and_exit(self.msg)

        return None

    def get_device_id_by_param(self, param, param_value):
        self.log("Initiating retrieval of device id details for device with {0}: '{1}' ".format(param, param_value), "DEBUG")

        try:
            param_api_name={
                "ip_address":"managementIpAddress",
                "hostname":"hostname",
                "mac_address":"macAddress",
                "serial_number":"serialNumber",
            }
            
            payload={
                "{0}".format(param_api_name.get(param)): param_value
            }
            response = self.dnac._exec(
                family="devices",
                function='get_device_list',
                op_modifies=True,
                params=payload,
            )
            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_device_list' for the Device with {0} '{1}' : {2}".format(param, param_value, str(response)), "DEBUG")

            if not response:
                self.msg = "No Device details retrieved for Device with {0}: {1}, Response empty.".format(param, param_value)
                self.log(self.msg, "DEBUG")
                return None
            device_id = response[0].get("id")

            return device_id

        except Exception as e:
            self.msg = """Error while getting the details of Device with {0}:'{1}' present in
            Cisco Catalyst Center: {2}""".format(param, param_value, str(e))
            self.fail_and_exit(self.msg)

        return None

    def get_port_id_by_device_id(self, device_id, port_name, device_identifier, device_identifier_value):

        self.log("Initiating retrieval of interface details for the interface name: '{0}' of device with {1}: '{2}'".format(port_name, device_identifier, device_identifier_value), "DEBUG")
        try:
            response = self.dnac._exec(
                family="devices",
                function="get_interface_details",
                op_modifies=True,
                params={"device_id": device_id, "name": port_name}
            )

            response = response.get("response")
            self.log("Received API response from 'get_interface_details' for the interface name: '{0}' of device with {1}: '{2}' is : {3}".format(port_name, device_identifier, device_identifier_value, str(response)), "DEBUG")

            if not response:
                self.msg = "No interface details for interface name: '{0}' of device with {1}: '{2}', Response empty.".format(port_name, device_identifier, device_identifier_value)
                self.log(self.msg, "DEBUG")
                return None
            
            port_id = response.get("id")
            
            return port_id

        except Exception as e:
            error_message = str(e)
            if "status_code: 404" in error_message and "No resource found with deviceId: {0} and interfaceName:{1}".format(device_id, port_name) in error_message:
                self.log("Interface not found for '{0}' on device with {1}: '{2}'. Skipping. Error: {3}".format(port_name, device_identifier, device_identifier_value, error_message), "INFO")
                return None  # Skips the operation when this specific error occurs

            self.msg = """Could Not retrieve Interface information for '{0}' of device with {1}: '{2}' in Cisco Catalyst Center. Exception Caused: {3}""".format(port_name, device_identifier, device_identifier_value, str(e))
            self.fail_and_exit(self.msg)

        return None

    def deduplicate_list_of_dict(self, list_of_dicts):
        seen = set()
        unique_dicts = []
        self.log(list_of_dicts)
        for d in list_of_dicts:
            self.log(d)
            # Convert dictionary to a tuple of sorted items (temporary hashable representation)
            identifier = tuple(sorted(d.items()))
            
            if identifier not in seen:
                seen.add(identifier)
                unique_dicts.append(d)  # Append the original dict (not modified)
        return unique_dicts

    def format_device_details(self, device_details):
        # (port_id, "interface", param_name, param, port_name)
        device_ids=[]
        for device_detail in device_details:
            port_names = device_detail.get("port_names")
            if port_names:
                self.log("Deduplicating the port_names list for duplicate port names", "DEBUG")
                port_names =  list(set(port_names))

            available_params=["ip_addresses", "hostnames", "mac_addresses", "serial_numbers"]
            available_param= ["ip_address", "hostname", "mac_address", "serial_number"]

            for params_name, param_name in zip(available_params,available_param):
                param_list = device_detail.get(params_name)
                if param_list:
                    for param in param_list:
                        device_id = self.get_device_id_by_param(param_name, param)
                        device_detail_dict={
                            "device_type": "networkdevice",
                            "device_identifier": param_name,
                            "device_value": param
                        }
                        if device_id is None:
                            device_detail_dict["reason"] = "Device doesn't exist in Cisco Catalyst Center"
                            state= self.params.get("state")
                            if state =="merged":
                                self.not_updated_tags_memberships.append(device_detail_dict)
                            elif state =="deleted":
                                self.not_deleted_tags_memberships.append(device_detail_dict)
                            self.log("No device found in Cisco Catalyst Center with {0}: {1}".format(param_name, param), "INFO")
                        else:
                            if port_names:
                                for port_name in port_names:
                                    port_id= self.get_port_id_by_device_id(device_id, port_name, param_name, param)
                                    interface_detail_dict={
                                            "device_type": "interface",
                                            "device_identifier": param_name,
                                            "device_value": param,
                                            "interface_name": port_name
                                    }
                                    if port_id is None:
                                        self.log("Interface: '{0}' is not available for the device with {1}:'{2}'.".format(port_name, param_name, param), "INFO")
                                        interface_detail_dict["reason"]="Interface Not Available on Device"
                                        state= self.params.get("state")
                                        if state =="merged":
                                            self.not_updated_tags_memberships.append(interface_detail_dict)
                                        elif state =="deleted":
                                            self.not_deleted_tags_memberships.append(interface_detail_dict)
                                    else:
                                        interface_detail_dict["id"]= port_id
                                        device_ids.append(interface_detail_dict)
                            else:
                                device_detail_dict["id"]= device_id
                                device_ids.append(device_detail_dict)

        

        self.log("Deduplicating the device_ids list for duplicate device IDs", "DEBUG")
        device_ids =  self.deduplicate_list_of_dict(device_ids)
        self.log("Successfully retrieved device/port IDs from device_details: {0}\nResult: {1}".format(device_details, device_ids), "DEBUG")
        return device_ids

    def get_device_id_list_by_site_name(self, site_name):
        site_id= self.get_site_id(site_name)

        self.log("Initiating retrieval of device details for site name: '{0}'.".format(site_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="site_design",
                function='get_site_assigned_network_devices',
                op_modifies=True,
                params={"site_id": site_id},
            )

            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_site_assigned_network_devices' for the site name: '{0}': {1}".format(site_name, str(response)), "DEBUG")

            if not response:
                self.msg = "No devices found under the site name: {0}, Response empty.".format(site_name)
                self.log(self.msg, "DEBUG")
                return None
            
            device_id_list=[]
            for response_ele in response:
                device_id_list.append(response_ele.get("deviceId"))
            
            return device_id_list

        except Exception as e:
            self.msg = """Error while getting the details of the devices under the site name '{0}' present in
            Cisco Catalyst Center: {1}""".format(site_name, str(e))
            self.fail_and_exit(self.msg)

        return None
        
    def format_site_details(self, site_details):

        device_ids=[]
        for site_detail in site_details:
            port_names = site_detail.get("port_names")
            if port_names:
                self.log("Deduplicating the port_names list for duplicate port names", "DEBUG")
                port_names =  list(set(port_names))
            site_names = site_detail.get("site_names")
            if site_names:
                for site in site_names:
                    site_id= self.get_site_id(site)
                    if site_id is None:
                        self.msg= (
                            "Site provided: {0} is Not present in Cisco Catalyst Center."
                            "Please ensure that the Site name hierarchy provided is valid"
                        ).format(site)
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    device_ids_list = self.get_device_id_list_by_site_name(site)
                    if device_ids_list is None:
                        self.log("No device found under the site '{0}' in Cisco Catalyst Center".format(site), "INFO")
                    else:
                        for device_id in device_ids_list:
                            device_name = self.get_device_name_by_id(device_id)
                            device_detail_dict={
                                "id":device_id,
                                "device_type": "networkdevice",
                                "device_identifier": "hostname",
                                "device_value": device_name,
                                "site_name": site
                            }
                            if port_names:
                                for port_name in port_names:
                                    interface_detail_dict={
                                        "device_type": "interface",
                                        "device_identifier": "hostname",
                                        "device_value": device_name,
                                        "interface_name": port_name,
                                        "site_name": site
                                    }
                                    port_id= self.get_port_id_by_device_id(device_id, port_name, "hostname", device_name)
                                    if port_id is None:
                                        interface_detail_dict["reason"]=" Interface Not Available on Device"
                                        self.not_updated_tags_memberships.append(interface_detail_dict)
                                        self.log("Interface: '{0}' is not available for the device with {1}:'{2}'.".format(port_name, "hostname", device_name), "INFO")
                                    else:
                                        interface_detail_dict["id"] = port_id
                                        device_ids.append(interface_detail_dict)
                            else:
                                device_ids.append(device_detail_dict)


        self.log("Deduplicating the device_ids list for duplicate device IDs", "DEBUG")
        device_ids =  self.deduplicate_list_of_dict(device_ids)

        self.log("Successfully retrieved device/port IDs from site_details: {0}\nResult: {1}".format(site_details, device_ids), "DEBUG")
        return device_ids

    def get_device_name_by_id(self, device_id):

        self.log("Initiating retrieval of device id details for device with id: {0}:".format(device_id), "DEBUG")

        try:
            payload={
                "id": device_id
            }
            response = self.dnac._exec(
                family="devices",
                function='get_device_list',
                op_modifies=True,
                params=payload,
            )
            # Check if the response is empty
            response = response.get("response")
            self.log("Received API response from 'get_device_list' for the Device with Id: {0}, {1}".format(device_id, str(response)), "DEBUG")

            if not response:
                self.msg = "No Device details retrieved for Device with Id: {0}, Response empty.".format(device_id)
                self.log(self.msg, "DEBUG")
                return None
            device_name = response[0].get("hostname")

            return device_name

        except Exception as e:
            self.msg = """Error while getting the details of Device with Id: {0} present in
            Cisco Catalyst Center: {2}""".format(device_id, str(e))
            self.fail_and_exit(self.msg)

        return None

    def create_tag_membership(self, tag_name, member_details):
        
        self.log("Starting to add members to the Tag:'{0}' with provided members:{1}".format(tag_name, member_details), "INFO")

        network_device_list=[]
        interface_list=[]
        self.log(member_details)
        for member_detail in member_details:
            member_id= member_detail.get("id")
            member_type= member_detail.get("device_type")
            if member_type == "interface": 
                interface_list.append(member_id)
            elif member_type == "networkdevice":
                network_device_list.append(member_id)

        tag_id= self.get_tag_id(tag_name)
        if tag_id is None:
            self.msg= "Tag ID for {0} is not found in Cisco Catalyst Center.".format(tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        member_payload={}

        if network_device_list:
            member_payload["networkdevice"] = network_device_list
        if interface_list:
            member_payload["interface"] = interface_list

        task_name = "add_members_to_the_tag"

        paramaters = {"payload": member_payload, "id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, paramaters)
        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        success_msg = "Added Tag members successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def assign_members_on_tag_creation(self, tags):
        assign_members = tags.get("assign_members")
        device_details= assign_members.get("device_details")
        member_details=[]
        if device_details:
            formatted_device_details = self.format_device_details(device_details)
            self.log(formatted_device_details)
            member_details= member_details+ formatted_device_details
        site_details= assign_members.get("site_details")
        if site_details:
            formatted_site_details = self.format_site_details(site_details)
            member_details= member_details + formatted_site_details
        tag_name = tags.get("name")
        self.log(tag_name)
        self.log(member_details)

        if member_details:
            self.create_tag_membership(tag_name, member_details)
        else:
            self.log("No Valid Assign Members for the Tag:{0}".format(tag_name), "INFO")

        return self
    
    def get_tags_associated_with_the_network_devices(self, network_device_details):
        
        self.log("Initiating retrieval of tags associated with network devices: {0}".format(network_device_details), "DEBUG")
        fetched_tags_details={}
        device_ids=[]
        for network_device_detail in network_device_details:
            device_id= network_device_detail.get("id")
            fetched_tags_details["{0}".format(device_id)]=[]
            device_ids.append(device_id)

        BATCH_SIZE = 500
        for i in range(0, len(device_ids), BATCH_SIZE):
            batch = device_ids[i : i + BATCH_SIZE]
            try:
                payload={
                    "ids": batch
                }

                response = self.dnac._exec(
                    family="tag",
                    function='query_the_tags_associated_with_network_devices',
                    op_modifies=True,
                    params=payload,
                )
                # Check if the response is empty
                response = response.get("response")
                self.log("Received API response from 'query_the_tags_associated_with_network_devices' for batch {0} payload: {1}, {2}".format(i//BATCH_SIZE + 1,payload, str(response)), "DEBUG")

                if not response:
                    self.log("No tags details retrieved for network_device_details: {0}, Response empty.".format(network_device_details), "DEBUG")
                    continue
                
                for response_ in response:
                    device_id = response_.get("id")
                    tags = response_.get("tags")
                    if tags is not None:
                        for tag in tags:
                            tag_name = tag.get("name")
                            tag_id = tag.get("id")
                            tag_detail_dict={
                                "tag_name":tag_name,
                                "tag_id":tag_id
                            }
                            fetched_tags_details[device_id].append(tag_detail_dict)

            except Exception as e:
                self.msg = """Error while getting the tags details of network_device_details: {0} for the batch:{1} present in
                Cisco Catalyst Center: {2}""".format(network_device_details,i//BATCH_SIZE + 1, str(e))
                self.fail_and_exit(self.msg)
    
        return fetched_tags_details

    def get_tags_associated_with_the_interfaces(self, interface_details):
        
        self.log("Initiating retrieval of tags associated with interfaces: {0}".format(interface_details), "DEBUG")
        fetched_tags_details={}
        interface_ids=[]
        for interface_detail in interface_details:
            interface_id= interface_detail.get("id")
            fetched_tags_details["{0}".format(interface_id)]=[]
            interface_ids.append(interface_id)

        BATCH_SIZE = 500
        for i in range(0, len(interface_ids), BATCH_SIZE):
            batch = interface_ids[i : i + BATCH_SIZE]
            try:
                payload={
                    "ids": batch
                }
                response = self.dnac._exec(
                    family="tag",
                    function='query_the_tags_associated_with_interfaces',
                    op_modifies=True,
                    params=payload,
                )
                # Check if the response is empty
                response = response.get("response")
                self.log("Received API response from 'query_the_tags_associated_with_interfaces' for the batch:{0} with payload: {1} is: {2}".format(i//BATCH_SIZE + 1, payload, str(response)), "DEBUG")
                if not response:
                    self.msg = "No tags details retrieved for interface_details: {0}, Response empty.".format(interface_details)
                    self.log(self.msg, "DEBUG")
                    continue
                else:
                    self.log(response)
                    for response_ in response:
                        interface_id = response_.get("id")
                        tags = response_.get("tags")
                        if tags is not None:
                            for tag in tags:
                                tag_name = tag.get("name")
                                tag_id = tag.get("id")
                                tag_detail_dict={
                                    "tag_name":tag_name,
                                    "tag_id":tag_id
                                }
                                fetched_tags_details[interface_id].append(tag_detail_dict)


            except Exception as e:
                self.msg = """Error while getting the tags details of interface_details: {0} for the batch:{1} present in
                Cisco Catalyst Center: {2}""".format(interface_details, i//BATCH_SIZE + 1, str(e))
                self.fail_and_exit(self.msg)

        return fetched_tags_details

    def compare_and_update_list(self, existing_list, new_list):

    #  Works only in case of primary list elements, 
        self.log("Existing List: {0}".format(existing_list))
        self.log("New List: {0}".format(new_list))
        existing_set = set(existing_list)
        new_set = set(new_list)
        self.log(existing_set)
        self.log(new_set)

        updated_list=[]
        state= self.params.get("state")
        if state == "merged":
            updated_list = list(existing_set | new_set)
        elif state =="deleted":
            updated_list = list(existing_set - new_set)
        
        # Sorted existing List 
        existing_list= sorted(existing_list)
        updated_list= sorted(updated_list)
        
        needs_update = updated_list != existing_list
        self.log(needs_update)
        self.log(updated_list)

        return needs_update, updated_list

    def unformat_rule_representation(self, formatted_rule):
        operation = formatted_rule.get("operation")
        name = formatted_rule.get("name")
        value = formatted_rule.get("value")

        # Reverse lookup for name_selector mapping
        name_selector_reverse = {
            "hostname": "device_name",
            "family": "device_family",
            "series": "device_series",
            "managementIpAddress": "ip_address",
            "groupNameHierarchy": "location",
            "softwareVersion": "version",
            "speed": "speed",
            "adminStatus": "admin_status",
            "portName": "port_name",
            "status": "operational_status",
            "description": "description"
        }

        rule_name = name_selector_reverse.get(name, name)

        # Detect search_pattern based on value transformation
        if value.startswith("%") and value.endswith("%"):
            search_pattern = "contains"
            value = value[1:-1]  # Remove %
        elif value.startswith("%"):
            search_pattern = "ends_with"
            value = value[1:]  # Remove leading %
        elif value.endswith("%"):
            search_pattern = "starts_with"
            value = value[:-1]  # Remove trailing %
        else:
            search_pattern = "equals"

        unformatted_rule = {
            "search_pattern": search_pattern,
            "operation": operation,
            "value": value,
            "rule_name": rule_name
        }

        self.log("Unformatted rule representation for Input:{0} is Output:{1}".format(formatted_rule, unformatted_rule), "INFO")
        return unformatted_rule

    def compare_and_update_list_of_dict(self, existing_list, new_list):
        self.log("Existing List: {0}".format(existing_list), "DEBUG")
        self.log("New List: {0}".format(new_list), "DEBUG")

        updated_list = []
        state = self.params.get("state")

        if state == "merged":
            # Merge while preserving order
            updated_list = existing_list.copy()
            for new_dict in new_list:
                if new_dict not in existing_list:  # Check if new_dict is already in existing_list
                    updated_list.append(new_dict)

        elif state == "deleted":
            # Delete elements in new_list from existing_list while preserving order
            updated_list = [d for d in existing_list if d not in new_list]

        self.log("Updated List: {0}".format(updated_list), "DEBUG")
        self.log("Existing List: {0}".format(existing_list), "DEBUG")

        # Check if there's a difference
        needs_update = updated_list != existing_list
        self.log("needs_update: {0}, updated_list: {1}".format(needs_update,updated_list), "DEBUG")

        return needs_update, updated_list

    def update_tags_associated_with_the_network_devices(self, payload):
        self.log("Starting to update tags associated with the network devices.", "INFO")

        task_name = "update_tags_associated_with_the_network_devices"

        BATCH_SIZE = 500
        start_index = 0

        while start_index<len(payload):
            batch= payload[start_index: start_index+BATCH_SIZE]
            parameters = {"payload": batch}
            task_id = self.get_taskid_post_api_call("tag", task_name, parameters)
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0} for the batch {1} with the payload {2}'.".format(task_name, start_index//BATCH_SIZE+1 , payload)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                break
            self.log("Successfully retrieved task_id for {0}: {1} for batch {2}.".format(task_name, task_id, start_index//BATCH_SIZE+1), "INFO")
            start_index += BATCH_SIZE

        success_msg = "Updated Tags associated with the network devices successfully in the Cisco Catalyst Center"
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.result["changed"]= True
        return self
    
    def update_tags_associated_with_the_interfaces(self, payload):
        self.log("Starting to update tags associated with the interfaces.", "INFO")

        task_name = "update_tags_associated_with_the_interfaces"
        BATCH_SIZE = 500
        start_index = 0

        while start_index<len(payload):
            batch= payload[start_index: start_index+BATCH_SIZE]
            parameters = {"payload": batch}

            task_id = self.get_taskid_post_api_call("tag", task_name, parameters)
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0} for the payload {1}'.".format(task_name, payload)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                break
            self.log("Successfully retrieved task_id for {0}: {1} for batch {2}.".format(task_name, task_id, start_index//BATCH_SIZE+1), "INFO")
            start_index += BATCH_SIZE

        success_msg = "Updated Tags associated with the interfaces successfully in the Cisco Catalyst Center"
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.result["changed"]= True
        return self

    def updating_tags_membership(self, tags_membership):
        
        device_details= tags_membership.get("device_details")
        new_tags_details = tags_membership.get("tags_name_id")
        self.log("*****")
        self.log(new_tags_details)
        member_details=[]
        if device_details:
            formatted_device_details = self.format_device_details(device_details)
            member_details = member_details + formatted_device_details    
            
        site_details= tags_membership.get("site_details")
        if site_details:
            formatted_site_details = self.format_site_details(site_details)
            member_details = member_details + formatted_site_details    

        interface_details=[]
        network_device_details=[]

        for member_detail in member_details:
            member_type=member_detail.get("device_type")
            if member_type=='networkdevice':
                network_device_details.append(member_detail)
            elif member_type=='interface':
                interface_details.append(member_detail)

        tags_membership["network_device_details"] = network_device_details
        tags_membership["interface_details"] = interface_details
        # member detail type is: (id, device_type(interface/networkdevice), hostname, device_name, Interface name)

        state= self.params.get("state")
        if network_device_details:
            fetched_tags_details = self.get_tags_associated_with_the_network_devices(network_device_details)
            payload=[]
            for network_device_detail in network_device_details:

                device_id = network_device_detail.get("id")
                device_identifier = network_device_detail.get("device_identifier")
                device_value = network_device_detail.get("device_value")
                network_device_detail["tags_list"] = new_tags_details
                
                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    updated_tags_ids=[]
                    for tag_detail in updated_tags:
                        tag_id= tag_detail.get("tag_id")
                        tag_id_dict={
                            "id":tag_id
                        }
                        updated_tags_ids.append(tag_id_dict)
                    MAX_TAGS_LIMIT=500
                    if len(updated_tags_ids)> MAX_TAGS_LIMIT:
                        self.msg="The maximum tag limit exceed for the device with {0}:{1}. The maximum number of tags A device can have is {2}. ".format(device_identifier, device_value, updated_tags_ids)
                        self.set_operation_result("failed", False, self.msg, "ERROR")

                    current_device_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }
                    if state =="merged":
                        self.updated_tags_memberships.append(network_device_detail)
                    elif state =="deleted":
                        self.deleted_tags_memberships.append(network_device_detail)


                    payload.append(current_device_payload)
                else:
                    if state =="merged":
                        network_device_detail["reason"] = "Device is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tags_memberships.append(network_device_detail)
                    elif state =="deleted":
                        network_device_detail["reason"] = "Device is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tags_memberships.append(network_device_detail)

                    # TODO:Log it and save it in list
            if payload:
                self.update_tags_associated_with_the_network_devices(payload)
            else:
                self.log(updated_tags)
                self.log(needs_update)
                self.log("No payload generated for updating tags associated with the network devices", "DEBUG")

        if interface_details:
            fetched_tags_details = self.get_tags_associated_with_the_interfaces(interface_details)
            payload=[]
            for interface_detail in interface_details:
                device_id = interface_detail.get("id")
                interface_detail["tags_list"] = new_tags_details
                device_identifier = interface_detail.get("device_identifier")
                device_value = interface_detail.get("device_value")
                interface_name = interface_detail.get("interface_name")


                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    updated_tags_ids=[]
                    for tag_detail in updated_tags:
                        tag_id= tag_detail.get("tag_id")
                        tag_id_dict={
                            "id":tag_id
                        }
                        updated_tags_ids.append(tag_id_dict)

                    
                    MAX_TAGS_LIMIT=500
                    if len(updated_tags_ids)> MAX_TAGS_LIMIT:
                        self.msg="The maximum tag limit exceed for the interface: {0} with {1}:{2}. The maximum number of tags A device can have is {3}. ".format(interface_name, device_identifier, device_value, updated_tags_ids)
                        self.set_operation_result("failed", False, self.msg, "ERROR")
                    current_interface_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }

                    if state =="merged":
                        self.updated_tags_memberships.append(interface_detail)
                    elif state =="deleted":
                        self.deleted_tags_memberships.append(interface_detail)

                    payload.append(current_interface_payload)
                else:
                    if state =="merged":
                        interface_detail["reason"] = "Interface is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tags_memberships.append(interface_detail)
                    elif state =="deleted":
                        interface_detail["reason"] = "Interface is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tags_memberships.append(interface_detail)
                    # TODO:Log it and save it in list

            if payload:
                self.update_tags_associated_with_the_interfaces(payload)
            else:
                self.log("No payload generated for updating tags associated with the interfaces", "DEBUG")

        self.log("Interfaces: {0}".format(interface_details))
        self.log("NetworkDevices: {0}".format(network_device_details))

    def compare_and_update_scope_description(self, scope_description, scope_description_in_ccc):

        requires_update = False

        # Scope Description in CCC can't be None
        if scope_description is None:
            return requires_update, scope_description_in_ccc

        group_type = scope_description.get("groupType") 
        group_type_in_ccc = scope_description_in_ccc.get("groupType") 

        group_members =  scope_description.get("scopeObjectIds")
        group_members_in_ccc =  scope_description_in_ccc.get("scopeObjectIds")
        
        inherit = scope_description.get("inherit")
        inherit_in_ccc = scope_description_in_ccc.get("inherit")

        
        updated_scope_description = {}

        if group_type== group_type_in_ccc:
            if inherit != inherit_in_ccc:
                requires_update = True

            tmp_requires_update, updated_group_members = self.compare_and_update_list(group_members_in_ccc, group_members)
            requires_update= requires_update | tmp_requires_update

            if not updated_group_members:
                # User wants to delete all the group members, so returning empty updated_scope_description 
                return requires_update, updated_scope_description

            updated_scope_description["groupType"] = group_type
            updated_scope_description["inherit"] = inherit
            updated_scope_description["scopeObjectIds"] = updated_group_members

        else:
            state = self.params.get("state")
            if state=="deleted":
                self.msg="""In Case of state:{0}, the grouping_category should be same as present in Cisco Catalist Center
                grouping_category provided:'{1}', grouping_category in Cisco Catalyst Center:'{2}'""".format(state, group_type, group_type_in_ccc)
                self.set_operation_result("failed", False, self.msg, "ERROR")

            requires_update = True
            updated_scope_description["groupType"] = group_type
            updated_scope_description["inherit"] = scope_description.get("inherit")
            updated_scope_description["scopeObjectIds"] = group_members

        updated_scope_description["memberType"] = "networkdevice"

        self.log(scope_description)
        self.log(scope_description_in_ccc)
        self.log(requires_update)

        return requires_update, updated_scope_description
        
    def ungroup_rules_tree_into_list(self, rules):
        """
        Recursively extracts all leaf nodes (base rules) from the given dictionary structure.
        """
        if rules is None:
            self.log("rules is {0}. Returning None".format(rules), "DEBUG")
            return None
        leaf_nodes = []
        
        # Check if the current dictionary has 'items' (indicating nested conditions)
        if isinstance(rules, dict) and 'items' in rules:
            for item in rules['items']:
                # Recursively process each item
                leaf_nodes.extend(self.ungroup_rules_tree_into_list(item))
        else:
            # If no 'items', it's a leaf node
            leaf_nodes.append(rules)
        
        
        self.log("Ungrouped rules for Input:{0} is Output:{1}".format(rules, leaf_nodes), "DEBUG")
        return leaf_nodes

    def compare_and_update_rules(self, rules, rules_in_ccc, tag_name):

        requires_update= False
        ungrouped_rules = self.ungroup_rules_tree_into_list(rules) 
        ungrouped_rules_in_ccc = self.ungroup_rules_tree_into_list(rules_in_ccc) 
        state = self.params.get("state")

        if state =="merged":
            if ungrouped_rules is None and ungrouped_rules_in_ccc is None:
                return requires_update, None
            if ungrouped_rules is None: # Nothing to update case
                return requires_update, ungrouped_rules_in_ccc
            if ungrouped_rules_in_ccc is None: # Updating it with the new rules
                requires_update= True
                return requires_update, ungrouped_rules
        if state =="deleted":
            if ungrouped_rules is None and ungrouped_rules_in_ccc is None:
                return requires_update, None
            if ungrouped_rules is None: # Nothing to delete case
                return requires_update, ungrouped_rules_in_ccc
            if ungrouped_rules_in_ccc is None: # Nothing to delete case
                return requires_update, ungrouped_rules_in_ccc

        requires_update, updated_rules = self.compare_and_update_list_of_dict(ungrouped_rules_in_ccc, ungrouped_rules)

        # if state == "merged":
        #     for new_dict in ungrouped_rules:
        #         tmp_rule_dict={
        #             "tag_name": tag_name,
        #             "rule_description":self.unformat_rule_representation(new_dict)
        #         }
        #         if new_dict not in ungrouped_rules_in_ccc:  # Check if new_dict is already in existing_list
        #             self.updated_rule.append(tmp_rule_dict)
        #         else:
        #             self.not_updated_rule.append(tmp_rule_dict)
        # elif state == "deleted":
        #     for rule in ungrouped_rules:
        #         tmp_rule_dict={
        #             "tag_name": tag_name,
        #             "rule_description":self.unformat_rule_representation(rule)
        #         }
        #         if rule not in ungrouped_rules_in_ccc:
        #             self.not_deleted_rule.append(tmp_rule_dict)
        #         else:
        #             self.deleted_rule.append(tmp_rule_dict)


        updated_rules = self.group_rules_into_tree(updated_rules)
        self.log("Comparing rules:{0} and rules_in_ccc:{1}\nrequires_update:{2}, updated_rules:{3}".format(rules, rules_in_ccc, requires_update, updated_rules), "DEBUG")
        
        return requires_update, updated_rules

    def compare_and_update_port_rules(self, port_rules, port_rules_in_ccc, tag_name):
        
        requires_update = False

        state = self.params.get("state")
        if state== "merged":
            # Both are Absent
            if port_rules is None and port_rules_in_ccc is None:
                return requires_update, None

            # One is Absent, as nothing to merge, So No update required
            if port_rules is None:
                return requires_update, port_rules_in_ccc
            
            if port_rules_in_ccc is None:
                #  Update is required, In existing there are No port_rules, so both scope and rules are required.
                requires_update = True
                scope_description = port_rules.get("scopeRule")
                rules = port_rules.get("rules")
                if not scope_description or not rules:
                    self.msg="""Either of rule_description:{0} or scope_description:{1} is empty in port_rules. 
                    As existing port_rules are not present in Cisco Catalyst Center, Both are required for an update (i.e. first time creation)""".format(rules, scope_description)
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                return requires_update, port_rules
            
        elif state =="deleted":
            # Both are Absent
            if port_rules is None and port_rules_in_ccc is None:
                return requires_update, None

            # One is Absent, Existing No port rules so nothing to delete
            if port_rules_in_ccc is None:
                return requires_update, port_rules_in_ccc
            # One is Absent, No new port rules in playbook, so nothing to delete
            if port_rules is None:
                return requires_update, port_rules_in_ccc
            
        #  Both exist case:

        scope_description = port_rules.get("scopeRule")
        scope_description_in_ccc = port_rules_in_ccc.get("scopeRule")

        tmp_required_update, updated_scope_description = self.compare_and_update_scope_description(scope_description, scope_description_in_ccc)
        requires_update = tmp_required_update | requires_update

        rules = port_rules.get("rules")
        rules_in_ccc = port_rules_in_ccc.get("rules")

        tmp_requires_update, updated_rules= self.compare_and_update_rules(rules, rules_in_ccc, tag_name)
        requires_update = tmp_requires_update | requires_update

        updated_port_rules={}

        if not updated_scope_description and not updated_rules:
            return requires_update, updated_port_rules 
        if not updated_scope_description or not updated_rules:
            self.msg= """On deletion, Either scope_description:{0} or rule_descriptions:{1} for port_rules are getting completed empty.
            Atleast one parameter must be left in both to proceed with the deletion""".format(updated_scope_description, updated_rules)
            self.set_operation_result("failed", False, self.msg, "ERROR")
        
        updated_port_rules={
            "memberType" : "interface",
            "rules": updated_rules,
            "scopeRule" : updated_scope_description
        }
        self.log(requires_update)

        return requires_update, updated_port_rules
        
    def compare_and_update_device_rules(self, device_rules, device_rules_in_ccc, tag_name):
        
        requires_update = False

        state = self.params.get("state")

        if state== "merged":
            # Both are Absent
            if device_rules_in_ccc is None and device_rules is None:
                return requires_update, None

            # One is Absent
            if device_rules is None:
                #  No merge required
                return requires_update, device_rules_in_ccc
            
            #  device_rules is Not None, so update required
            if device_rules_in_ccc is None:
                requires_update = True
                return requires_update, device_rules

        
        elif state =="deleted":
            # Both are Absent
            if device_rules_in_ccc is None and device_rules is None:
                return requires_update, None

            # Any one is absent, device_rules is none so, nothing to delete
            if device_rules is None:
                return requires_update, device_rules_in_ccc
            
            # Any one is absent, device_rules_in_ccc is None, so nothing to delete
            if device_rules_in_ccc is None:
                return requires_update, device_rules_in_ccc


        #  Both are present case
        rules = device_rules.get("rules")
        rules_in_ccc = device_rules_in_ccc.get("rules")

        tmp_requires_update, updated_rules= self.compare_and_update_rules(rules, rules_in_ccc, tag_name)
        requires_update = tmp_requires_update | requires_update

        updated_device_rules = {}
        if updated_rules:
            updated_device_rules={
                "memberType" : "networkdevice",
                "rules": updated_rules,
            }
        self.log(requires_update)
        return requires_update, updated_device_rules

    def compare_and_update_tag(self, tag, tag_in_ccc):

        requires_update= False

        tag_name= tag.get("name")
        description= tag.get("description")
        device_rules = tag.get("device_rules")
        port_rules = tag.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)
        formatted_port_rules = self.format_port_rules(port_rules)


        tag_name_in_ccc= tag_in_ccc.get("name")
        description_in_ccc= tag_in_ccc.get("description")
        dynamic_rules_in_ccc = tag_in_ccc.get("dynamicRules",[])
        dynamic_rule_dict_in_ccc={}

        for dynamic_rule_in_ccc in dynamic_rules_in_ccc:
            member_type_in_ccc= dynamic_rule_in_ccc.get("memberType")
            if member_type_in_ccc == "interface":
                scope_description_in_ccc = dynamic_rule_in_ccc.get("scopeRule")
                rules_in_ccc = dynamic_rule_in_ccc.get("rules")
                dynamic_rule_dict_in_ccc["formatted_port_rules_in_ccc"] = {
                    "memberType" : member_type_in_ccc,
                    "rules": rules_in_ccc,
                    "scopeRule" : scope_description_in_ccc
                }
            elif member_type_in_ccc == "networkdevice":
                rules_in_ccc = dynamic_rule_in_ccc.get("rules")
                dynamic_rule_dict_in_ccc["formatted_device_rules_in_ccc"] = {
                    "memberType" : member_type_in_ccc,
                    "rules": rules_in_ccc,
                }
        
        formatted_device_rules_in_ccc = dynamic_rule_dict_in_ccc.get("formatted_device_rules_in_ccc")
        formatted_port_rules_in_ccc = dynamic_rule_dict_in_ccc.get("formatted_port_rules_in_ccc")

        updated_tag_info={}
        if tag_name != tag_name_in_ccc:
            requires_update = True

        if description != description_in_ccc:
            requires_update = True

        tmp_requires_update, updated_device_rules = self.compare_and_update_device_rules(formatted_device_rules, formatted_device_rules_in_ccc, tag_name)
        requires_update = tmp_requires_update | requires_update

        tmp_requires_update, updated_port_rules = self.compare_and_update_port_rules(formatted_port_rules, formatted_port_rules_in_ccc, tag_name)
        requires_update = tmp_requires_update | requires_update

        updated_dynamic_rules= self.combine_device_port_rules(updated_device_rules, updated_port_rules)

        updated_tag_info={
            "name": tag_name,
            "description": description,
        }
        if updated_dynamic_rules:
            updated_tag_info["dynamic_rules"] = updated_dynamic_rules

        self.log(requires_update)

        return requires_update, updated_tag_info
        
    def update_tag(self, tag, tag_id):

        tag_name= tag.get("name")
        description= tag.get("description")
        tag_payload={
            "name": tag_name,
            "description": description,
            "id": tag_id
        }
        dynamic_rules = tag.get("dynamic_rules")
        if dynamic_rules:
            tag_payload["dynamicRules"] = dynamic_rules
        task_name = "update_tag"
        paramaters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, paramaters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        success_msg = "Tag: '{0}' updated successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.updated_tag.append(tag_name)
        self.result["changed"]= True

        return self

    def delete_tag(self, tag, tag_id):
        self.log("Starting the API call to delete tag:'{0}'".format(tag.get("name")), "DEBUG")
        tag_name= tag.get("name")
        task_name = "delete_tag"
        paramaters = {"id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, paramaters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag.get("name"))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        success_msg = "Tag: '{0}' deleted successfully in the Cisco Catalyst Center".format(tag.get("name"))
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.deleted_tag.append(tag_name)
        self.result["changed"]= True
        return self

    def get_tag_members(self, tag, tag_id):
        self.log("Starting retrieval of members assicoated with the tag:'{0}'".format(tag.get("name")), "DEBUG")
        member_details=[]
        tag_name = tag.get("name")
        offset = 1
        while True:
            try:
                self.log(tag_id)
                response = self.dnac._exec(
                    family="tag",
                    function='get_tag_members_by_id',
                    op_modifies=True,
                    params={
                        "id": tag_id,
                        "member_type": "networkdevice",
                        "offset": offset,
                    },
                )
                response = response.get("response")
                self.log("Received API response from 'get_tag_members_by_id' for the tag '{0}': {1}".format(tag_name, str(response)), "DEBUG")
                if not response:
                    break

                for device_detail in response:
                    device_id = device_detail.get("instanceUuid")
                    device_name = self.get_device_name_by_id(device_id)
                    device_detail_dict={
                        "id":device_id,
                        "device_type": "networkdevice",
                        "device_identifier": "hostname",
                        "device_value": device_name,
                    }
                    member_details.append(device_detail_dict)

            except Exception as e:
                self.msg = """Error while getting the details of Tag Members with given name '{0}' present in
                Cisco Catalyst Center: {1}""".format(tag_name, str(e))
                self.fail_and_exit(self.msg)
            offset += 500

        #  For Interfaces
        offset = 1
        while True:
            try:
                self.log(tag_id)
                response = self.dnac._exec(
                    family="tag",
                    function='get_tag_members_by_id',
                    op_modifies=True,
                    params={
                        "id": tag_id,
                        "member_type": "interface",
                        "offset": offset,
                    },
                )
                response = response.get("response")
                self.log("Received API response from 'get_tag_members_by_id' for the tag '{0}': {1}".format(tag_name, str(response)), "DEBUG")
                if not response:
                    break

                for interface_detail in response:
                    interface_id = interface_detail.get("instanceUuid")
                    device_id = interface_detail.get("deviceId")
                    interface_name= interface_detail.get("portName")
                    device_name = self.get_device_name_by_id(device_id)
                    interface_detail_dict={
                        "id": interface_id,
                        "device_type": "interface",
                        "device_identifier": "hostname",
                        "device_value": device_name,
                        "interface_name":interface_name
                    }
                    member_details.append(interface_detail_dict)

            except Exception as e:
                self.msg = """Error while getting the details of Tag Members with given name '{0}' present in
                Cisco Catalyst Center: {1}""".format(tag_name, str(e))
                self.fail_and_exit(self.msg)
            offset += 500

        self.log(member_details)
        return member_details

    def force_delete_tag_memberships(self, tag, tag_id):
        
        tag_name= tag.get("name")
        member_details= self.get_tag_members(tag, tag_id)
        interface_details=[]
        network_device_details=[]

        new_tags_details=[
            {
                "tag_name":tag_name,
                "tag_id":tag_id
            }
        ]
        for member_detail in member_details:
            member_type=member_detail.get("device_type")
            if member_type=='networkdevice':
                network_device_details.append(member_detail)
            elif member_type=='interface':
                interface_details.append(member_detail)

        state= self.params.get("state")
        if network_device_details:
            fetched_tags_details = self.get_tags_associated_with_the_network_devices(network_device_details)
            payload=[]
            for network_device_detail in network_device_details:

                device_id = network_device_detail.get("id")
                network_device_detail["tags"] = new_tags_details
                
                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    updated_tags_ids=[]
                    for tag_detail in updated_tags:
                        tag_id= tag_detail.get("tag_id")
                        tag_id_dict={
                            "id":tag_id
                        }
                        updated_tags_ids.append(tag_id_dict)
                    current_device_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }
                    network_device_detail["state"]= self.params.get("state")
                    if state =="merged":
                        self.updated_tags_memberships.append(network_device_detail)
                    elif state =="deleted":
                        self.deleted_tags_memberships.append(network_device_detail)
                    payload.append(current_device_payload)
                else:
                    network_device_detail["reason"] = "Already up to date, No new tags to update." 
                    if state =="merged":
                        network_device_detail["reason"] = "Device is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tags_memberships.append(network_device_detail)
                    elif state =="deleted":
                        network_device_detail["reason"] = "Device is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tags_memberships.append(network_device_detail)


            if payload:
                self.update_tags_associated_with_the_network_devices(payload)
            else:
                self.log(updated_tags)
                self.log(needs_update)
                self.log("No payload generated for updating tags associated with the network devices", "DEBUG")

        if interface_details:
            fetched_tags_details = self.get_tags_associated_with_the_interfaces(interface_details)
            payload=[]
            for interface_detail in interface_details:
                device_id = interface_detail.get("id")
                interface_detail["tags"] = new_tags_details

                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    updated_tags_ids=[]
                    for tag_detail in updated_tags:
                        tag_id= tag_detail.get("tag_id")
                        tag_id_dict={
                            "id":tag_id
                        }
                        updated_tags_ids.append(tag_id_dict)
                    current_interface_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }
                    self.updated_tags_memberships.append(interface_detail)

                    interface_detail["state"]= self.params.get("state")
                    payload.append(current_interface_payload)
                else:
                    interface_detail["reason"] = "Already up to date, No new tags to update." 

                    self.not_updated_tags_memberships.append(interface_detail)
                    # TODO:Log it and save it in list

            if payload:
                self.update_tags_associated_with_the_interfaces(payload)
            else:
                self.log("No payload generated for updating tags associated with the interfaces", "DEBUG")

        self.log("Interfaces: {0}".format(interface_details))
        self.log("NetworkDevices: {0}".format(network_device_details))

    def get_diff_merged(self, config):
        tag = self.want.get("tags")
        tags_membership = self.want.get("tags_membership")

        if tag:
            tag_name = tag.get("name")
            self.log("Starting Tag Creation/Updation for the Tag: {0}".format(tag_name), "DEBUG")
            tag_in_ccc= self.have.get("tag_info")
            if not tag_in_ccc:
                self.log("Starting the process of creating {0} Tag with config: {1}".format(tag_name, tag), "DEBUG")
                self.create_tag(tag).check_return_status()
            
            else:
                self.log("Tag: {0} is already present in Cisco Catalyst Center with details: {1}".format(tag_name, tag_in_ccc), "DEBUG")
                requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)

                if requires_update:
                    self.update_tag(tag = updated_tag_info, tag_id= tag_in_ccc.get("id"))
                else:
                    self.not_updated_tag.append(tag_name)
                    # TODO: Log and update as required.
                self.log(requires_update)
                self.log(updated_tag_info)

            # # IMP: TODO: planning to discontinue assign_members, because of added complexity in the final verdict printing functions.
            # assign_members = tag.get("assign_members")
            # if assign_members:
            #     self.assign_members_on_tag_creation(tag)

        if tags_membership:
            self.log("Starting Tag Membership Creation/Updation", "DEBUG")
            tag_names = tags_membership.get("tags")
            tags_details_list=[]
            for tag_name in tag_names:
                self.log(tag_name)
                tag_id = self.get_tag_id(tag_name)
                if tag_id is None:
                    self.msg="Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(tag_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR")

                else:
                    tag_detail_dict={
                        "tag_id":tag_id,
                        "tag_name":tag_name
                    }
                    tags_details_list.append(tag_detail_dict)
                    
            tags_membership["tags_name_id"] = tags_details_list
            self.updating_tags_membership(tags_membership)

        return self
    
    def get_diff_deleted(self, config):
        tag = self.want.get("tags")
        tags_membership = self.want.get("tags_membership")

        if tag:
            tag_name= tag.get("name")
            self.log("Starting Tag Deletion for the Tag: {0}".format(tag_name), "DEBUG")
            pass
            tag_in_ccc= self.have.get("tag_info")
            self.log(tag_in_ccc)
            if not tag_in_ccc:
                self.log("Not able to delete Tag {0} as it is not present in Cisco Catalyst Center.".format(tag_name), "DEBUG")
                self.absent_tag.append(tag_name)
            else:
                tag_id= tag_in_ccc.get("id")
                force_delete= tag.get("force_delete")
                description= tag.get("description")
                device_rules= tag.get("device_rules")
                port_rules= tag.get("port_rules")

                if force_delete:
                    tmp_tag={
                        "name": tag_name
                    }
                    # Updating the Tag with no dynamic rules to remove dynamic_members
                    self.update_tag(tmp_tag,tag_id)
                    # Deleting this tag from all the current members.
                    self.force_delete_tag_memberships(tag, tag_id)
                    # Now it has no members, so it will get deleted without any errors.
                    self.delete_tag(tag, tag_id)
                    
                    self.deleted_tag.append(tag_name)
                else:
                    if not description and not device_rules and not port_rules:
                        # Entire Tag Deletion Case
                        self.log("WEEEEEEEEEEE")
                        tag_id = tag_in_ccc.get("id")
                        self.delete_tag(tag, tag_id)
                        self.deleted_tag.append(tag_name)
                    else:
                        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)
                        self.log(requires_update)
                        self.log(updated_tag_info)
                        if requires_update:
                            self.update_tag(tag = updated_tag_info, tag_id= tag_in_ccc.get("id"))
                            self.updated_tag.append(tag_name)
                        else:
                            self.not_updated_tag.append(tag_name)
                            # TODO: Log andf save properly

        if tags_membership:
            self.log("Starting Tag Membership Creation/Updation", "DEBUG")
            tag_names = tags_membership.get("tags")
            tags_details_list=[]
            for tag_name in tag_names:
                self.log(tag_name)
                tag_id = self.get_tag_id(tag_name)
                if tag_id is None:
                    self.msg="Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(tag_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR")

                else:
                    tag_detail_dict={
                        "tag_id":tag_id,
                        "tag_name":tag_name
                    }
                    tags_details_list.append(tag_detail_dict)
                    
            tags_membership["tags_name_id"] = tags_details_list
            self.updating_tags_membership(tags_membership)


        return self

    def verify_tag_membership_diff(self, tags_membership):
        interface_details=tags_membership.get("interface_details")
        network_device_details=tags_membership.get("network_device_details")
        new_tags_details = tags_membership.get("tags_name_id")
        verify_success = True
        if network_device_details:
            fetched_tags_details = self.get_tags_associated_with_the_network_devices(network_device_details)
            for network_device_detail in network_device_details:
                device_id = network_device_detail.get("id")
                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    verify_success = False
                    device_identifier = network_device_detail.get("device_identifier")
                    device_value = network_device_detail.get("device_value")
                    self.log("Tag membership in Cisco catalyst center for device with {0}:{1} is different than provided in the playbook. Playbook operation might not be successful".format(device_identifier, device_value), "WARNING")

        if interface_details:
            fetched_tags_details = self.get_tags_associated_with_the_interfaces(interface_details)
            for interface_detail in interface_details:
                device_id = interface_detail.get("id")
                interface_detail["tags_list"] = new_tags_details

                needs_update, updated_tags = self.compare_and_update_list_of_dict(fetched_tags_details.get(device_id), new_tags_details)
                if needs_update:
                    verify_success = False
                    device_identifier = interface_detail.get("device_identifier")
                    device_value = interface_detail.get("device_value")
                    interface_name = interface_detail.get("interface_name")
                    self.log("Tag membership in Cisco catalyst center for the interface {0} belonging to device with {1}:{2} is different than provided in the playbook. Playbook operation might not be successful".format(interface_name, device_identifier, device_value), "WARNING")

        return verify_success

    def verify_diff_merged(self, config):
        self.get_have(config).check_return_status()
        tag = self.want.get("tags")
        tags_membership = self.want.get("tags_membership")
        verify_diff=True
        if tag:
            tag_in_ccc= self.have.get("tag_info")
            tag_name= tag.get("name")
            if not tag_in_ccc:
                verify_diff = False
                self.log("Tag {0} not found in Cisco Catalyst Center. Merged playbook operation might be unsuccessful".format(tag_name), "WARNING")
            else:
                self.log("Checking for Tag {0} if the details are same in playbook and Cisco Catalyst Center".format(tag_name), "DEBUG")
                requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)

                if requires_update:
                    verify_diff = False
                    self.log("Tags Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful".format(tag_name), "WARNING")
                else:
                    self.log("Tags Details present in playbook and Cisco Catalyst Center are same.".format(tag_name), "DEBUG")

            # # IMP: TODO: planning to discontinue assign_members, because of added complexity in the final verdict printing functions.
            # assign_members = tag.get("assign_members")
            # if assign_members:
            #     self.assign_members_on_tag_creation(tag)

        if tags_membership:
            membership_verify_diff = self.verify_tag_membership_diff(tags_membership)
            if membership_verify_diff:
                self.log("Tags Membership Details present in playbook and Cisco Catalyst Center are same.", "DEBUG")
            else:
                verify_diff = False
                self.log("Tags Membership Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful", "WARNING")
        
        if verify_diff:
            self.msg="Playbook operation is successful"
            self.log(self.msg, "INFO")
        else:
            self.msg="Playbook operation is unsuccessful"
            self.log(self.msg, "WARNING")
        return self

    def verify_diff_deleted(self, config):

        self.get_have(config).check_return_status()
        tag = self.want.get("tags")
        tags_membership = self.want.get("tags_membership")

        verify_diff= True
        if tag:
            tag_name= tag.get("name")
            tag_in_ccc= self.have.get("tag_info")
            force_delete= tag.get("force_delete")

            if force_delete:
                if not tag_in_ccc:
                    self.log("Tag {0} is not present in Cisco Catalyst Center.".format(tag_name), "DEBUG")
                else:
                    verify_diff = False
                    self.log("Tag {0} is found in Cisco Catalyst Center. Playbook operation might be unsuccessful.".format(tag_name), "WARNING")
            else:
                description= tag.get("description")
                device_rules= tag.get("device_rules")
                port_rules= tag.get("port_rules")

                if description or device_rules or port_rules:
                    #  Updation Case
                    if not tag_in_ccc:
                        verify_diff = False
                        self.log("Tag {0} is not found in Cisco Catalyst Center. It should have been present. Playbook operation might be unsuccessful".format(tag_name), "WARNING")
                    else:
                        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)
                        if requires_update:
                            verify_diff = False
                            self.log("Tag details for Tag:{0} are different in Cisco Catalyst Center and Playbook. Playbook operation might be unsuccessful".format(tag_name), "WARNING")
                        else:
                            self.log("Tag details for Tag:{0} are same in Cisco Catalyst Center and Playbook.".format(tag_name), "DEBUG")
                            # TODO: Log andf save properly
                else:
                    # Simple Tag Deletion Case
                    if not tag_in_ccc:
                        self.log("Tag {0} is not present in Cisco Catalyst Center".format(tag_name),"DEBUG")
                    else:
                        verify_diff = False
                        self.log("Tag {0} is still present in Cisco Catalyst Center. Playbook operation might be unsuccessful".format(tag_name),"WARNING")

        if tags_membership:
            membership_verify_diff = self.verify_tag_membership_diff(tags_membership)
            if membership_verify_diff:
                self.log("Tags Membership Details present in playbook and Cisco Catalyst Center are same.", "DEBUG")
            else:
                verify_diff = False
                self.log("Tags Membership Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful", "WARNING")
        
        if verify_diff:
            self.msg="Playbook operation is successful"
            self.log(self.msg, "INFO")
        else:
            self.msg="Playbook operation is unsuccessful"
            self.log(self.msg, "WARNING")
        return self

    def int_fail(self, msg="Intentional Fail :)"):
        self.msg = msg
        self.set_operation_result("failed", False, self.msg, "ERROR")
        self.check_return_status()

    def debugg(self, msg="Sample Debug Message"):
        self.log(msg, "DEBUG")

    def generate_tagging_message(self, action, membership):
        """Generate a tagging/un-tagging message dynamically using .format()."""

        device_type = membership.get("device_type")
        device_identifier = membership.get("device_identifier")
        device_value = membership.get("device_value")
        site_name = membership.get("site_name", "")
        tags_list = membership.get("tags_list")
        reason = membership.get("reason", "")  
        interface_name = membership.get("interface_name", "")

        if device_type == "networkdevice":
            base_msg = "The Device with {0}: {1}".format(device_identifier, device_value)
        elif device_type == "interface":
            base_msg = "The Interface {0} of device with {1}: {2}".format(interface_name, device_identifier, device_value)
        else:
            return ""

        if site_name:
            base_msg += " under site:{0}".format(site_name)

        tag_names = ", ".join(tag.get("tag_name", "Unknown") for tag in tags_list) if tags_list else "any tags"

        if action == "updated":
            return "{0} has been tagged to {1}".format(base_msg, tag_names)
        elif action == "not_updated":
            return "{0} has not been tagged to {1} because: {2}".format(base_msg, tag_names, reason)
        elif action == "deleted":
            return "{0} has been untagged from {1}".format(base_msg, tag_names)
        elif action == "not_deleted":
            return "{0} has not been untagged from {1} because: {2}".format(base_msg, tag_names, reason)
        
        return ""

    def update_tags_profile_messages(self):

    #  List of member_details schema
    # {
    #     "id": device_id, 
    #     "device_type": "networkdevice"/"interface",
    #     "device_identifier": "hostname", etc
    #     "device_value": device_name, etc
    #     "interface_name": interface_name/None
    #     "site_name": site_name/None
    #     "reason": Failing Reason.. Only present in not_updated/not_deleted_tag_memberships
    #     "tags_list":[List of tag names]  in all memberships
    # }

    # List of tags schema
    # {
    #     "tag_name": TAG_NAME,
    #     "tag_id": TAG_ID
    # }

        self.result["changed"] = False
        result_msg_list = []

        if self.created_tag:
            created_tag_msg = "Tag '{0}' has been created successfully in Cisco Catalyst Center.".format(self.created_tag[0])
            result_msg_list.append(created_tag_msg)

        if self.updated_tag:
            updated_tag_msg = "Tag '{0}' has been updated successfully in Cisco Catalyst Center.".format(self.updated_tag[0])
            result_msg_list.append(updated_tag_msg)

        if self.not_updated_tag:
            not_updated_tag_msg = "Tag '{0}' needs no update in Cisco Catalyst Center.".format(self.not_updated_tag[0])
            result_msg_list.append(not_updated_tag_msg)

        if self.deleted_tag:
            deleted_tag_msg = "Tag '{0}' has been deleted successfully in Cisco Catalyst Center.".format(self.deleted_tag[0])
            result_msg_list.append(deleted_tag_msg)

        if self.absent_tag:
            absent_tag_msg = "Tag '{0}' is not deleted. It is not present in Cisco Catalyst Center.".format(self.absent_tag[0])
            result_msg_list.append(absent_tag_msg)

        for action, memberships in [
            ("updated", self.updated_tags_memberships),
            ("not_updated", self.not_updated_tags_memberships),
            ("deleted", self.deleted_tags_memberships),
            ("not_deleted", self.not_deleted_tags_memberships),
        ]:
            if memberships:
                for membership in memberships:
                    message = self.generate_tagging_message(action, membership)
                    if message:
                        result_msg_list.append(message)
        
        if self.created_tag or self.updated_tag or self.deleted_tag or self.updated_tags_memberships or self.deleted_tags_memberships:
            self.result["changed"] = True

        self.msg = ("\n").join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self

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
    if ccc_tags.compare_dnac_versions(ccc_tags.get_ccc_version(), "2.3.7.9") < 0:
        ccc_tags.msg = (
            "The specified version '{0}' does not support the tagging feature. Supported versions start "
            "  from '2.3.7.9' onwards. Version '2.3.7.9' introduces APIs for creating, updating and deleting the "
            "tags and Tag memberships."
            .format(ccc_tags.get_ccc_version())
        )
        ccc_tags.set_operation_result(
            "failed", False, ccc_tags.msg, "ERROR").check_return_status()

    state = ccc_tags.params.get("state")


    if state not in ccc_tags.supported_states:
        ccc_tags.status = "invalid"
        ccc_tags.msg = "State {0} is invalid".format(state)
        ccc_tags.check_return_status()

    # ccc_tags.debugg("PRECHECK at 407")
    ccc_tags.validate_input().check_return_status()
    ccc_tags.debugg(f"Validated Config: {ccc_tags.validated_config}")
    config_verify = ccc_tags.params.get("config_verify")

    for config in ccc_tags.validated_config:
        ccc_tags.reset_values()
        ccc_tags.get_want(config).check_return_status()
        ccc_tags.get_have(config).check_return_status()

        ccc_tags.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_tags.verify_diff_state_apply[state](config).check_return_status()

    ccc_tags.update_tags_profile_messages().check_return_status()

    module.exit_json(**ccc_tags.result)


# Tasks:
# 1) Make design changes, tags to tag and name to tag_name/tag_names
# 2) ADD PROPER LOGS AND TEST THE ENTIRE WORKFLOW READING ALL THE LOGS, ALSO CHECK ALL THE LOGS.
# 3) Documentation:
# 4) SwFS doc
# 5) Proper Logging, code refactoring.
# 6) TESTING


#  Bugs:
# 1) Changed not working properly:
# - tags:
#     name: TEST101
#     force_delete: True
# tags_membership:
#     tags:
#     - TEST101
#     device_details:
#     - ip_addresses:
#         - 22.1.1.1 
# make and delete it to reproduce.

if __name__ == '__main__':
    main()
