#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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
        self.create_tag, self.update_tag, self.no_update_tag = [], [], []
        self.delete_tag, self.absent_tag= [], []

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
                        'inherit': {'type': 'bool', 'default': False},
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
                family="sites",
                function='get_site',
                op_modifies=True,
                params={"name": site_name},
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
            tag_id= self.get_tag_id(tag_name)
            if not tag_id:
                self.msg= "Tag ID for {0} not available in Cisco Catalyst Center".format(tag_name)
                self.log(self.msg, "DEBUG")
            else:
                have["tag_id"]= tag_id
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
            return device_rules
        
        rule_descriptions= device_rules.get("rule_descriptions")
        
        formatted_rule_descriptions=[]
        for device_rule in rule_descriptions:
            formatted_rule_description= self.format_rule_representation(device_rule)
            formatted_rule_descriptions.append(formatted_rule_description)

        # Sorting it so that its easier to compare.
        formatted_rule_descriptions= self.sorting_rule_descriptions(formatted_rule_descriptions)

        grouped_device_rules= self.group_rules_into_tree(formatted_rule_descriptions)
        
        self.log(formatted_rule_descriptions, "DEBUG")
        self.log(grouped_device_rules, "DEBUG")
        
        formatted_device_rules = {
            "memberType" : "networkdevice",
            "rules": grouped_device_rules
        }

        return formatted_device_rules

    def format_scope_description(self, scope_description):
        
        grouping_category= scope_description.get("grouping_category")
        group_members= scope_description.get("group_members")
        group_members_ids=[]
        if grouping_category == "TAG":
            for tag in group_members:
                tag_id= self.get_tag_id(tag)
                if tag_id is None:
                    self.msg= (
                        "Grouping Member provided: {0} is Not present in Cisco Catalyst Center."
                        "Please ensure that the group_members and grouping category provided are valid"
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

        return formatted_scope_description
        
    def format_port_rules(self, port_rules):
        
        if port_rules is None:
            return port_rules
        
        rule_descriptions= port_rules.get("rule_descriptions")
        scope_description= port_rules.get("scope_description")

        self.log(port_rules, "DEBUG")
        
        formatted_rule_descriptions=[]
        for port_rule in rule_descriptions:
            formatted_rule_description= self.format_rule_representation(port_rule)
            formatted_rule_descriptions.append(formatted_rule_description)

        # Sorting it so that its easier to compare.
        formatted_rule_descriptions_list= self.sorting_rule_descriptions(formatted_rule_descriptions)
        
        # Converting the sorted list to tree structure.
        formatted_rule_descriptions= self.group_rules_into_tree(formatted_rule_descriptions_list)
        
        formatted_scope_description= self.format_scope_description(scope_description)

        self.log(formatted_rule_descriptions_list, "DEBUG")
        self.log(formatted_rule_descriptions, "DEBUG")
        
        formatted_port_rules = {
            "memberType" : "interface",
            "rules": formatted_rule_descriptions,
            "scopeRule" : formatted_scope_description
        }

        return formatted_port_rules
        
    def combine_device_port_rules(self, device_rules, port_rules):
        
        dynamic_rules=[]
        if device_rules:
            dynamic_rules.append(device_rules)
        if port_rules:
            dynamic_rules.append(port_rules)

        return dynamic_rules

    def create_tag(self, tags):

        tag_name= tags.get("name")
        description= tags.get("description")
        device_rules = tags.get("device_rules")
        port_rules = tags.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)

        formatted_port_rules = self.format_port_rules(port_rules)

        dynamic_rules= self.combine_device_port_rules(formatted_device_rules, formatted_port_rules)
        
        tag_payload={
            "name": tag_name,
            "description": description,
            "dynamicRules": dynamic_rules,
        }

        task_name = "create_tag"
        payload = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, payload)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        success_msg = "Tag: '{0}' created successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.create_tag.append(tag_name)

        return self

    def format_device_details(self):
        pass

    def assign_members_on_tag_creation(self, tags):
        assign_members = tags.get("assign_members")

        




    def get_diff_merged(self, config):
        tags = self.want.get("tags")
        if tags:
            self.log("Starting Tag Creation/Updation", "DEBUG")
            tag_in_ccc= self.have.get("tags")
            if not tag_in_ccc:
                self.log("Starting thr prpcess of creating {0} Tag with config: {1}".format(tags.get("name"), tags), "DEBUG")
                self.create_tag(tags).check_return_status()

                assign_members = tags.get("assign_members")
                if assign_members:
                    pass
                    # code to assign members to the tag. Make it reusable. 
            else:
                # Check if the tag in ccc and tag are same, if not, it needs an update, so call the respective apis
                pass

            pass
        return self
        
    def int_fail(self, msg="Intentional Fail "):
        self.msg = msg
        self.set_operation_result("failed", False, self.msg, "ERROR")
        self.check_return_status()

    def debugg(self, msg="Sample Debug Message"):
        self.log(msg, "DEBUG")


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
        # if config_verify:
        #     ccc_tags.verify_diff_state_apply[state](config).check_return_status()

    ccc_tags.int_fail()
    # ccc_tags.get_tag_id("TEST101")
    # ccc_tags.log(ccc_tags["have"].get("tag_id"))

    # Invoke the API to check the status and log the output of each site/zone and authentication profile update on console.
    ccc_tags.update_site_zones_profile_messages().check_return_status()

    module.exit_json(**ccc_tags.result)


if __name__ == '__main__':
    main()