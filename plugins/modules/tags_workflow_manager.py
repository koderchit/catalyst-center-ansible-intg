#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


#  TODO: check all the get functions and check that if NONE CASE IS HANDELLED OR NOT
#  TODO: add proper logs to each function.
#  TODO: Check all the logs and remove unnecessary logs
#  TODO: check for all the pass statements and remove where not needed.
#  TODO: remove all the TODO statements as well.
#  WHen port rule has speed, UI adds some zeroes in the value.
# UI SHOWS RANDOM BEHAVIOUR WHEN ALL 4 (Equals, ends, starts, contains) ARE GIVEN WITH SAME VALUE
from __future__ import absolute_import, division, print_function
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common import validation

from collections import defaultdict

__metaclass__ = type
__author__ = ("Archit Soni, Madhan Sankaranarayanan")


DOCUMENTATION = r"""
---

module: tags_workflow_manager
short_description: Create/ Update/ Delete Tag(s) and Tag Memberships in Cisco Catalyst Center.
description:
  - This module helps users create, update, and delete tags, as well as manage tag memberships in Cisco Catalyst Center.  
  - It provides the ability to define dynamic rules for tagging devices and ports, ensuring that devices and ports are 
    automatically tagged based various matching criterias.  
  - Users can assign, update, or delete tags on devices and ports based on attributes such as IP Address, MAC Address, 
    hostnames, serial numbers, or port names.
  - The module also facilitates assigning, updating, or deleting tags for devices and ports within specific sites, 
    simplifying the management of tags across multiple devices and ports under sites.

version_added: '6.30.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Archit Soni (@arcsoni)
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
    description: >
        A list of dictionaries containing detailed configurations for managing REST Endpoints that will receive Audit log
        and Events from the Cisco Catalyst Center Platform. This list is essential for specifying attributes and
        parameters required for the lifecycle management of tags and tag memberships. 
    type: list
    elements: dict
    required: true
    suboptions:
      tag:
        description: A dictionary containing detailed configurations for creating, updating, or deleting tags.
        type: dict
        elements: dict
        suboptions:
          name:
            description: >
              This name uniquely identifies the tag for operations such as creating, updating, or deleting. 
              This parameter is mandatory for any tag management operation.
            type: str
            required: true
          description:
            description: >
              A textual description providing details about the tag.
              This field is optional, but it helps to provide additional context about the tag.
            type: str
          force_delete:
            description: >
              A boolean flag that forces the deletion of a tag, even if it is associated with devices and ports.
              It is typically used when the playbook state is set to 'deleted'. When enabled, it removes all existing 
              dynamic rules associated with the tag and detaches the tag from all devices and ports and delete the tag.
            type: bool
            default: false
          device_rules:
            description: >
                Rules for dynamically tagging devices based on attributes such as 
                device name, device family, device series, IP address, location, version. 
                A device that meets the specified criteria will be automatically tagged.
                If multiple device rules are provided, rules with the same `rule_name` will be ORed together, 
                while rules with different `rule_name` values will be ANDed.
            type: dict
            elements: dict
            suboptions:
              rule_descriptions:
                description: List of rules that define how devices will be tagged.
                type: list
                elements: dict
                required: true
                suboptions:
                  rule_name:
                    description: The name of the rule. 
                    type: str
                    choices: [device_name, device_family, device_series, ip_address, location, version]
                    required: true
                  search_pattern:
                    description: The pattern used to search for device attributes.
                    type: str
                    choices: [contains, equals, starts_with, ends_with]
                    required: true
                  value:
                    description: The value that the rule will match against (e.g., specific IP or MAC address).
                    type: str
                    required: true
                  operation:
                    description: >
                      The operation used to match the respective value to the device.
                      ILIKE for case-insensitive matching and LIKE is for case-sensitive matching.
                    type: str
                    choices: [ILIKE, LIKE]
                    default: ILIKE
          port_rules:
            description: > 
                Rules for dynamically tagging ports based on attributes such as 
                Port Name, Port Speed, Admin Status, Operational Status, Description. 
                A port that meets the specified criteria will be automatically tagged.
                If multiple port rules are provided, rules with the same `rule_name` will be ORed together, 
                while rules with different `rule_name` values will be ANDed.
            type: dict
            elements: dict
            suboptions:
              scope_description:
                description: Describes the device scope of the rule, which includes scope category and scope members. 
                    The port rules will be only applied to ports of the devices present under the given scope.
                type: dict
                elements: dict
                suboptions:
                  scope_category:
                    description: >
                     The category of the scope. It can be either TAG or SITE. 
                     If TAG is the scope_category, scope_members are tag names that are present in Cisco Catalyst Center
                     If SITE is the scope_category, scope_members are site name hierarchies that are present in Cisco Catalyst Center
                    choices: [TAG, SITE]
                    type: str
                    required: true
                  scope_members:
                    description: >
                      List of scope members (e.g. tag names when scope_category is TAG or site name hierarchies 
                      when scope_category is SITE) that needs to be included in the scope.
                    type: list
                    elements: str
                    required: true
                  inherit:
                    description: >
                      A boolean flag that specifies whether the site should inherit its children.
                      It is typically used when the scope_category is SITE. When enabled, it removes all existing 
                      dynamic rules associated with the tag and detaches the tag from all devices and ports.
                      # TODO: Check with pawan and update if necessary.
                    type: bool
              rule_descriptions:
                description: List of rules that define how ports will be tagged.
                type: list
                elements: dict
                suboptions:
                  rule_name:
                    description: The name of the rule.
                    type: str
                    choices: [speed, admin_status, port_name, operational_status, description]
                    required: true
                  search_pattern:
                    description: The pattern used to search for port attributes.
                    type: str
                    choices: [contains, equals, starts_with, ends_with]
                    required: true
                  value:
                    description: The value that the rule will match against (e.g., port name, port speed).
                    type: str
                    required: true
                  operation:
                    description: >
                      The operation used to match the respective value to the port.
                      ILIKE for case-insensitive matching and LIKE is for case-sensitive matching.
                    type: str
                    choices: [ILIKE, LIKE]
                    default: 'ILIKE'
      tag_memberships:
        description: A dictionary containing detailed configuration for managing tag memberships for devices and interfaces.
        type: dict
        elements: dict
        suboptions:
          tags:
            description: >
              List of tag names to assign to devices or interfaces. 
              These tags should be present in Cisco Catalyst Center.
            type: list
            elements: str
            required: true
          device_details:
            description: Details about the devices and interfaces to which tags are to be assigned.
            type: list
            elements: dict
            suboptions:
              ip_addresses:
                description: List of IP addresses for the devices.
                type: list
                elements: str
              hostnames:
                description: List of hostnames for the devices.
                type: list
                elements: str
              mac_addresses:
                description: List of MAC addresses for the devices.
                type: list
                elements: str
              serial_numbers:
                description: List of serial numbers for the devices.
                type: list
                elements: str
              port_names:
                description: >
                  List of port names to which the tags are to be assigned under the devices. 
                  It is an optional parameter, used as per requirement.
                  If port_names is not given, the tags will be assigned to devices.
                  If port_names is given, the tags will be assigned to the ports under the respective devices.
                type: list
                elements: str
          site_details:
            description:  Details about the sites under which devices or interfaces will be tagged.
            type: list
            elements: dict
            suboptions:
              site_names:
                description: List of the site name hierarchies under which devices or interfaces will be tagged.
                type: list
                elements: str
                required: true
              port_names:
                description: >
                  List of port names to which the tags are to be assigned under the devices belonging to the 
                  given sites. It is an optional parameter, used as per requirement.
                  If port_names is not given, the tags will be assigned to devices under the given sites.
                  If port_names is given, the tags will be assigned to these ports under devices belonging to the given sites.
                type: list
                elements: str
          
requirements:
  - dnacentersdk >= 2.10.3
  - python >= 3.9

notes:
  - Ensure that all required parameters are correctly provided for successful execution. If any failure is encountered,
    the module will halt the execution without proceeding to further operations.
  - If `force_delete` is set to `true` in deleted state, the tag will be forcibly removed from all associated devices and ports and the tag will be deleted
  - In device_rules and port_rules, rules with the same rule_name are ORed together, while rules with different rule_name values are ANDed together. 
  - Each device or interface can have a maximum of 500 tags assigned.
  - SDK Method used are:
    tags.Tag.add_members_to_the_tag
    tags.Tag.create_tag
    tags.Tag.delete_tag
    tags.Tag.get_device_list
    tags.Tag.get_interface_details
    tags.Tag.get_sites
    tags.Tag.get_site_assigned_network_devices
    tags.Tag.get_tag
    tags.Tag.get_tag_members_by_id
    tags.Tag.query_the_tags_associated_with_network_devices
    tags.Tag.query_the_tags_associated_with_interfaces
    tags.Tag.update_tag
    tags.Tag.update_tags_associated_with_the_interfaces
    tags.Tag.update_tags_associated_with_the_network_devices

"""

EXAMPLES = r"""



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
        """
        Initializes the Tags class with module-specific configurations.

        Args:
            module: The module instance being initialized.

        Attributes:
            supported_states (list): A list of supported states, including "merged" and "deleted".
            created_tag (list): Stores tag that has been newly created.
            updated_tag (list): Stores tag that has been updated.
            not_updated_tag (list): Stores tag that was expected to be updated but were not.
            deleted_tag (list): Stores tag that has been deleted.
            absent_tag (list): Stores tag that are absent.

            updated_tag_memberships (list): A list of tag memberships that were successfully updated.
            not_updated_tag_memberships (list): A list of tag memberships that failed to update.
            deleted_tag_memberships (list): A list of tag memberships that were successfully deleted.
            not_deleted_tag_memberships (list): A list of tag memberships that failed to be deleted.

        Schema for a member in tag_memberships (Updated/ Not Updated/ Deleted/ Not deleted):
            {
                "id": device_id, 
                "device_type": "networkdevice" / "interface",
                "device_identifier": "hostname",  # etc.
                "device_value": device_name,  # etc.
                "interface_name": interface_name / None,
                "site_name": site_name / None,
                "reason": "Failing reason (only in not_updated/not_deleted memberships)",
                "tags_list": [List of tag names]  # Present in all memberships
            }

        Schema for a member in tag_list:
            {
                "tag_name": TAG_NAME,
                "tag_id": TAG_ID
            }
        """
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created_tag, self.updated_tag, self.not_updated_tag = [], [], []
        self.deleted_tag, self.absent_tag = [], []

        self.updated_tag_memberships, self.not_updated_tag_memberships = [], []
        self.deleted_tag_memberships, self.not_deleted_tag_memberships = [], []
        self.result["changed"] = False

    def validate_input(self):
        # @DONE
        """
        Validate the playbook configuration.

        Description:
            Checks the configuration provided in the playbook against a predefined specification 
            to ensure it adheres to the expected structure and data types.

        Args:
            self (object): The instance of the class that contains the 'config' attribute to be validated.

        Returns:
            self.msg (str): A message describing the validation result.
            self.status (str): The status of the validation (either 'success' or 'failed').
            self.validated_config (dict or None): If successful, a validated version of the 'config' parameter;
                                                otherwise, None.
        """

        temp_spec = {
            'tag': {
                'type': 'dict',
                'elements': 'dict',
                'name': {'type': 'str', 'required': True},
                'description': {'type': 'str'},
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
                        'scope_category': {'type': 'str','required': True},
                        'inherit': {'type': 'bool'},
                        'scope_members': {
                            'type': 'list',
                            'elements': 'str',
                            'required': True
                        }
                    },
                    'rule_descriptions': {
                        'type': 'list',
                        'elements': 'dict',
                        'rule_name': {'type': 'str', 'required': True},
                        'search_pattern': {'type': 'str', 'required': True},
                        'value': {'type': 'str', 'required': True},
                        'operation': {'type': 'str', 'default': 'ILIKE'}
                    }
                }
            },
            'tag_memberships': {
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
                        'elements': 'str'
                    },
                    'hostnames': {
                        'type': 'list',
                        'elements': 'str'
                    },
                    'mac_addresses': {
                        'type': 'list',
                        'elements': 'str'
                    },
                    'serial_numbers': {
                        'type': 'list',
                        'elements': 'str'
                    },
                    'port_names': {
                        'type': 'list',
                        'elements': 'str'
                        
                    }
                },
                'site_details': {
                    'type': 'list',
                    'elements': 'dict',
                    'site_names': {
                        'type': 'list',
                        'elements': 'str',
                        'required': True
                    },
                    'port_names': {
                        'type': 'list',
                        'elements': 'str'
                    }
                }
            }
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing. Please check the playbook and try again."
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self
        
        # Validate device params
        valid_temp, invalid_params = self.validate_list_of_dicts(
            self.config, temp_spec
        )

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}. Please check the playbook".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self
        
        self.validated_config = valid_temp
        self.msg= "Successfully validated playbook configuration parameters. Validated Config: {0}".format(self.pprint(valid_temp))
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
        device_rules=config.get("tag").get("device_rules")

        if not device_rules:
            self.log("No Device Rule is provided", "INFO")
            return device_rules
        rule_descriptions = device_rules.get("rule_descriptions")
        if not rule_descriptions:
            self.msg = ("Device Rules does not contain rule descriptions." 
                        "Required parameter for defining dynamic device rules.")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        validated_rule_descriptions=[]
        
        # Choices
        rule_name_choices = ['device_name', 'device_family', 'device_series', 'ip_address', 'location', 'version']
        search_pattern_choices = ['contains', 'equals', 'starts_with', 'ends_with']
        operation_choices = ['ILIKE', 'LIKE']
        
        for device_rule in rule_descriptions:
            validated_device_rule={}
            rule_name= device_rule.get("rule_name")
            if not rule_name:
                self.msg = (
                "Rule Name not provided. Required parameter for defining dynamic device rules."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            rule_name = rule_name.lower()
            if rule_name not in rule_name_choices:
                self.msg = (
                "Rule Name provided: {0} is Invalid. Rulename should be one of {1}".format(rule_name, rule_name_choices)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            search_pattern= device_rule.get("search_pattern")
            if not search_pattern:
                self.msg = (
                "Search Pattern not provided. Required parameter for defining dynamic device rules."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            search_pattern = search_pattern.lower()
            if search_pattern not in search_pattern_choices:
                self.msg = (
                "Search pattern provided: {0} is Invalid. Search Pattern should be one of {1}".format(search_pattern, search_pattern_choices)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            value = device_rule.get("value")
            if not value:
                self.msg = (
                    "Value not provided. Required parameter for defining dynamic device rules."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            operation= device_rule.get("operation")
            if not operation:
                operation= "ILIKE"
                self.msg = (
                    "Operation not provided. Setting it to its default value of {0}".format(operation)
                )
                self.log(self.msg, "INFO")

            operation = operation.upper()
            if operation not in operation_choices:
                self.msg = (
                    "Operation provided: {0} is Invalid. Operation should be one of {1}".format(operation, operation_choices)
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            validated_device_rule["rule_name"]= rule_name
            validated_device_rule["search_pattern"]= search_pattern
            validated_device_rule["value"]= value
            validated_device_rule["operation"]= operation

            validated_rule_descriptions.append(validated_device_rule)

        validated_device_rules={
            "rule_descriptions":validated_rule_descriptions
        }

        self.msg = (
            "Device Rules validation completed. Validated device rules: {0}".format(self.pprint(validated_device_rules))
        )
        self.log(self.msg, "INFO")
                
        return validated_device_rules

    def validate_port_rules(self, config):
        """
        Validates and processes port rules provided in the configuration dictionary.

        Args:
            config (dict): A configuration dictionary containing a "tags" key with 
                        "port_rules" under it. Port rules should include:
                        - "rule_descriptions" (list): List of rule objects defining port attributes.
                        - "scope_description" (dict): Specifies scope details for the port rules.

        Returns:
            dict: A dictionary containing the validated port rules.

        Description:
            This method ensures all provided port rules and scope descriptions are valid. 
            It checks for missing or invalid fields and logs errors when necessary. Default 
            values are assigned to optional fields if missing. The validation halts with an 
            error if critical fields are invalid or missing.
        """
        port_rules=config.get("tag").get("port_rules")

        if not port_rules:
            self.log("No Port Rules are provided", "INFO")
            return port_rules
        rule_descriptions = port_rules.get("rule_descriptions")
        scope_description = port_rules.get("scope_description")
        validated_port_rules={}

        if not rule_descriptions and not scope_description:
            self.msg = (
                "Port Rules does not contain the rule descriptions and the scope description."
                "Both are required for creation of dynamic rules and atleast one is required for updation or deletion."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if not scope_description:
            self.log("Port Rules does not contain scope descrption.", "INFO")
        else:
            scope_category = scope_description.get("scope_category")
            scope_category_choices=["TAG", "SITE"]
            scope_category = scope_category.upper()
            if scope_category and scope_category not in scope_category_choices:
                self.msg = (
                    "Scope category provided: {0} is Invalid. Scope category should be one of {1}".format(scope_category, scope_category_choices)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            inherit = scope_description.get("inherit")

            if not inherit:
                if scope_category =="SITE":
                    inherit = True
                else:
                    inherit = False
                self.log("Inherit Not provided, Setting it to its default value: {0} for scope_category {1}.".format(inherit, scope_category), "INFO")

            scope_members= scope_description.get("scope_members")

            if not scope_members:
                self.msg = (
                    "No scope members provided for scope category: {0}." 
                    "It is required to define/update port rules"
                    .format(scope_category)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            validated_scope_description={
                "scope_category": scope_category,
                "inherit": inherit,
                "scope_members": scope_members
            }
            validated_port_rules["scope_description"]=validated_scope_description

        if not rule_descriptions:
            self.log("Port Rules Rules does not contain rule descriptions.", "INFO")
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
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                rule_name = rule_name.lower()
                if rule_name not in rule_name_choices:
                    self.msg = (
                        "Rule Name provided: '{0}' is Invalid. Rule Name should be one of {1}".format(rule_name, rule_name_choices)
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                search_pattern= port_rule.get("search_pattern")
                if not search_pattern:
                    self.msg = (
                        "Search Pattern not provided. Required parameter for defining dynamic rules."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                search_pattern = search_pattern.lower()
                if search_pattern not in search_pattern_choices:
                    self.msg = (
                    "Search pattern provided: '{0}' is Invalid. Search Pattern should be one of {1}".format(search_pattern, search_pattern_choices)
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                value = port_rule.get("value")
                if not value:
                    self.msg = (
                        "Value not provided. Required parameter for defining dynamic rules."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                operation= port_rule.get("operation")
                if not operation:
                    operation= "ILIKE"
                    self.log("Operation not provided. Setting it to its default value of {0}".format(operation), "INFO")

                operation = operation.upper()
                if operation not in operation_choices:
                    self.msg = (
                        "Operation provided: {0} is Invalid. Operation should be one of {1}".format(operation, operation_choices)
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                
                valudated_port_rule={
                    "rule_name": rule_name,
                    "search_pattern": search_pattern,
                    "value": value,
                    "operation": operation
                }
                validated_rule_descriptions.append(valudated_port_rule)

            validated_port_rules["rule_descriptions"] = validated_rule_descriptions
            
        self.log("Port Rules validation completed. Validated Port rules: {0}".format(self.pprint(validated_port_rules)), "INFO")
                
        return validated_port_rules

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

            response = response.get("response")
            self.log("Received API response from 'get_tag' for the tag '{0}': {1}".format(tag_name, str(response)), "DEBUG")

            # Check if the response is empty
            if not response:
                self.log("No tag details retrieved for tag name: {0}, Response empty.".format(tag_name), "DEBUG")
                return None
            
            tag_id = response[0].get("id")
            return tag_id

        except Exception as e:
            self.msg = """Error while getting the details of Tag with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(tag_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        
    def get_site_id(self, site_name):
        """
        Retrieves the site ID from Cisco Catalyst Center based on the given site name.

        Args:
            site_name (str): The hierarchical name of the site.

        Returns:
            str or None: The site ID if found, otherwise None.

        Description:
            This method queries the 'get_sites' API and extracts the site ID if available.
            It logs appropriate debug messages and handles errors gracefully.
        """
        
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
                self.log("No Site details retrieved for Site name: {0}, Response empty.".format(site_name), "DEBUG")
                return None
            site_id = response[0].get("id")

            return site_id

        except Exception as e:
            self.msg = """Error while getting the details of Site with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(site_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_want(self, config):
        """
        Processes and validates the desired state configuration for tags and tag memberships from the provided playbook.

        Args:
            config (dict): The input dictionary containing tag and tag membership details.

        Returns:
            object: The instance of the class with the `want` attribute updated to reflect the validated desired state.

        Description:
            This function extracts and validates tag details such as name, description, force_delete flag, and associated 
            device and port rules. It also verifies tag membership assignments for network devices, interfaces, and sites, 
            ensuring that at least one valid identifier (IP address, hostname, MAC address, or serial number) is provided 
            for device-level assignments. If validation fails at any stage, an appropriate error message is logged, and 
            execution is halted. 

            The validated configuration is stored in the `want` dictionary, which includes:
            - 'tag': Validated tag details (if provided)
            - 'tag_memberships': Validated tag membership details (if provided)

            This updated `want` dictionary is assigned to the instance for further processing.
        """

        self.log("Starting Get Want for the config: {0}".format(self.pprint(config)), "DEBUG")

        want={}
        
        tag = config.get("tag")
        tag_memberships = config.get("tag_memberships")

        if not tag and not tag_memberships:
            self.msg = (
                "No input provided in the playbook for tag operation or updating tag memberships in Cisco Catalysyt Center."
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        if not tag:
            self.log("Tag creation/updation config not provided.", "DEBUG")
        else:
            tag_name = tag.get("name")
            if not tag_name:
                self.msg = (
                    "No Tag Name provided or Provided Tag Name is empty."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            description= tag.get("description")
            if not description:
                self.msg= "No Description is provided."
                self.log(self.msg, "DEBUG")

            force_delete = tag.get("force_delete")
            if not force_delete:
                force_delete= False
                self.msg= "force delete not provided, setting it to its default value: {0}".format(force_delete)
                self.log(self.msg, "INFO")

            device_rules = self.validate_device_rules(config)
            port_rules = self.validate_port_rules(config)
            validated_tag={
                "name": tag_name,
                "description": description,
                "force_delete": force_delete,
                "device_rules": device_rules,
                "port_rules": port_rules
            }
            # Creating dictionary again as the dynamic rules might have got modified for upper/lower case changes.
            # Else we could have returned the same dict.

            want['tag']= validated_tag
            self.log("Tag config validation completed. Validated Tag Config: {0}".format(self.pprint(validated_tag)), "INFO")
                
        if not tag_memberships:
            self.log("Tag memberships config not provided.", "DEBUG")
        else:
            tags = tag_memberships.get("tags")
            device_details= tag_memberships.get("device_details")
            site_details= tag_memberships.get("site_details")
            if not tags:
                self.msg = (
                    "No tags provided in tag_memberships. Required Parameter."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            
            if not device_details:
                self.log("Device details are not provided in tag memberships config", "DEBUG")
            else:
                for device_detail in device_details:    
                    ip_addresses = device_detail.get("ip_addresses")
                    hostnames = device_detail.get("hostnames")
                    mac_addresses = device_detail.get("mac_addresses")
                    serial_numbers = device_detail.get("serial_numbers")
                    if not ip_addresses and not hostnames and not mac_addresses and not serial_numbers:
                        self.msg = (
                            "None of ip addresses, hostnames, mac addresses or serial numbers are provided."
                            "Atleast one is needed to modify tag memberships"
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    port_names = device_detail.get("port_names")
                    if port_names:
                        self.msg=(
                            "Port names is provided under devide details."
                            "Tag membership operation applies to interfaces"
                        )
                        self.log(self.msg)
                    else:
                        self.msg=(
                            "Port names is not provided under devide details."
                            "Tag membership operation applies to network devices"
                        )
                        self.log(self.msg)

            if not site_details:
                self.log("Site details are not provided in tag memberships config", "DEBUG")
            else:
                for site_detail in site_details:    
                    site_names = site_detail.get("site_names")
                    if not site_names:
                        self.msg = (
                            "Site Names not provided. Required to assign the tags to its members"
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()    
                    port_names = site_detail.get("port_names")
                    if port_names:
                        self.msg=(
                            "Port names is provided under site details."
                            "Tag membership operation applies to interfaces"
                        )
                        self.log(self.msg)
                    else:
                        self.msg=(
                            "Port names is not provided under site details."
                            "Tag membership operation applies to network devices"
                        )
                        self.log(self.msg)

            want["tag_memberships"]= tag_memberships
            self.msg = (
                "Tag memberships validation completed. Validated tag memberships: {0}".format(self.pprint(tag_memberships))
            )
            self.log(self.msg, "DEBUG")

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook for tag and tag memberships playbook configuration"
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
            Retrieves the tag ID based on the provided config, and stores it in the 'have' dictionary.

            Args:
                config (dict): Configuration dictionary containing the 'tag' key with 'name' as a subkey.

            Returns:
                self: Returns the instance of the class for method chaining.

            Description:
                This method extracts the tag name from the config, retrieves the tag ID, 
                and stores it in the 'have' dictionary. If the tag ID is not found, it logs an debug message.
        """
        have={}
        tag = config.get("tag")
        if tag:
            tag_name= tag.get("name")
            tag_info= self.get_tag_info(tag_name)
            if not tag_info:
                self.msg= "Tag Details for {0} are not available in Cisco Catalyst Center".format(tag_name)
                self.log(self.msg, "DEBUG")
            else:
                have["tag_info"]= tag_info
        self.have= have
        self.msg = "Successfully collected all parameters from the Cisco Catalyst Center for tag and tag memberships playbook configuration"
        self.log("Present State (have): {0}".format(self.pprint(self.have)), "INFO")
        return self

    def format_rule_representation(self, rule):
        """
        Formats a rule representation by mapping rule names to appropriate selectors and applying 
        search pattern transformations to the value.

        Args:
            rule (dict): A dictionary containing rule details with keys:
                        - "search_pattern" (str): The pattern type (equals, contains, starts_with, ends_with).
                        - "operation" (str): The operation to be performed.
                        - "value" (str): The value associated with the rule.
                        - "rule_name" (str): The name of the rule.

        Returns:
            dict: A formatted rule representation with keys:
                - "operation" (str): The operation type.
                - "name" (str): The mapped name for the rule.
                - "value" (str): The transformed value based on the search pattern.
        """
        search_pattern= rule.get("search_pattern")
        operation= rule.get("operation")
        value = rule.get("value")
        name = rule.get("rule_name")

        name_selector = {
            # Device rule_names
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
        # if formatted_rule["name"] == "speed":
        #     formatted_rule["value"] = formatted_rule["value"] +"000"
        # # Adding 3 zeroes to mimic UI behaviour

        self.log("Formatted rule representation for Input:{0} is Output:{1}".format(self.pprint(rule), self.pprint(formatted_rule)), "INFO")
        return formatted_rule
    
    def sorting_rule_descriptions(self, rule_descriptions):
        """
        Sorts rule descriptions based on predefined priority order of 'name' and then 
        lexicographically by 'value' within the same 'name'.

        Args:
            rule_descriptions (list of dict): A list of dictionaries where each dictionary 
                contains:
                - "name" (str): The rule category.
                - "value" (str): The corresponding value.

        Returns:
            list of dict: A sorted list of rule descriptions, first by the priority of 'name' 
                         and then alphabetically by 'value'.
        """
        
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
                rule_descriptions (list): List of leaf nodes (base rules).

            Returns:
                dict: Hierarchical rule description dictionary structure.
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
        """
        Formats device rules by processing rule descriptions, applying formatting, 
        sorting, and grouping them into a hierarchical structure.

        Args:
            device_rules (dict): A dictionary containing device rule details.
                Expected keys:
                    - "rule_descriptions" (list of dict): List of device rules.

        Returns:
            dict: A formatted dictionary containing device rules grouped hierarchically.
        """
         
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

        self.log("Formatted Rule Descriptions In List Format:{0}".format(self.pprint(formatted_rule_descriptions_list)), "INFO")
        
        formatted_device_rules = {
            "memberType" : "networkdevice",
            "rules": formatted_rule_descriptions_list
        }
        self.log("Formatted Device rules for Input:{0} is Output:{1}".format(self.pprint(device_rules), self.pprint(formatted_device_rules)), "INFO")
        return formatted_device_rules

    def format_scope_description(self, scope_description):
        """
        Formats scope description by processing scope category and members, 
        retrieving corresponding IDs, and returning a structured output.

        Args:
            scope_description (dict): A dictionary containing scope details.
                Expected keys:
                    - "scope_category" (str): Category of the scope (TAG or SITE).
                    - "scope_members" (list): List of scope members.
                    - "inherit" (bool): Inherit flag in case of SITE.

        Returns:
            dict: A formatted dictionary containing scope description.
        """
        if not scope_description:
            self.log("scope_description is {0}. Returning None".format(scope_description), "INFO")
            return formatted_scope_description
        
        scope_category= scope_description.get("scope_category")
        scope_members= scope_description.get("scope_members")
        scope_members_ids=[]
        if scope_category == "TAG":
            for tag in scope_members:
                tag_id= self.get_tag_id(tag)
                if tag_id is None:
                    self.msg= (
                        "Scope Member provided: {0} is Not present in Cisco Catalyst Center."
                        "Please ensure that the scope_members are present and scope_category is provided are valid"
                    ).format(tag)
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                scope_members_ids.append(tag_id)
        elif scope_category == "SITE":
            for site in scope_members:
                site_id= self.get_site_id(site)
                if site_id is None:
                    self.msg= (
                        "Scope Member provided: {0} is Not present in Cisco Catalyst Center."
                        "Please ensure that the scope_members are present and scope_category provided are valid"
                    ).format(site)
                    self.log(self.msg, "INFO")
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                scope_members_ids.append(site_id)

        formatted_scope_description={
            "memberType": "networkdevice",
            "groupType": scope_category,
            "scopeObjectIds": scope_members_ids,
            "inherit": scope_description.get("inherit")
        }
        
        self.log("Formatted Scope Description for Input:{0} is Output:{1}".format(scope_description, formatted_scope_description), "INFO")

        return formatted_scope_description
        
    def format_port_rules(self, port_rules):
        """
        Formats port rules by processing rule descriptions and scope descriptions, 
        applying formatting, sorting, and structuring them into a hierarchical format.

        Args:
            port_rules (dict): A dictionary containing port rule details.
                Expected keys:
                    - "rule_descriptions" (list of dict): List of port rules.
                    - "scope_description" (dict): Scope description details.

        Returns:
            dict: A formatted dictionary containing structured port rules.
        """
        
        if port_rules is None:
            self.log("port_rules is {0}. Returning None".format(port_rules), "DEBUG")
            return None
        
        formatted_port_rules = {
            "memberType" : "interface"
        }

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
            formatted_port_rules["rules"]= formatted_rule_descriptions

        formatted_scope_description= []
        if scope_description:
            formatted_scope_description= self.format_scope_description(scope_description)
            formatted_port_rules["scopeRule"] = formatted_scope_description

        self.log("Formatted Port rules for Input:{0} is Output:{1}".format(port_rules, formatted_port_rules), "INFO")
        return formatted_port_rules
        
    def combine_device_port_rules(self, device_rules, port_rules): 
        """
        Combines device-specific and port-specific rules into a list.

        Args:
            device_rules (list): A list of rules related to the device.
            port_rules (list): A list of rules related to the port.

        Returns:
            list: A list containing the combined device and port rules. If either list is None, it is treated as an empty list.

        Description:
            This method combines the given device and port rules into a single list and logs the result.
        """

        dynamic_rules=[]
        if port_rules:
            dynamic_rules.append(port_rules)
        if device_rules:
            dynamic_rules.append(device_rules)

        self.log("Combined dynamic_rules for device_rules:{0}, port_rules:{1} are: {2}".format(self.pprint(device_rules), self.pprint(port_rules), self.pprint(dynamic_rules)), "DEBUG")
        return dynamic_rules

    def create_tag(self, tag):
        """
        Creates a new tag with associated rules and parameters.

        Args:
            tag (dict): A dictionary containing the tag information. Expected keys are:
                - "name": The name of the tag. (required)
                - "description": A description of the tag.
                - "device_rules": A dictionary of device-related rules.
                - "port_rules": A dictionary of port-related rules.

        Returns:
            self: Returns the current instance (self) for chaining.
        
        Description:
            This method formats the device and port rules, validates the port rule descriptions, 
            combines the rules, and creates a new tag by making an API call. If any errors occur 
            during the process, appropriate error messages are logged.
        """

        tag_name= tag.get("name")
        description= tag.get("description")
        device_rules = tag.get("device_rules")
        port_rules = tag.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)
        if formatted_device_rules:
            formatted_device_rules["rules"]= self.group_rules_into_tree(formatted_device_rules["rules"])

        formatted_port_rules = self.format_port_rules(port_rules)
        if formatted_port_rules:
            formatted_port_rules["rules"]= self.group_rules_into_tree(formatted_port_rules["rules"])


        if formatted_port_rules:
            rule_descriptions= port_rules.get("rule_descriptions")
            scope_description= port_rules.get("scope_description")
            if not rule_descriptions or not scope_description:
                self.msg="""Either of rule_description:{0} or scope_description:{1} is empty in port_rules. 
                Both are required for port rule creation""".format(rule_descriptions, scope_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

        dynamic_rules= self.combine_device_port_rules(formatted_device_rules, formatted_port_rules)
        tag_payload={
            "name": tag_name,
            "description": description,
        }
        if dynamic_rules:
            tag_payload["dynamicRules"]= dynamic_rules

        task_name = "create_tag"
        parameters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        
        success_msg = "Tag: '{0}' created successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def get_tag_info(self, tag_name):
        """
        Retrieves the details of a tag by its name.

        Args:
            tag_name (str): The name of the tag.

        Returns:
            dict or None: The tag details if found, otherwise None.

        Description:
            Sends an API request to retrieve the details of a tag based on its name.
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
            tag_info = response[0]
            
            return tag_info

        except Exception as e:
            self.msg = """Error while getting the details of Tag with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(tag_name, str(e))
            self.fail_and_exit(self.msg)

    def get_device_id_by_param(self, param, param_value):
        
        """
        Retrieves the device ID based on a given parameter (e.g., IP address, hostname).

        Args:
            param (str): The parameter to search by (e.g., "ip_address", "hostname").
            param_value (str): The value of the parameter to search for.

        Returns:
            str or None: The device ID if found, otherwise None.

        Description:
            Sends an API request to retrieve the device ID based on the provided parameter and value.
        """
        
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
            self.log("Received API response from 'get_device_list' for the Device with {0}: '{1}' : {2}".format(param, param_value, str(response)), "DEBUG")

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

    def get_port_id_by_device_id(self, device_id, port_name, device_identifier, device_identifier_value):
        """
        Retrieves the port ID for a given device id and interface/port name.

        Args:
            device_id (str): The ID of the device.
            port_name (str): The name of the interface/port.
            device_identifier (str): The identifier type (e.g., 'hostname', 'serial_number').
            device_identifier_value (str): The value of the device identifier.

        Returns:
            str or None: The port ID if found, otherwise None.

        Description:
            Sends an API request to retrieve the port ID for the specified interface on the given device.
        """

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

    def deduplicate_list_of_dict(self, list_of_dicts):
        """
        Removes duplicate dictionaries from a list.

        Args:
            list_of_dicts (list): A list of dictionaries to deduplicate.

        Returns:
            list: A list of unique dictionaries (duplicates removed).

        Description:
            Iterates through a list of dictionaries and removes duplicates based on their content.
        """
        seen = set()
        unique_dicts = []
        for d in list_of_dicts:
            # Convert dictionary to a tuple of sorted items (temporary hashable representation)
            identifier = tuple(sorted(d.items()))
            
            if identifier not in seen:
                seen.add(identifier)
                unique_dicts.append(d)  # Append the original dict (not modified)
        return unique_dicts

    def format_device_details(self, device_details):
        """
        Formats device details by retrieving device and port IDs.

        Args:
            device_details (list): A list of dictionaries containing device details.

        Returns:
            list: A list of dictionaries with formatted device and port information, including IDs.

        Description:
            This function processes a list of device details, deduplicates port names, retrieves device IDs, and handles missing devices or interfaces.
        """

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

                            if port_names:
                                for port_name in port_names:
                                    interface_detail_dict={
                                                "device_type": "interface",
                                                "device_identifier": param_name,
                                                "device_value": param,
                                                "interface_name": port_name,
                                                "reason" : "Device doesn't exist in Cisco Catalyst Center"
                                        }
                                    # Tag not updated/deleted for interface
                                    if state =="merged":
                                        self.not_updated_tag_memberships.append(interface_detail_dict)
                                    elif state =="deleted":
                                        self.not_deleted_tag_memberships.append(interface_detail_dict)
                            else:
                                # Tag not updated/deleted for device
                                if state =="merged":
                                    self.not_updated_tag_memberships.append(device_detail_dict)
                                elif state =="deleted":
                                    self.not_deleted_tag_memberships.append(device_detail_dict)

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
                                            self.not_updated_tag_memberships.append(interface_detail_dict)
                                        elif state =="deleted":
                                            self.not_deleted_tag_memberships.append(interface_detail_dict)
                                    else:
                                        interface_detail_dict["id"]= port_id
                                        device_ids.append(interface_detail_dict)
                            else:
                                device_detail_dict["id"]= device_id
                                device_ids.append(device_detail_dict)

        

        self.log("Deduplicating the device_ids list for duplicate device IDs", "DEBUG")
        device_ids =  self.deduplicate_list_of_dict(device_ids)
        self.log("Successfully retrieved device/port IDs from device_details: {0}\nResult: {1}".format(self.pprint(device_details), self.pprint(device_ids)), "DEBUG")
        return device_ids

    def get_device_id_list_by_site_name(self, site_name):
        """
        Retrieves a list of device IDs assigned to a specific site.

        Args:
            site_name (str): The name of the site for which to retrieve device IDs.

        Returns:
            list: A list of device IDs if found, else None.

        Description:
            This function fetches the device IDs for all devices assigned to a site identified by its name. If no devices are found, it logs the error.
        """

        self.log("Initiating retrieval of device details under site: '{0}'.".format(site_name), "DEBUG")

        site_id= self.get_site_id(site_name)
        device_id_list=[]

        offset = 1
        limit = 500
        while True:
            batch = offset//limit + 1
            try:
                response = self.dnac._exec(
                    family="site_design",
                    function='get_site_assigned_network_devices',
                    op_modifies=True,
                    params={"site_id": site_id, "offset" : offset, "limit" : limit},
                )

                # Check if the response is empty
                response = response.get("response")
                self.log("Received API response from 'get_site_assigned_network_devices' for the site name: '{0}' for batch:{1}: {2}".format(site_name, batch , str(response)), "DEBUG")

                if not response:
                    self.msg = "No devices found under the site name: {0} for batch :{1}, Response empty.".format(site_name, batch)
                    self.log(self.msg, "DEBUG")
                    break
                
                for response_ele in response:
                    device_id_list.append(response_ele.get("deviceId"))
                
            except Exception as e:
                self.msg = """Error while getting the details of the devices under the site name '{0}' for batch {1} present in
                Cisco Catalyst Center: {2}""".format(site_name, batch , str(e))
                self.fail_and_exit(self.msg)

            offset += limit
            
        return device_id_list
    
    def format_site_details(self, site_details):
        """
        Formats site details to retrieve device and interface information for each site.

        Args:
            site_details (list): A list of site details, including site names and associated port names (optional).

        Returns:
            list: A list of device and interface details with IDs, including site names.

        Description:
            This function processes the site details, retrieves the device and interface IDs for each site, and formats the data for further processing. It handles deduplication and error logging for missing sites and devices.
        """
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
                                        self.not_updated_tag_memberships.append(interface_detail_dict)
                                        self.log("Interface: '{0}' is not available for the device with {1}:'{2}'.".format(port_name, "hostname", device_name), "INFO")
                                    else:
                                        interface_detail_dict["id"] = port_id
                                        device_ids.append(interface_detail_dict)
                            else:
                                device_ids.append(device_detail_dict)


        self.log("Deduplicating the device_ids list for duplicate device IDs", "DEBUG")
        device_ids =  self.deduplicate_list_of_dict(device_ids)

        self.log("Successfully retrieved device/port IDs from site_details: {0}\nResult: {1}".format(self.pprint(site_details), device_ids), "DEBUG")
        return device_ids

    def get_device_name_by_id(self, device_id):

        """
        Retrieves the device name (hostname) using the device ID.

        Args:
            device_id (str): The ID of the device to retrieve.

        Returns:
            str: The device name (hostname) if found, else None.

        Description:
            This function retrieves the device details for a given device ID and extracts the hostname. If no details are found, it logs the error.
        """

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

    def create_tag_membership(self, tag_name, member_details):
        """
        Args:
            tag_name (str): The name of the tag to which members are to be added.
            member_details (list): A list of dictionaries containing member details. Each dictionary must contain 'id' and 'device_type' keys.

        Returns:
            self: The current instance of the object, allowing for method chaining.

        Description:
            Adds network device and interface members to a specified tag in the Cisco Catalyst Center.
        """

        self.log("Starting to add members to the Tag:'{0}' with provided members:{1}".format(tag_name, self.pprint(member_details)), "INFO")

        network_device_list=[]
        interface_list=[]
        for member_detail in member_details:
            member_id= member_detail.get("id")
            member_type= member_detail.get("device_type")
            if member_type == "interface": 
                interface_list.append(member_id)
            elif member_type == "networkdevice":
                network_device_list.append(member_id)

        tag_id= self.get_tag_id(tag_name)
        if tag_id is None:
            self.msg= "Tag {0} is not found in Cisco Catalyst Center. Please check the playbook. ".format(tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        member_payload={}

        if network_device_list:
            member_payload["networkdevice"] = network_device_list
        if interface_list:
            member_payload["interface"] = interface_list

        task_name = "add_members_to_the_tag"

        parameters = {"payload": member_payload, "id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)
        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0}' for the tag {1}.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        success_msg = "Added Tag members successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self
    
    def get_tags_associated_with_the_network_devices(self, network_device_details):
        
        """
        Args:
            network_device_details (list): A list of dictionaries, each containing 'id' (device ID) to identify the network devices.

        Returns:
            dict: A dictionary where the keys are device IDs and the values are lists of dictionaries, each containing 'tag_name' and 'tag_id' for associated tags.

        Description:
            Retrieves tags associated with a list of network devices in batches from the Cisco Catalyst Center.
        """

        self.log("Initiating retrieval of tags associated with network devices: {0}".format(self.pprint(network_device_details)), "DEBUG")
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
                self.log("Received API response from 'query_the_tags_associated_with_network_devices' for batch {0} payload: {1}, {2}".format(i//BATCH_SIZE + 1, payload, str(response)), "DEBUG")

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
        
        """
        Args:
            interface_details (list): A list of dictionaries, each containing 'id' (interface ID) to identify the interfaces.

        Returns:
            dict: A dictionary where the keys are interface IDs and the values are lists of dictionaries, each containing 'tag_name' and 'tag_id' for associated tags.

        Description:
            Retrieves tags associated with a list of interfaces in batches from the Cisco Catalyst Center.
        """

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
        """
        Description:
            Compares two lists (existing and new) and returns whether they need to be updated, 
            based on the specified state ('merged' or 'deleted'). It also returns the updated list.
            This function works only in case of primary list elements (str/tuple/int/etc.).

        Args:
            existing_list (list): The list of existing items.
            new_list (list): The list of new items to compare and merge or delete.

        Returns:
            tuple: A tuple containing:
                - bool: `True` if the list has been updated, `False` otherwise.
                - list: The updated list after merging or deleting elements.
        """


        state= self.params.get("state")
        self.log("Comparing lists for the state: '{0}'".format(state),"DEBUG")
        self.log("Existing List: {0}".format(existing_list),"DEBUG")
        self.log("New List: {0}".format(new_list),"DEBUG")
        
        existing_set = set(existing_list)
        new_set = set(new_list)

        updated_list=[]
        if state == "merged":
            updated_list = list(existing_set | new_set)
        elif state =="deleted":
            updated_list = list(existing_set - new_set)
        
        # Sorted existing List 
        existing_list= sorted(existing_list)
        updated_list= sorted(updated_list)
        
        needs_update = updated_list != existing_list

        self.log("Updated List: {0}".format(updated_list),"DEBUG")
        self.log("Needs Update: {0}".format(needs_update),"DEBUG")

        return needs_update, updated_list

    def unformat_rule_representation(self, formatted_rule):
        """
        Args:
            formatted_rule (dict): A dictionary containing the formatted rule with keys 'operation', 'name', and 'value'.

        Returns:
            dict: An unformatted rule represented by a dictionary with keys 'search_pattern', 'operation', 'value', and 'rule_name'.
        
        Description:
            Converts a formatted rule (with specific name mappings and value patterns) to an unformatted representation
            by reversing name mappings and detecting the search pattern (contains, starts_with, ends_with, equals).
        """
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
        """

        Args:
            existing_list (list): A list of dictionaries representing the existing items.
            new_list (list): A list of dictionaries representing the new items to compare and merge or delete.

        Returns:
            tuple: A tuple containing:
                - bool: `True` if the list has been updated, `False` otherwise.
                - list: The updated list after merging or deleting elements.
        Description:
            Compares two lists of dictionaries (existing and new) and returns whether they need to be updated, 
            based on the specified state ('merged' or 'deleted'). It also returns the updated list while preserving the order.
        """
        

        updated_list = []
        state = self.params.get("state")
        self.log("Comparing list of dict for the state: '{0}'".format(state), "DEBUG")
        self.log("Existing List: {0}".format(self.pprint(existing_list)), "DEBUG")
        self.log("New List: {0}".format(self.pprint(new_list)), "DEBUG")

        if state == "merged":
            # Merge while preserving order
            updated_list = existing_list.copy()
            for new_dict in new_list:
                if new_dict not in existing_list:  # Check if new_dict is already in existing_list
                    updated_list.append(new_dict)

        elif state == "deleted":
            # Delete elements in new_list from existing_list while preserving order
            updated_list = [d for d in existing_list if d not in new_list]

        self.log("Updated List: {0}".format(self.pprint(updated_list)), "DEBUG")
        # Check if there's a difference
        needs_update = updated_list != existing_list
        self.log("Needs Update: {0}".format(needs_update), "DEBUG")

        return needs_update, updated_list

    def update_tags_associated_with_the_network_devices(self, payload):
        """
        Args:
            payload (list): A list of data representing the tags to be associated with the network devices. Each entry in the list 
                            corresponds to a devices with their associated tags as a list.

        Returns:
            self: The instance of the class, allowing for method chaining.

        Description:
            Updates the tags associated with network devices in batches and checks the status of each update task.
            The function breaks down the payload into smaller batches, sends them to the Cisco Catalyst Center API, 
            and retrieves the task ID for each batch to track the update progress.
        """
        
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
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                break
            self.log("Successfully retrieved task_id for {0}: {1} for batch {2}.".format(task_name, task_id, start_index//BATCH_SIZE+1), "INFO")
            success_msg = "Updated Tags associated with the network devices for the batch {0} successfully in the Cisco Catalyst Center".format(start_index//BATCH_SIZE+1)
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            start_index += BATCH_SIZE
        
        return self
    
    def update_tags_associated_with_the_interfaces(self, payload):
        
        """
        Args:
            payload (list): A list of data representing the tags to be associated with interfaces. Each entry in the list corresponds 
                            to a batch of interfaces with their associated tags as a list.

        Returns:
            self: The instance of the class, allowing for method chaining.
        
        Description:
            Updates the tags associated with interfaces in batches and checks the status of each update task.
            The function splits the provided payload into smaller batches and sends each batch to the Cisco Catalyst Center API. 
            It tracks the task status for each batch after it is submitted.
        """
        
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
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                break
            self.log("Successfully retrieved task_id for {0}: {1} for batch {2}.".format(task_name, task_id, start_index//BATCH_SIZE+1), "INFO")

            success_msg = "Updated Tags associated with the interfaces successfully for the batch: {0} in the Cisco Catalyst Center".format(start_index//BATCH_SIZE+1)
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            start_index += BATCH_SIZE
        
        return self

    def updating_tag_memberships(self, tag_memberships):
        
        """
        Args:
            tag_memberships (dict): A dictionary containing 'device_details', 'tags_name_id', and optionally 
                                    'site_details' to update the tags.
        Returns:
            self (object): The current instance after updating tags.

        Description:
            Updates tag memberships for network devices and interfaces. It processes device and site details, compares 
            existing and new tags, and updates the tags in batches based on the 'merged' or 'deleted' state. If the 
            number of tags exceeds the maximum limit (500), an error is raised. It handles different types of members 
            (network devices and interfaces) and updates them accordingly.    
        """

        device_details= tag_memberships.get("device_details")
        new_tags_details = tag_memberships.get("tags_name_id")
        member_details=[]
        if device_details:
            formatted_device_details = self.format_device_details(device_details)
            member_details = member_details + formatted_device_details    
            
        site_details= tag_memberships.get("site_details")
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

        tag_memberships["network_device_details"] = network_device_details
        tag_memberships["interface_details"] = interface_details

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
                        self.msg="The maximum tag limit exceed for the device with {0}:{1}. The maximum number of tags a device can have is {2}. ".format(device_identifier, device_value, MAX_TAGS_LIMIT)
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    current_device_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }
                    if state =="merged":
                        self.updated_tag_memberships.append(network_device_detail)
                    elif state =="deleted":
                        self.deleted_tag_memberships.append(network_device_detail)

                    payload.append(current_device_payload)
                else:
                    if state =="merged":
                        network_device_detail["reason"] = "Device is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tag_memberships.append(network_device_detail)
                    elif state =="deleted":
                        network_device_detail["reason"] = "Device is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tag_memberships.append(network_device_detail)

            if payload:
                self.update_tags_associated_with_the_network_devices(payload)
            else:
                self.log("No need for updating tags associated with the network devices", "DEBUG")

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
                        self.msg="The maximum tag limit exceed for the interface: {0} with {1}:{2}. The maximum number of tags A device can have is {3}. ".format(interface_name, device_identifier, device_value, MAX_TAGS_LIMIT)
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    current_interface_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }

                    if state =="merged":
                        self.updated_tag_memberships.append(interface_detail)
                    elif state =="deleted":
                        self.deleted_tag_memberships.append(interface_detail)
                    payload.append(current_interface_payload)
                else:
                    if state =="merged":
                        interface_detail["reason"] = "Interface is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tag_memberships.append(interface_detail)
                    elif state =="deleted":
                        interface_detail["reason"] = "Interface is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tag_memberships.append(interface_detail)
            if payload:
                self.update_tags_associated_with_the_interfaces(payload)
            else:
                self.log("No need for updating tags associated with the interfaces", "DEBUG")

        return self

    def compare_and_update_scope_description(self, scope_description, scope_description_in_ccc):
        """
        Args:
            scope_description (dict): The scope description to compare and update.
            scope_description_in_ccc (dict): The current scope description in CCC.

        Returns:
            tuple: (bool, dict) indicating if update is needed and the updated scope description.

        Description: 
            Compares and updates the scope description between provided and CCC data.
        """
        requires_update = False

        # Scope Description in Cisco Catalyst Center can't be None, else port_rule won't exist in the first place.
        if scope_description is None:
            return requires_update, scope_description_in_ccc

        scope_category = scope_description.get("groupType") 
        scope_category_in_ccc = scope_description_in_ccc.get("groupType") 

        scope_members =  scope_description.get("scopeObjectIds")
        scope_members_in_ccc =  scope_description_in_ccc.get("scopeObjectIds")
        
        inherit = scope_description.get("inherit")
        inherit_in_ccc = scope_description_in_ccc.get("inherit")

        updated_scope_description = {}

        state = self.params.get("state")
        if scope_category == scope_category_in_ccc:

            if inherit != inherit_in_ccc:
                requires_update = True

            tmp_requires_update, updated_scope_members = self.compare_and_update_list(scope_members_in_ccc, scope_members)
            requires_update= requires_update | tmp_requires_update

            if not updated_scope_members:
                # In this case user wants to delete all the scope members, so returning empty updated_scope_description 
                return requires_update, updated_scope_description

            updated_scope_description["groupType"] = scope_category
            updated_scope_description["inherit"] = inherit
            updated_scope_description["scopeObjectIds"] = updated_scope_members

        else:
            if state=="deleted":
                self.msg =("In Case of state:{0}, the scope_category should be same as present in Cisco Catalist Center.\n"
                "scope_category provided:'{1}', scope_category in Cisco Catalyst Center:{2}").format(state, scope_category, scope_category_in_ccc)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            elif state=="merged":
                if not scope_members:
                    self.msg =("In Case of state:{0}, when changing the scope_category in Cisco Catalist Center.\n"
                    "The scope_members can't be empty. Please check the playbook.\n"
                    "scope_members:{1}, scope_category provided:'{2}', scope_category in Cisco Catalyst Center:{3}"
                    ).format(state, scope_members,  scope_category, scope_category_in_ccc)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            requires_update = True
            updated_scope_description["groupType"] = scope_category
            updated_scope_description["inherit"] = scope_description.get("inherit")
            updated_scope_description["scopeObjectIds"] = scope_members

        updated_scope_description["memberType"] = "networkdevice"
        self.log("Update required in scope description: {0}".format(requires_update), "DEBUG")
        self.log("Updated scope description: {0}".format(self.pprint(updated_scope_description)), "DEBUG")

        return requires_update, updated_scope_description
        
    def ungroup_rules_tree_into_list(self, rules):
        
        """
        Args:
            rules (dict or None): The rule structure, which may contain nested dictionaries.

        Returns:
            list: A list of leaf nodes (base rules).

        Description: Recursively extracts all leaf nodes (base rules) from a nested rule structure.
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
        
        return leaf_nodes

    def compare_and_update_rules(self, rules, rules_in_ccc):
        
        """
        Description: Compares and updates rules based on the current state (merged or deleted).
        
        Args:
            rules (dict): The new set of rules to compare.
            rules_in_ccc (dict): The existing set of rules from the Cisco Catalyst Center.

        Returns:
            tuple: A tuple containing a boolean indicating if an update is required and the updated rules (or None).
        """

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

        self.log("Comparing rules for state: '{0}'".format(state), "DEBUG")
        self.log("new rules:{0} and existing rules:{1}".format(self.pprint(rules), self.pprint(rules_in_ccc)), "DEBUG")
        self.log("Requires update:{0}, updated rules:{1}".format(requires_update, self.pprint(updated_rules)), "DEBUG")

        return requires_update, updated_rules

    def compare_and_update_port_rules(self, port_rules, port_rules_in_ccc):
        
        """
        Description:
            Compares and updates port rules between the provided `port_rules` and `port_rules_in_ccc`.

        Args:
            port_rules (dict): Port rules to be applied.
            port_rules_in_ccc (dict): Current port rules in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated port rules dictionary.
        """

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
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
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

        tmp_requires_update, updated_rules= self.compare_and_update_rules(rules, rules_in_ccc)
        requires_update = tmp_requires_update | requires_update

        updated_port_rules={}

        if not updated_scope_description and not updated_rules:
            return requires_update, updated_port_rules 
        if not updated_scope_description or not updated_rules:
            self.msg= """On deletion, Either scope_description:{0} or rule_descriptions:{1} for port_rules are getting completed empty.
            Atleast one parameter must be left in both to proceed with the deletion""".format(updated_scope_description, updated_rules)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        
        updated_port_rules={
            "memberType" : "interface",
            "rules": updated_rules,
            "scopeRule" : updated_scope_description
        }
        self.log("Comparing port rules for state: '{0}'".format(state), "DEBUG")
        self.log("new port rules:{0} and existing port rules:{1}".format(self.pprint(port_rules), self.pprint(port_rules_in_ccc)), "DEBUG")
        self.log("Requires update:{0}, updated port rules:{1}".format(requires_update, self.pprint(updated_port_rules)), "DEBUG")


        return requires_update, updated_port_rules
        
    def compare_and_update_device_rules(self, device_rules, device_rules_in_ccc):

        """
        Args:
            device_rules (dict): Device rules to be applied.
            device_rules_in_ccc (dict): Current device rules in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated device rules dictionary.

        Description: 
            Compares and updates device rules between the provided `device_rules` and `device_rules_in_ccc`.
        """

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

        tmp_requires_update, updated_rules= self.compare_and_update_rules(rules, rules_in_ccc)
        requires_update = tmp_requires_update | requires_update

        updated_device_rules = {}
        if updated_rules:
            updated_device_rules={
                "memberType" : "networkdevice",
                "rules": updated_rules,
            }


        self.log("Comparing device rules for state: '{0}'".format(state), "DEBUG")
        self.log("new device rules:{0} and existing device rules:{1}".format(self.pprint(device_rules), self.pprint(device_rules_in_ccc)), "DEBUG")
        self.log("Requires update:{0}, updated device rules:{1}".format(requires_update, self.pprint(updated_device_rules)), "DEBUG")

        return requires_update, updated_device_rules

    def compare_and_update_tag(self, tag, tag_in_ccc):

        """
        Args:
            tag (dict): The tag containing the updated information.
            tag_in_ccc (dict): The existing tag information in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated tag details.

        Description:
            Compares and updates tag details, including device rules and port rules, between the provided tag and the one in Cisco Catalyst Center (CCC).
        """
        
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

        tmp_requires_update, updated_device_rules = self.compare_and_update_device_rules(formatted_device_rules, formatted_device_rules_in_ccc)
        requires_update = tmp_requires_update | requires_update

        tmp_requires_update, updated_port_rules = self.compare_and_update_port_rules(formatted_port_rules, formatted_port_rules_in_ccc)
        requires_update = tmp_requires_update | requires_update

        if updated_device_rules:
            updated_device_rules["rules"]= self.group_rules_into_tree(updated_device_rules["rules"])
        
        if updated_port_rules:
            updated_port_rules["rules"]= self.group_rules_into_tree(updated_port_rules["rules"])


        updated_dynamic_rules= self.combine_device_port_rules(updated_device_rules, updated_port_rules)

        updated_tag_info={
            "name": tag_name,
            "description": description,
        }
        if updated_dynamic_rules:
            updated_tag_info["dynamic_rules"] = updated_dynamic_rules

        state = self.params.get("state")
        self.log("Comparing tag info for state: '{0}'".format(state), "DEBUG")
        self.log("new tag info: {0} and existing tag info:{1}".format(self.pprint(tag), self.pprint(tag_in_ccc)), "DEBUG")
        self.log("Requires update:{0}, updated tag info:{1}".format(requires_update, self.pprint(updated_tag_info)), "DEBUG")

        return requires_update, updated_tag_info
        
    def update_tag(self, tag, tag_id):
        """
        Args:
            tag (dict): The tag containing the updated information.
            tag_id (str): The ID of the tag to be updated.

        Returns:
            self: The updated instance with the tag's name appended to the updated_tag list if the update is successful.

        Description:
            Updates a tag in the Cisco Catalyst Center (CCC) with the provided tag details.
        """
        
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
        parameters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        success_msg = "Tag: '{0}' updated successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def delete_tag(self, tag, tag_id):

        """
        Deletes a tag from the Cisco Catalyst Center (CCC) based on the provided tag ID.

        Args:
            tag (dict): The tag containing the name and other details of the tag to be deleted.
            tag_id (str): The ID of the tag to be deleted.

        Returns:
            self: The updated instance with the tag's name appended to the deleted_tag list if the deletion is successful.
        """

        tag_name= tag.get("name")
        self.log("Starting the API call to delete tag:'{0}'".format(tag_name), "DEBUG")
        task_name = "delete_tag"
        parameters = {"id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(task_name, tag_name)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        success_msg = "Tag: '{0}' deleted successfully in the Cisco Catalyst Center".format(tag_name)
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        
        return self
    
    def get_tag_members(self, tag, tag_id):

        """
        Args:
            tag (dict): The tag containing information about the tag.
            tag_id (str): The ID of the tag whose members are to be retrieved.

        Returns:
            list: A list of dictionaries containing details of the tag members (network devices and interfaces).

        Description:
            Retrieves the list of members (network devices and interfaces) associated with a tag from the Cisco Catalyst Center (CCC).
        """

        tag_name = tag.get("name")
        self.log("Starting retrieval of members assicoated with the tag:'{0}'".format(tag_name), "DEBUG")
        member_details=[]
        offset = 1
        while True:
            try:
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
        self.log("Extracted member details for the tag: '{0}' is :{1}".format(tag_name, member_details),"INFO")
        return member_details

    def force_delete_tag_memberships(self, tag, tag_id):

        """
        Args:
            tag (dict): The tag containing information about the tag.
            tag_id (str): The ID of the tag to be processed.

        Returns:
            self: The updated instance after removing the given tag from its members.

        Description:
            Forces the update or deletion of tag memberships for network devices and interfaces associated with a tag in Cisco Catalyst Center.
            This function fetches members associated with the given tag and deletes the given tag from the respective member's tag associations.
        """
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
                    current_device_payload={
                        "id": device_id,
                        "tags": updated_tags_ids
                    }
                    network_device_detail["state"]= self.params.get("state")
                    if state =="merged":
                        self.updated_tag_memberships.append(network_device_detail)
                    elif state =="deleted":
                        self.deleted_tag_memberships.append(network_device_detail)
                    payload.append(current_device_payload)
                else:
                    network_device_detail["reason"] = "Already up to date, No new tags to update." 
                    if state =="merged":
                        network_device_detail["reason"] = "Device is already Tagged with the given tags. Nothing to update." 
                        self.not_updated_tag_memberships.append(network_device_detail)
                    elif state =="deleted":
                        network_device_detail["reason"] = "Device is not tagged with given tags. Nothing to delete." 
                        self.not_deleted_tag_memberships.append(network_device_detail)

            if payload:
                self.update_tags_associated_with_the_network_devices(payload)
            else:
                self.log("No Need for updating tags associated with the network devices", "DEBUG")

        if interface_details:
            fetched_tags_details = self.get_tags_associated_with_the_interfaces(interface_details)
            payload=[]
            for interface_detail in interface_details:
                device_id = interface_detail.get("id")
                interface_detail["tags_list"] = new_tags_details

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
                    self.updated_tag_memberships.append(interface_detail)

                    interface_detail["state"]= self.params.get("state")
                    payload.append(current_interface_payload)
                else:
                    interface_detail["reason"] = "Already up to date, No new tags to update." 
                    self.not_updated_tag_memberships.append(interface_detail)

            if payload:
                self.update_tags_associated_with_the_interfaces(payload)
            else:
                self.log("No need for updating tags associated with the interfaces", "DEBUG")

        self.log("Successfully removed the tag:{0} from all its members.".format(tag_name), "INFO")
        return self

    def get_diff_merged(self, config):
        """
        Args:
            config (dict): The configuration that contains details about the tags and tag memberships.

        Returns:
            self: The instance of the class, enabling method chaining.

        Description:
            Compares the desired configuration (`want`) with the current configuration (`have`) for tags and tag memberships.
            This function handles the creation and updating of tags and tag memberships in Cisco Catalyst Center.
        """
        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

        if tag:
            tag_name = tag.get("name")
            self.log("Starting Tag Creation/Updation for the Tag: {0}".format(tag_name), "DEBUG")
            tag_in_ccc= self.have.get("tag_info")
            
            if not tag_in_ccc:
                self.log("Starting the process of creating {0} Tag with config: {1}".format(tag_name, self.pprint(tag)), "DEBUG")
                self.create_tag(tag).check_return_status()
                self.created_tag.append(tag_name)
            else:
                self.log("Tag: {0} is already present in Cisco Catalyst Center with details: {1}".format(tag_name, self.pprint(tag_in_ccc)), "DEBUG")
                requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)

                if requires_update:
                    self.log("Updating the tag: {0} with config: {1}".format(tag_name, self.pprint(updated_tag_info)), "DEBUG")
                    self.update_tag(tag = updated_tag_info, tag_id= tag_in_ccc.get("id"))
                    self.updated_tag.append(tag_name)
                else:
                    self.not_updated_tag.append(tag_name)
                    self.log("No update required in the tag: {0}".format(tag_name), "DEBUG")

        if tag_memberships:
            self.log("Starting Tag Membership Creation/Updation", "DEBUG")
            tag_names = tag_memberships.get("tags")
            tags_details_list=[]
            for tag_name in tag_names:
                tag_id = self.get_tag_id(tag_name)
                if tag_id is None:
                    self.msg="Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(tag_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return self
                else:
                    tag_detail_dict={
                        "tag_id":tag_id,
                        "tag_name":tag_name
                    }
                    tags_details_list.append(tag_detail_dict)
            tag_memberships["tags_name_id"] = tags_details_list
            self.updating_tag_memberships(tag_memberships)

        self.msg = "Get Diff Merged Completed Successfully"
        return self
    
    def get_diff_deleted(self, config):
        """
        Args:
            config (dict): The configuration that contains details about the tags and tag memberships.

        Returns:
            self: The instance of the class, enabling method chaining.

        Description:
            Compares the desired configuration (`want`) with the current configuration (`have`) for tags and tag memberships.
            This function handles the deletion of tags and their associated memberships in Cisco Catalyst Center.
        """

        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

        if tag:
            tag_name= tag.get("name")
            self.log("Starting Tag Deletion for the Tag '{0}'".format(tag_name), "DEBUG")
            tag_in_ccc= self.have.get("tag_info")
            if not tag_in_ccc:
                self.log("Not able to delete Tag '{0}' as it is not present in Cisco Catalyst Center.".format(tag_name), "DEBUG")
                self.absent_tag.append(tag_name)
            else:
                tag_id= tag_in_ccc.get("id")
                force_delete= tag.get("force_delete")
                description= tag.get("description")
                device_rules= tag.get("device_rules")
                port_rules= tag.get("port_rules")

                if force_delete:
                    self.log("Starting Force delete for the tag: {0}".format(tag_name), "DEBUG")
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
                        self.log("Starting deletion of the tag: {0}".format(tag_name), "DEBUG")
                        tag_id = tag_in_ccc.get("id")
                        self.delete_tag(tag, tag_id)
                        self.deleted_tag.append(tag_name)
                    else:
                        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)
                        if requires_update:
                            self.log("Starting deletion of the playbook specific paramaters for the tag: {0}".format(tag_name), "DEBUG")
                            self.update_tag(tag = updated_tag_info, tag_id= tag_in_ccc.get("id"))
                            self.updated_tag.append(tag_name)
                        else:
                            self.not_updated_tag.append(tag_name)
                            self.log("Already up to date, No need of deletion of tag parameters.","INFO")

        if tag_memberships:
            self.log("Starting Tag Membership Creation/Updation", "DEBUG")
            tag_names = tag_memberships.get("tags")
            tags_details_list=[]
            for tag_name in tag_names:
                tag_id = self.get_tag_id(tag_name)
                if tag_id is None:
                    self.msg="Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(tag_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return self
                else:
                    tag_detail_dict={
                        "tag_id":tag_id,
                        "tag_name":tag_name
                    }
                    tags_details_list.append(tag_detail_dict)
                    
            tag_memberships["tags_name_id"] = tags_details_list
            self.updating_tag_memberships(tag_memberships)

        self.msg = "Get Diff Deleted Completed Successfully"

        return self

    def verify_tag_membership_diff(self, tag_memberships):

        """
        Args:
            tag_memberships (dict): A dictionary containing details of tag memberships for devices and interfaces.
                - "interface_details": List of interfaces with associated tags.
                - "network_device_details": List of network devices with associated tags.
                - "tags_name_id": List of tags to verify against the current tag memberships.
        Returns:
            bool: Returns True if all tag memberships are successfully verified without any differences. 
                Returns False if there are mismatches between the provided tag memberships and the current ones in the system.

        Description:
            Verifies if the tag memberships for network devices and interfaces match the provided details 
            in the playbook. Logs warnings if there is a mismatch.
        """

        interface_details=tag_memberships.get("interface_details")
        network_device_details=tag_memberships.get("network_device_details")
        new_tags_details = tag_memberships.get("tags_name_id")
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
        """
        Args:
            config (dict): Configuration details required to fetch current state and verify tags and memberships.
                This typically includes the current state and playbook-defined configurations.

        Returns:
            self: The object instance with the updated status and logs regarding the success or failure of the verification process.

        Description:
            Verifies if the tag and tag membership details in the playbook match the current state in the Cisco Catalyst Center.
            Logs warnings if there are discrepancies and returns the status of the operation.
        """
        self.get_have(config).check_return_status()
        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")
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
                    self.log("Tag Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful".format(tag_name), "WARNING")
                else:
                    self.log("Tag Details present in playbook and Cisco Catalyst Center are same.".format(tag_name), "DEBUG")

        if tag_memberships:
            membership_verify_diff = self.verify_tag_membership_diff(tag_memberships)
            if membership_verify_diff:
                self.log("tag memberships Details present in playbook and Cisco Catalyst Center are same.", "DEBUG")
            else:
                verify_diff = False
                self.log("tag memberships Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful", "WARNING")
        
        if verify_diff:
            self.msg="Playbook operation is successful. Verification Completed"
            self.log(self.msg, "INFO")
        else:
            self.msg="Playbook operation is unsuccessful."
            self.log(self.msg, "WARNING")
        return self

    def verify_diff_deleted(self, config):
        
        """
        Verifies whether the tag and tag membership details in the playbook align with the current state in the Cisco Catalyst Center
        when performing a delete operation. Logs warnings if there are discrepancies.

        Args:
            config (dict): Configuration details required to fetch the current state and verify tags and memberships.
                This includes the current state and playbook-defined configurations.

        Returns:
            self: The object instance with the updated status and logs indicating the success or failure of the verification process.
        """

        self.get_have(config).check_return_status()
        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

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
                else:
                    # Simple Tag Deletion Case
                    if not tag_in_ccc:
                        self.log("Tag {0} is not present in Cisco Catalyst Center".format(tag_name),"DEBUG")
                    else:
                        verify_diff = False
                        self.log("Tag {0} is still present in Cisco Catalyst Center. Playbook operation might be unsuccessful".format(tag_name),"WARNING")

        if tag_memberships:
            membership_verify_diff = self.verify_tag_membership_diff(tag_memberships)
            if membership_verify_diff:
                self.log("tag memberships Details present in playbook and Cisco Catalyst Center are same.", "DEBUG")
            else:
                verify_diff = False
                self.log("tag memberships Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful", "WARNING")
        
        if verify_diff:
            self.msg="Playbook operation is successful. Verification Completed"
            self.log(self.msg, "INFO")
        else:
            self.msg="Playbook operation is unsuccessful"
            self.log(self.msg, "WARNING")
        return self

    def int_fail(self, msg="Intentional Fail :)"):
        self.msg = msg
        self.set_operation_result("failed", False, self.msg, "ERROR")
        self.check_return_status()

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

        """
        Generates and updates messages regarding the status of tag operations (creation, update, deletion) 
        and tag memberships (updates, deletions, and non-updates) in the Cisco Catalyst Center.

        The function performs the following:
        - Adds messages for tag creation, update, and deletion status.
        - Adds messages for each tag membership update, deletion, and non-update, including reasons if applicable.
        - Sets the operation result as "changed" if any tags or memberships have been modified.

        Returns:
            self: The current object with the operation result and messages updated.
        """

        self.result["changed"] = False
        result_msg_list = []

        if self.created_tag:
            if len(self.created_tag) == 1:
                created_tag_msg = "Tag '{0}' has been created successfully in the Cisco Catalyst Center.".format(self.created_tag[0])
            else:
                created_tag_msg = "Tags '{0}' have been created successfully in the Cisco Catalyst Center.".format(", ".join(self.created_tag))
            result_msg_list.append(created_tag_msg)

        if self.updated_tag:
            if len(self.updated_tag) == 1:
                updated_tag_msg = "Tag '{0}' has been updated successfully in the Cisco Catalyst Center.".format(self.updated_tag[0])
            else:
                updated_tag_msg = "Tags '{0}' have been updated successfully in the Cisco Catalyst Center.".format(", ".join(self.updated_tag))
            result_msg_list.append(updated_tag_msg)

        if self.not_updated_tag:
            if len(self.not_updated_tag) == 1:
                not_updated_tag_msg = "Tag '{0}' needs no update in the Cisco Catalyst Center.".format(self.not_updated_tag[0])
            else:
                not_updated_tag_msg = "Tags '{0}' needs no update in the Cisco Catalyst Center.".format(", ".join(self.not_updated_tag))
            result_msg_list.append(not_updated_tag_msg)

        if self.deleted_tag:
            if len(self.deleted_tag) == 1:
                deleted_tag_msg = "Tag '{0}' has been deleted successfully in the Cisco Catalyst Center.".format(self.deleted_tag[0])
            else:
                deleted_tag_msg = "Tags '{0}' have been deleted successfully in the Cisco Catalyst Center.".format(", ".join(self.deleted_tag))
            result_msg_list.append(deleted_tag_msg)

        if self.absent_tag:
            if len(self.absent_tag) == 1:
                absent_tag_msg = "Tag '{0}' can't be deleted. It is not present in the Cisco Catalyst Center.".format(self.absent_tag[0])
            else:
                absent_tag_msg = "Tags '{0}' can't be deleted. They are not present in the Cisco Catalyst Center.".format(", ".join(self.absent_tag))
            result_msg_list.append(absent_tag_msg)

        for action, memberships in [
            ("updated", self.updated_tag_memberships),
            ("not_updated", self.not_updated_tag_memberships),
            ("deleted", self.deleted_tag_memberships),
            ("not_deleted", self.not_deleted_tag_memberships),
        ]:
            if memberships:
                for membership in memberships:
                    message = self.generate_tagging_message(action, membership)
                    if message:
                        result_msg_list.append(message)
        
        if self.created_tag or self.updated_tag or self.deleted_tag or self.updated_tag_memberships or self.deleted_tag_memberships:
            self.result["changed"] = True

        self.msg = ("\n").join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO").check_return_status()

        return self

def main():
    """ 
    main entry point for tags workflow manager module execution
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
            "from '2.3.7.9' onwards. Version '2.3.7.9' introduces APIs for creating, updating and deleting the "
            "tag and tag memberships."
            .format(ccc_tags.get_ccc_version())
        )
        ccc_tags.set_operation_result("failed", False, ccc_tags.msg, "ERROR").check_return_status()

    state = ccc_tags.params.get("state")

    if state not in ccc_tags.supported_states:
        ccc_tags.msg = "State '{0}' is invalid. Supported states:{1}. Please check the playbook and try again.".format(state, ccc_tags.supported_states)
        ccc_tags.set_operation_result("failed", False, ccc_tags.msg, "ERROR").check_return_status()

    ccc_tags.validate_input().check_return_status()
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
#  Write all the playbooks and add in examples and complete the documentation. Then start testing
# 2) ADD PROPER LOGS AND TEST THE ENTIRE WORKFLOW READING ALL THE LOGS, ALSO CHECK ALL THE LOGS.
# 3) Documentation:
# 4) SwFS doc
# 5) Proper Logging, code refactoring.
# 6) TESTING


if __name__ == '__main__':
    main()
