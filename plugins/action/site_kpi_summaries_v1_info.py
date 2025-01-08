#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.plugins.action import ActionBase
try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.dnac.plugins.plugin_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    taskId=dict(type="str"),
    startTime=dict(type="float"),
    endTime=dict(type="float"),
    siteHierarchy=dict(type="str"),
    siteHierarchyId=dict(type="str"),
    siteId=dict(type="str"),
    siteType=dict(type="str"),
    ssid=dict(type="str"),
    band=dict(type="str"),
    failureCategory=dict(type="str"),
    failureReason=dict(type="str"),
    view=dict(type="str"),
    attribute=dict(type="str"),
    limit=dict(type="float"),
    offset=dict(type="float"),
    sortBy=dict(type="str"),
    order=dict(type="str"),
    headers=dict(type="dict"),
))

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail("ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = True
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def get_object(self, params):
        new_object = dict(
            task_id=params.get("taskId"),
            start_time=params.get("startTime"),
            end_time=params.get("endTime"),
            site_hierarchy=params.get("siteHierarchy"),
            site_hierarchy_id=params.get("siteHierarchyId"),
            site_id=params.get("siteId"),
            site_type=params.get("siteType"),
            ssid=params.get("ssid"),
            band=params.get("band"),
            failure_category=params.get("failureCategory"),
            failure_reason=params.get("failureReason"),
            view=params.get("view"),
            attribute=params.get("attribute"),
            limit=params.get("limit"),
            offset=params.get("offset"),
            sort_by=params.get("sortBy"),
            order=params.get("order"),
            headers=params.get("headers"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        self._result.update(dict(dnac_response={}))

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="sites",
            function='get_site_analytics_for_the_child_sites_of_given_parent_site_and_other_query_parameters_v1',
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result