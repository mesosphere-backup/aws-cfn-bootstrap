#==============================================================================
# Copyright 2011 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#==============================================================================
import logging
import security

log = logging.getLogger("cfn.init")

class GroupTool(object):
    """
    Creates OS groups
    """

    def apply(self, action):
        """
        Create groups, returning a list of groups that were created

        Arguments:
        action -- a dict of group name to attributes, where attributes has keys of:
            gid: the gid of the user (a string or int)

        Exceptions:
        ToolError -- on expected failures
        """

        groups_created = []

        if not action:
            log.debug("No groups specified")
            return groups_created

        for name in sorted(action.keys()):
            gid = None
            if "gid" in action[name]:
                gid = str(action[name]["gid"])

            if security.create_group(name, gid):
                groups_created.append(name)

        return groups_created

class UserTool(object):
    """
    Creates OS Users
    """

    def apply(self, action):
        """
        Create users, returning a list of users that were created or modified

        Arguments:
        action -- a dict of user name to attributes, where attributes has keys of:
            groups: A list of group names for this user to be a member of
            homeDir: The home directory for this user
            uid: The uid for this user

        Exceptions:
        ToolError -- on expected failures
        """

        users_modified = []
        if not action:
            log.debug("No users specified")
            return users_modified

        for name in sorted(action.keys()):
            attributes = action[name]

            uid = None if not "uid" in attributes else str(attributes["uid"])

            if security.create_or_modify_user(name, attributes.get("groups", []), attributes.get("homeDir", None), uid):
                users_modified.append(name)

        return users_modified
