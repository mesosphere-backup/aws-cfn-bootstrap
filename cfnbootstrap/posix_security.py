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
import pwd
import grp
import os
import logging
from cfnbootstrap.construction_errors import ToolError
from cfnbootstrap.util import ProcessHelper

log = logging.getLogger("cfn.init")

def set_owner_and_group(filename, owner_name, group_name):
    owner_id = -1
    group_id = -1

    if owner_name:
        try:
            owner_id = pwd.getpwnam(owner_name)[2]
        except KeyError:
            raise ToolError("%s is not a valid user name" % owner_name)

    if group_name:
        try:
            group_id = grp.getgrnam(group_name)[2]
        except KeyError:
            raise ToolError("%s is not a valid group name" % group_name)

    if group_id != -1 or owner_id != -1:
        logging.debug("Setting owner %s and group %s for %s", owner_id, group_id, filename)
        os.lchown(filename, owner_id, group_id)

def create_group(group_name, gid=None):
    """Create a group in the OS, returning True if one is created"""
    try:
        group_record = grp.getgrnam(group_name)
        if gid and str(group_record[2]) != gid:
            raise ToolError("Group %s exists with gid %s, but gid %s was requested" % (group_name, group_record[2], gid))
        log.debug("Group %s already exists", group_name)
        return False
    except KeyError:
        pass

    cmd = ['/usr/sbin/groupadd', '-r']

    if gid:
        cmd.extend(['-g', gid])

    cmd.append(group_name)

    result = ProcessHelper(cmd).call()

    if result.returncode:
        log.error("Failed to create group %s", group_name)
        log.debug("Groupadd output: %s", result.stdout)
        raise ToolError("Failed to create group %s" % group_name)
    else:
        log.info("Created group %s successfully", group_name)
        return True


def create_or_modify_user(user_name, groups=[], homedir=None, uid=None):
    """Create or modify a user in the OS, returning True if action was taken"""
    try:
        user_record = pwd.getpwnam(user_name)
        if uid and str(user_record[2]) != uid:
            raise ToolError("User %s exists with uid %s, but uid %s was requested" % (user_name, user_record[2], uid))
        return _modify_user(user_name, groups, homedir)
    except KeyError:
        _create_user(user_name, groups, homedir, uid)
        return True

def _modify_user(user_name, groups=[], homedir=None):
    """ Modify a user and return True, else return False """
    if not homedir and not groups:
        log.info("No homedir or groups specified; not modifying %s", user_name)
        return False

    cmd = ['/usr/sbin/usermod']

    if groups:
        gids = _get_gids(groups)
        current_gids = _gids_for_user(user_name)
        if frozenset(gids) ^ frozenset(current_gids):
            cmd.extend(['-G', ','.join(gids)])
        else:
            log.debug("Groups have not changed for %s", user_name)

    if homedir:
        if homedir != _get_user_homedir(user_name):
            cmd.extend(['-d', homedir])
        else:
            log.debug("Homedir has not changed for %s", user_name)

    if len(cmd) == 1:
        log.debug("User %s does not need modification", user_name)
        return False

    cmd.append(user_name)

    result = ProcessHelper(cmd).call()

    if result.returncode:
        log.error("Failed to modify user %s", user_name)
        log.debug("Usermod output: %s", result.stdout)
        raise ToolError("Failed to modify user %s" % user_name)
    else:
        log.info("Modified user %s successfully", user_name)
        return True

def _get_user_homedir(user_name):
    return pwd.getpwnam(user_name)[5]

def _create_user(user_name, groups=[], homedir=None, uid=None):
    gids = _get_gids(groups)

    cmd = ['/usr/sbin/useradd', '-M', '-r', '--shell', '/sbin/nologin']

    if homedir:
        cmd.extend(['-d', homedir])

    if uid:
        cmd.extend(['-u', uid])

    if gids:
        cmd.extend(['-G', ','.join(gids)])

    cmd.append(user_name)

    result = ProcessHelper(cmd).call()

    if result.returncode:
        log.error("Failed to add user %s", user_name)
        log.debug("Useradd output: %s", result.stdout)
        raise ToolError("Failed to add user %s" % user_name)
    else:
        log.info("Added user %s successfully", user_name)

def _get_gids(groups):
    gids = []
    for group_name in groups:
        try:
            gids.append(str(grp.getgrnam(group_name)[2]))
        except KeyError:
            raise ToolError("%s is not a valid group name" % group_name)
    return gids

def _gids_for_user(user_name):
    return [str(group[2]) for group in grp.getgrall() if user_name in group[3]]
