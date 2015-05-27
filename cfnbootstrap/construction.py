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
"""
A library for building an installation from metadata

Classes:
Contractor - orchestrates the build process
Carpenter - does the concrete work of applying metadata to the installation
Tool - performs a specific task on an installation
ToolError - a base exception type for all tools

CloudFormationCarpenter - Orchestrates a non-delegated installation
YumTool - installs packages via yum

"""
from cfnbootstrap import platform_utils
from cfnbootstrap.apt_tool import AptTool
from cfnbootstrap.auth import AuthenticationConfig
from cfnbootstrap.command_tool import CommandTool
from cfnbootstrap.construction_errors import BuildError, NoSuchConfigSetError, \
    NoSuchConfigurationError, CircularConfigSetDependencyError
from cfnbootstrap.file_tool import FileTool
from cfnbootstrap.lang_package_tools import PythonTool, GemTool
from cfnbootstrap.msi_tool import MsiTool
from cfnbootstrap.rpm_tools import RpmTool, YumTool
from cfnbootstrap.service_tools import SysVInitTool, WindowsServiceTool
from cfnbootstrap.sources_tool import SourcesTool
from cfnbootstrap.user_group_tools import GroupTool, UserTool
import collections
import contextlib
import logging
import operator
import os.path
import shelve
import sys
import time

log = logging.getLogger("cfn.init")

class WorkLog(object):
    """
    Keeps track of pending work, and can resume from the last known point
    Useful for commands that cause restarts
    """

    def __init__(self, dbname='resume_db'):
        if os.name == 'nt':
            self._shelf_dir = os.path.expandvars(r'${SystemDrive}\cfn\cfn-init')
        else:
            self._shelf_dir = '/var/lib/cfn-init'

        if not os.path.isdir(self._shelf_dir) and not os.path.exists(self._shelf_dir):
            os.makedirs(self._shelf_dir)

        if not os.path.isdir(self._shelf_dir):
            print >> sys.stderr, "Could not create %s to store the work log" % self._shelf_dir
            logging.error("Could not create %s to store the work log", self._shelf_dir)

        self._dbname = dbname

    def clear(self):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            shelf.clear()

    def clear_except_metadata(self):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            metadata = shelf.get('metadata')
            shelf.clear()
            if metadata:
                shelf['metadata'] = metadata

    def put(self, key, data):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            if data:
                shelf[key] = data
            elif key in shelf:
                del shelf[key]

    def has_key(self, key):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            return key in shelf

    def get(self, key, default=None):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            return shelf.get(key, default)

    def delete(self, key):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            del shelf[key]

    def pop(self, key):
        with contextlib.closing(shelve.open(os.path.join(self._shelf_dir, self._dbname))) as shelf:
            value = shelf[key]
            ret_val = value.popleft()
            if not value:
                del shelf[key]
            else:
                shelf[key] = value
        return ret_val

    def build(self, metadata, configSets):
        self.put('metadata', metadata)
        platform_utils.set_reboot_trigger()
        Contractor(metadata).build(configSets, self)

    def run_commands(self):
        cmd_tool = CommandTool()
        while self.has_key('commands'):
            next_cmd = self.pop('commands')
            changes = self.get('changes', collections.defaultdict(list))
            cmd_options = next_cmd[1]
            command_changes = cmd_tool.apply({next_cmd[0]:cmd_options})
            changes['commands'].extend(command_changes)
            self.put('changes', changes)
            if not command_changes:
                log.info("Not waiting as command did not execute")
            else:
                wait = CommandTool.get_wait(cmd_options)
                if wait < 0:
                    log.info("Waiting indefinitely for command to reboot")
                    sys.exit(0)
                elif wait > 0:
                    log.info("Waiting %s seconds for reboot", wait)
                    time.sleep(wait)
            
        for manager, services in self.get('services', {}).iteritems():
            if manager in CloudFormationCarpenter._serviceTools:
                CloudFormationCarpenter._serviceTools[manager]().apply(services, self.get('changes', collections.defaultdict(list)))
            else:
                log.warn("Unsupported service manager: %s", manager)

        if self.has_key('changes'):
            self.delete('changes')

        if self.has_key('services'):
            self.delete('services')

    def resume(self):
        log.debug("Starting resume")
        platform_utils.set_reboot_trigger()

        self.run_commands()

        contractor = Contractor(self.get('metadata'))

        #TODO: apply services when supported by Windows

        while self.has_key('configs'):
            next_config = self.pop('configs')
            log.debug("Resuming config: %s", next_config.name)
            contractor.run_config(next_config, self)

        if self.has_key('configSets'):
            remaining_sets = self.get('configSets')
            log.debug("Resuming configSets: %s", remaining_sets)
            contractor.build(remaining_sets, self)
        else:
            self.clear()
            platform_utils.clear_reboot_trigger()

        log.debug("Resume completed")


class CloudFormationCarpenter(object):
    """
    Takes a model and uses tools to make it reality
    """

    _packageTools = { "yum" : YumTool,
                      "rubygems" : GemTool,
                      "python" : PythonTool,
                      "rpm" : RpmTool,
                      "apt" : AptTool,
                      "msi" : MsiTool }

    _pkgOrder = ["msi", "dpkg", "rpm", "apt", "yum"]

    _serviceTools = { "sysvinit" : SysVInitTool, "windows" : WindowsServiceTool }

    @staticmethod
    def _pkgsort(x, y):
        order = CloudFormationCarpenter._pkgOrder
        if x[0] in order and y[0] in order:
            return cmp(order.index(x[0]), order.index(y[0]))
        elif x[0] in order:
            return -1
        elif y[0] in order:
            return 1
        else:
            return cmp(x[0].lower(), y[0].lower())

    def __init__(self, config, auth_config):
        self._config = config
        self._auth_config = auth_config

    def build(self, worklog):
        changes = collections.defaultdict(list)

        changes['packages'] = collections.defaultdict(list)
        if self._config.packages:
            for manager, packages in sorted(self._config.packages.iteritems(), cmp=CloudFormationCarpenter._pkgsort):
                if manager in CloudFormationCarpenter._packageTools:
                    changes['packages'][manager] = CloudFormationCarpenter._packageTools[manager]().apply(packages, self._auth_config)
                else:
                    log.warn('Unsupported package manager: %s', manager)
        else:
            log.debug("No packages specified")

        if self._config.groups:
            changes['groups'] = GroupTool().apply(self._config.groups)
        else:
            log.debug("No groups specified")

        if self._config.users:
            changes['users'] = UserTool().apply(self._config.users)
        else:
            log.debug("No users specified")

        if self._config.sources:
            changes['sources'] = SourcesTool().apply(self._config.sources, self._auth_config)
        else:
            log.debug("No sources specified")

        if self._config.files:
            changes['files'] = FileTool().apply(self._config.files, self._auth_config)
        else:
            log.debug("No files specified")

        if self._config.commands:
            if os.name=='nt':
                worklog.put('changes', changes)
                worklog.put('commands', collections.deque(sorted(self._config.commands.iteritems(), key=operator.itemgetter(0))))
            else:
                changes['commands'] = CommandTool().apply(self._config.commands)
        else:
            log.debug("No commands specified")

        if self._config.services:
            if os.name=='nt':
                worklog.put('services', self._config.services)
            else:
                for manager, services in self._config.services.iteritems():
                    if manager in CloudFormationCarpenter._serviceTools:
                        CloudFormationCarpenter._serviceTools[manager]().apply(services, changes)
                    else:
                        log.warn("Unsupported service manager: %s", manager)
        else:
            log.debug("No services specified")

class ConfigDefinition(object):
    """
    Encapsulates one config definition
    """

    def __init__(self, name, model):
        self._name = name
        self._files = model.get("files")
        self._packages = model.get("packages")
        self._services = model.get("services")
        self._sources = model.get("sources")
        self._commands = model.get("commands")
        self._users = model.get("users")
        self._groups = model.get("groups")

    @property
    def name(self):
        return self._name

    @property
    def files(self):
        return self._files

    @property
    def packages(self):
        return self._packages

    @property
    def services(self):
        return self._services

    @property
    def sources(self):
        return self._sources

    @property
    def commands(self):
        return self._commands

    @property
    def users(self):
        return self._users

    @property
    def groups(self):
        return self._groups

    def __str__(self):
        return 'Config(%s)' % self._name


class ConfigSetRef(object):
    """
    Encapsulates a ref to a ConfigSet
    """

    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    def __str__(self):
        return 'ConfigSet(%s)' % self._name

class ConfigSet(object):
    """
    A list of ConfigDefinition or ConfigSetRef objects with their dependencies
    """

    def __init__(self, configDef=None):
        """
        Arguments:
        configDef - optional ConfigDefinition|ConfigSetRef to initialize this list with (handy for 1-member lists)
        """
        self._defs = [] if not configDef else [configDef]
        self._dependencies = set() if (not configDef or isinstance(configDef, ConfigDefinition)) else set([configDef.name])

    def addConfigDef(self, configDef):
        if isinstance(configDef, ConfigSetRef):
            self._dependencies.add(configDef.name)
        self._defs.append(configDef)

    def extend(self, configDefList):
        for cd in configDefList.configDefs:
            self.addConfigDef(cd)

    @property
    def dependencies(self):
        return self._dependencies

    @property
    def configDefs(self):
        return self._defs

    def __str__(self):
        return 'ConfigSet of: %s' % ','.join(self._defs)

class Contractor(object):
    """
    Take in a metadata model and force the environment to match it, returning nothing.

    Processes configSets if they exist; otherwise, invents a virtual configSet named
    "default" with one config of "config"

    """

    _configKey = "AWS::CloudFormation::Init"
    _authKey = "AWS::CloudFormation::Authentication"
    _configSetsKey = "configSets"

    def __init__(self, model):
        initModel = model.get(Contractor._configKey)
        if not initModel:
            raise ValueError("Metadata does not contain '%s'" % Contractor._configKey)

        if not Contractor._configSetsKey in initModel:
            self._configSets = { 'default' : [ConfigDefinition("config", initModel.get("config", dict()))]}
        else:
            configSetsDef = initModel[Contractor._configSetsKey]
            if not isinstance(configSetsDef, dict):
                raise ValueError("%s should be a mapping of name to list" % Contractor._configSetsKey)

            self._processConfigSetsDefinition(configSetsDef, initModel)

        self._auth_config = AuthenticationConfig(model.get(Contractor._authKey, {}))

    def _processConfigSetsDefinition(self, configSetsDef, model):
        """
        Parse a set of configSets from the model and collapse them, validating there are no cycles
        and that all references are valid.
        """

        # This builds both a map of the uncollapsed config sets
        # as well as a lookup and reverse lookup table
        # so we can traverse the graph and detect cycles
        # in a not-terrible time

        rawConfigSets = {}
        dependencyTree = {} # maps configSets to the configSets they depend on
        reverseDependencyTree = collections.defaultdict(set) # maps configSets to the configSets that depend on them
        roots = set() # the roots of the configSets graph -- configSets without dependencies
        for configSetName, configList in configSetsDef.iteritems():
            processedList = self._processConfigList(configList, model)
            if processedList.dependencies:
                dependencyTree[configSetName] = set(processedList.dependencies)
                for dependency in processedList.dependencies:
                    reverseDependencyTree[dependency].add(configSetName)
            else:
                roots.add(configSetName)

            rawConfigSets[configSetName] = list(processedList.configDefs)

        if not roots:
            raise CircularConfigSetDependencyError("No configSets exist without references; this creates a circular dependency and is not allowed")

        self._configSets = {}
        # use a traditional (Kahn) topological sort to traverse the configSets in dependency order
        # http://en.wikipedia.org/wiki/Topological_sort#Algorithms has a nice description
        while roots:
            configSet = roots.pop()
            self._configSets[configSet] = self._collapse(configSet, rawConfigSets[configSet])
            for dependent in reverseDependencyTree.pop(configSet, []):
                dependencyTree[dependent].remove(configSet)
                if not dependencyTree[dependent]:
                    roots.add(dependent)
                    del dependencyTree[dependent]

        if dependencyTree:
            raise CircularConfigSetDependencyError("At least one circular dependency detected; this is not allowed. Culprits: " + ', '.join(dependencyTree.keys()))


    def _collapse(self, configSetName, configList):
        """
        Transform ConfigSetRefs into the contents of the ConfigSets they reference, returning a list of only ConfigDefinition objects
        """
        returnList = []

        for config in configList:
            if isinstance(config, ConfigDefinition):
                returnList.append(config)
            else:
                if not config.name in self._configSets:
                    raise ValueError("ConfigSet %s referenced ConfigSet %s but it is not defined" % (configSetName, config.name))
                returnList.extend(self._configSets[config.name])

        return returnList

    def _processConfigList(self, configList, model):
        """
        Processes a parsed-JSON list of config definitions, returning a ConfigSet

        Handles both references ({"ConfigSet" : "name"}) and plain config names
        so users can define simple ConfigSets without using lists, and so we can recurse simply
        """

        if isinstance(configList, basestring):
            if not configList in model:
                raise NoSuchConfigurationError("No configuration found with name: %s" % configList)
            return ConfigSet(ConfigDefinition(configList, model[configList]))

        if isinstance(configList, dict):
            if not 'ConfigSet' in configList:
                raise ValueError("Config definitions must be either a config name or a reference in the format {'ConfigSet':<config set name>}")
            setName = configList['ConfigSet']
            if not setName in model[Contractor._configSetsKey]:
                raise ValueError("Configuration set %s was referenced but not defined" % setName)
            return ConfigSet(ConfigSetRef(setName))

        returnSet = ConfigSet()
        for configDef in configList:
            returnSet.extend(self._processConfigList(configDef, model))

        return returnSet


    def build(self, configSets, worklog):
        """Does the work described by each configSet, in order, returning nothing"""

        worklog.clear_except_metadata()

        configSets = collections.deque(configSets)
        log.info("Running configSets: %s", ', '.join(configSets))

        while configSets:
            configSetName = configSets.popleft()
            if not configSetName in self._configSets:
                raise NoSuchConfigSetError("Error: no ConfigSet named %s exists" % configSetName)

            worklog.put('configSets', configSets)

            configSet = collections.deque(self._configSets[configSetName])
            log.info("Running configSet %s", configSetName)
            while configSet:
                config = configSet.popleft()

                worklog.put('configs', configSet)

                self.run_config(config, worklog)

        log.info("ConfigSets completed")
        worklog.clear()
        platform_utils.clear_reboot_trigger()

    def run_config(self, config, worklog):
        log.info("Running config %s", config.name)
        try:
            CloudFormationCarpenter(config, self._auth_config).build(worklog)

            worklog.run_commands()
        except BuildError, e:
            log.exception("Error encountered during build of %s: %s", config.name, str(e))
            raise

    @classmethod
    def metadataValid(cls, metadata):
        return metadata and cls._configKey in metadata and metadata[cls._configKey]

    @property
    def configs(self):
        return dict(self._configSets)
