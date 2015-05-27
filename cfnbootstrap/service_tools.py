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
from cfnbootstrap import util
from cfnbootstrap.construction_errors import ToolError
from cfnbootstrap.util import ProcessHelper
import collections
import logging
import os.path

log = logging.getLogger("cfn.init")

_windows_supported = True
try:
    import win32service
    import win32serviceutil
except ImportError:
    _windows_supported = False

class ServiceTool(object):

    def _detect_required_restart(self, serviceProperties, changes):
        if self._list_type_change_occurred(serviceProperties, changes, 'files'):
            return True

        if self._list_type_change_occurred(serviceProperties, changes, 'sources'):
            return True

        if self._list_type_change_occurred(serviceProperties, changes, 'groups'):
            return True

        if self._list_type_change_occurred(serviceProperties, changes, 'users'):
            return True

        if self._list_type_change_occurred(serviceProperties, changes, 'commands'):
            return True

        if 'packages' in serviceProperties and 'packages' in changes:
            for manager, pkg_list in changes['packages'].iteritems():
                if manager in serviceProperties['packages']:
                    if frozenset(serviceProperties['packages'][manager]) & frozenset(pkg_list):
                        return True

        return False

    def _list_type_change_occurred(self, serviceProperties, changes, key):
        if key in serviceProperties and key in changes:
            if frozenset(serviceProperties[key]) & frozenset(changes[key]):
                return True

        return False

class WindowsServiceTool(ServiceTool):
    """
    Manages Windows services
    
    """
    
    def apply(self, action, changes = collections.defaultdict(list)):
        """
        Takes a dict of service name to dict.
        Keys we look for are:
            - "enabled" (setting a service to "Automatic")
            - "ensureRunning" (actually start the service)
        """

        if not action.keys():
            log.debug("No Windows services specified")
            return
        
        if not _windows_supported:
            raise ToolError("Cannot modify windows services without pywin32")
        
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        try:
            for service, serviceProperties in action.iteritems():
                handle = win32service.OpenService(manager, service, win32service.SERVICE_ALL_ACCESS)
                try:
                    if "enabled" in serviceProperties:
                        start_type = win32service.SERVICE_AUTO_START if util.interpret_boolean(serviceProperties["enabled"]) else win32service.SERVICE_DEMAND_START
                        self._set_service_startup_type(handle, start_type)
                    else:
                        log.debug("Not modifying enabled state of service %s", service)
                        
                    if self._detect_required_restart(serviceProperties, changes):
                        log.debug("Restarting %s due to change detected in dependency", service)
                        win32serviceutil.RestartService(service)
                    elif "ensureRunning" in serviceProperties:
                        ensureRunning = util.interpret_boolean(serviceProperties["ensureRunning"])
                        status = win32service.QueryServiceStatus(handle)[1]
                        isRunning = status & win32service.SERVICE_RUNNING or status & win32service.SERVICE_START_PENDING
                                        
                        if ensureRunning and not isRunning:
                            log.debug("Starting service %s as it is not running", service)
                            win32service.StartService(handle, None)
                        elif not ensureRunning and isRunning:
                            log.debug("Stopping service %s as it is running", service)
                            win32service.ControlService(handle, win32service.SERVICE_CONTROL_STOP)
                        else:
                            log.debug("No need to modify running state of service %s", service)
                    else:
                        log.debug("Not modifying running state of service %s", service)
                finally:
                    win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(manager)
    
    def _set_service_startup_type(self, service, start_type):
        win32service.ChangeServiceConfig(service,
                                         win32service.SERVICE_NO_CHANGE,
                                         start_type,
                                         win32service.SERVICE_NO_CHANGE,
                                         None,
                                         None,
                                         0,
                                         None,
                                         None,
                                         None,
                                         None)

class SysVInitTool(ServiceTool):
    """
    Manages SysV Init services

    """

    def apply(self, action, changes = collections.defaultdict(list)):
        """
        Takes a dict of service name to dict.
        Keys we look for are:
            - "enabled" (equivalent to /sbin/chkconfig service on)
            - "ensureRunning" (equivalent to /sbin/service service start)
        """

        if not action.keys():
            log.debug("No System V init scripts specified")
            return

        for service, serviceProperties in action.iteritems():
            force_restart = self._detect_required_restart(serviceProperties, changes)

            if "enabled" in serviceProperties:
                self._set_service_enabled(service, util.interpret_boolean(serviceProperties["enabled"]))
            else:
                log.debug("Not modifying enabled state of service %s", service)

            if force_restart:
                log.debug("Restarting %s due to change detected in dependency", service)
                self._restart_service(service)
            elif "ensureRunning" in serviceProperties:
                ensureRunning = util.interpret_boolean(serviceProperties["ensureRunning"])
                isRunning = self._is_service_running(service)
                if ensureRunning and not isRunning:
                    log.debug("Starting service %s as it is not running", service)
                    self._start_service(service)
                elif not ensureRunning and isRunning:
                    log.debug("Stopping service %s as it is running", service)
                    self._stop_service(service)
                else:
                    log.debug("No need to modify running state of service %s", service)
            else:
                log.debug("Not modifying running state of service %s", service)

    def _restart_service(self, service):
        cmd = self._get_service_executable(service)
        cmd.append("restart")

        result = ProcessHelper(cmd).call()

        if result.returncode:
            log.error("Could not restart service %s; return code was %s", service, result.returncode)
            log.debug("Service output: %s", result.stdout)
            raise ToolError("Could not restart %s" % service)
        else:
            log.info("Restarted %s successfully", service)

    def _start_service(self, service):
        cmd = self._get_service_executable(service)
        cmd.append("start")

        result = ProcessHelper(cmd).call()

        if result.returncode:
            log.error("Could not start service %s; return code was %s", service, result.returncode)
            log.debug("Service output: %s", result.stdout)
            raise ToolError("Could not start %s" % service)
        else:
            log.info("Started %s successfully", service)

    def _stop_service(self, service):
        cmd = self._get_service_executable(service)
        cmd.append("stop")

        result = ProcessHelper(cmd).call()

        if result.returncode:
            log.error("Could not stop service %s; return code was %s", service, result.returncode)
            log.debug("Service output: %s", result.stdout)
            raise ToolError("Could not stop %s" % service)
        else:
            log.info("Stopped %s successfully", service)

    def _is_service_running(self, service):
        cmd = self._get_service_executable(service)
        cmd.append("status")

        result = ProcessHelper(cmd).call()

        if result.returncode:
            return False

        return True

    def _set_service_enabled(self, service, enabled=True):
        modifier = self._get_service_modifier()
        if not modifier:
            log.error("Could not enable %s, as chkconfig and update-rc.d were not available", service)
            return

        log.debug("Setting service %s to %s", service, "enabled" if enabled else "disabled")

        modifier.set_service_enabled(service, enabled);

    def _get_service_modifier(self):
        if hasattr(self, '_cached_modifier'):
            return self._cached_modifier

        if Chkconfig.installed():
            self._cached_modifier = Chkconfig()
        elif UpdateRcD.installed():
            self._cached_modifier = UpdateRcD()
        else:
            self._cached_modifier = None

        log.debug("Using service modifier: %s", self._cached_modifier)

        return self._cached_modifier

    def _get_service_executable(self, service):
        """
        Returns the service executable as an array
        Right now either ["/sbin/service", service], ["/usr/sbin/service", service], or ["/etc/init.d/<service>"]
        """
        if not hasattr(self, '_service_runner'):
            if os.path.exists("/sbin/service"):
                self._service_runner = "/sbin/service"
            elif os.path.exists("/usr/sbin/service"):
                self._service_runner = "/usr/sbin/service"
            else:
                self._service_runner = None

            if self._service_runner:
                log.debug("Using service runner: %s", self._service_runner)
            else:
                log.debug("Running init scripts directly")

        if self._service_runner:
            return [self._service_runner, service]
        else:
            return ["/etc/init.d/%s" % service]

class Chkconfig(object):

    _executable = "/sbin/chkconfig"

    @classmethod
    def installed(cls):
        return os.path.exists(cls._executable)

    def __init__(self):
        #Leaving this open for multiple locations of chkconfig
        self._executable = Chkconfig._executable

    def __str__(self, *args, **kwargs):
        return self._executable

    def set_service_enabled(self, service, enabled=True):
        if not os.path.exists(self._executable):
            raise ToolError("Cannot find chkconfig")

        result = ProcessHelper([self._executable, service, 'on' if enabled else 'off']).call()

        if result.returncode:
            log.error("chkconfig failed with error %s. Output: %s", result.returncode, result.stdout)
            raise ToolError("Could not %s service %s" % ("enable" if enabled else "disable", service), result.returncode)
        else:
            log.info("%s service %s", "enabled" if enabled else "disabled", service)

class UpdateRcD(object):

    _executable = "/usr/sbin/update-rc.d"

    @classmethod
    def installed(cls):
        return os.path.exists(cls._executable)

    def __init__(self):
        #Leaving this open for multiple locations of update-rc.d
        self._executable = UpdateRcD._executable

    def __str__(self, *args, **kwargs):
        return self._executable

    def set_service_enabled(self, service, enabled=True):
        if not os.path.exists(self._executable):
            raise ToolError("Cannot find update-rc.d")

        result = ProcessHelper([self._executable, service, 'enable' if enabled else 'disable']).call()

        if result.returncode:
            log.error("update-rc.d failed with error %s. Output: %s", result.returncode, result.stdout)
            raise ToolError("Could not %s service %s" % ("enable" if enabled else "disable", service), result.returncode)
        else:
            log.info("%s service %s", "enabled" if enabled else "disabled", service)

