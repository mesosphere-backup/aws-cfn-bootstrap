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
from cfnbootstrap import update_hooks
import cfnbootstrap
import logging
import os
import time

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:
    logging.warn("Win32 cfn-hup service requires pywin32")

class HupService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'cfn-hup'
    _svc_display_name_="CloudFormation cfn-hup"
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STOPPED,
                              (self._svc_name_, ''))
        win32event.SetEvent(self.hWaitStop)
        
    def SvcDoRun(self):
        try:
            main_config, processor, cmd_processor = update_hooks.parse_config(os.path.expandvars('${SystemDrive}\cfn'))
        except ValueError, e:
            servicemanager.LogMsg(servicemanager.EVENTLOG_ERROR_TYPE,
                                  servicemanager.PYS_SERVICE_STOPPING,
                                  (self._svc_name_, ': %s' % str(e)))
            return
        
        verbose = main_config.has_option('main', 'verbose') and main_config.getboolean('main', 'verbose')
        cfnbootstrap.configureLogging("DEBUG" if verbose else "INFO", filename='cfn-hup.log')
        log = logging.getLogger("cfn.hup")
        
        if main_config.has_option('main', 'interval'):
            interval = main_config.getint('main', 'interval')
            if interval < 1:
                log.error("Invalid interval (must be 1 minute or greater): %s", interval)
                interval = 15
        else:
            interval = 15
                
        interval = interval * 60
        
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        
        last_normal_hup = 0
        delay = 1 * 1000
        while True:
            try:
                if processor and time.time() - last_normal_hup > interval:
                    processor.process()
                    last_normal_hup = time.time()
                
                if cmd_processor:
                    if not cmd_processor.is_registered():
                        cmd_processor.register()
                    
                    if cmd_processor.creds_expired():
                        delay = 20 * 1000
                        log.error("Expired credentials found; skipping process")
                    else:
                        delay = 1 * 1000
                        cmd_processor.process()
            except update_hooks.FatalUpdateError:
                log.exception("Fatal exception caught; stopping cfn-hup")
                break
            except Exception:
                log.exception("Unhandled exception")
            
            if win32event.WAIT_OBJECT_0 == win32event.WaitForSingleObject(self.hWaitStop, delay):
                log.info("Received shutdown event; stopping cfn-hup")
                break
            
    