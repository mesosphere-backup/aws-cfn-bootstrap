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
import logging
import os
import re
from cfnbootstrap.packages import requests
import tempfile

log = logging.getLogger("cfn.init")

_msi_supported = True
try:
    import win32com.client
except ImportError:
    _msi_supported = False

class MsiTool(object):

    _remote_pattern = re.compile(r'^(https?|ftp)://.*$', re.I)

    def apply(self, action, auth_config):

        """
        Install a set of MSI packages

        Arguments:
        action -- a dict of package name to path, which is a string

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action.keys():
            log.debug("No packages installed for MSI")
            return pkgs_changed

        if not _msi_supported:
            raise ToolError("MSI support is only available under Windows")

        pkgs = {}
        tmp_pkgs=[]

        installer_db = Installer()

        try:
            for name, loc in action.iteritems():
                if MsiTool._remote_pattern.match(loc):
                    try:
                        msi_file = self._msi_from_url(loc, auth_config)
                    except IOError, e:
                        raise ToolError("Failed to retrieve %s: %s" % (loc, e.strerror))
                    tmp_pkgs.append(msi_file)
                else:
                    msi_file = loc

                if installer_db.isMsiInstalled(msi_file):
                    log.info("%s is already installed; skipping", name)
                else:
                    pkgs[name] = msi_file

            if not pkgs:
                log.info("All MSI packages already installed")
                return

            for name, pkg in pkgs.iteritems():
                log.debug("Installing %s via MSI", name)
                installer_db.installProduct(pkg)

                log.info("Installed %s successfully", name)
                pkgs_changed.append(pkg)

            return pkgs_changed
        finally:
            for tmp_pkg in tmp_pkgs:
                os.remove(tmp_pkg)

    @util.retry_on_failure()
    def _msi_from_url(self, archive, auth_config):
        tf = tempfile.mkstemp(suffix='.msi', prefix='cfn-init-tmp')

        with os.fdopen(tf[0], 'wb') as temp_dest:
            opts = util.req_opts({'auth': auth_config.get_auth(None)})
            util.EtagCheckedResponse(requests.get(archive, **opts)).write_to(temp_dest)

        return tf[1]

class Installer(object):

    def __init__(self):
        self._installer = win32com.client.gencache.EnsureModule('{000C1092-0000-0000-C000-000000000046}', 1033, 1, 0).Installer()
        self._installer.UILevel = 2 # Hide UI

    def getProperty(self, msi_path, msi_property):
        db = self._installer.OpenDatabase(msi_path, 0)
        view = db.OpenView(r"Select `Value` From Property WHERE `Property` =?")
        try:
            paramRecord = self._installer.CreateRecord(1)
            paramRecord.SetStringData(1, msi_property)
            view.Execute(paramRecord)
            resultRecord = view.Fetch()
            return resultRecord.StringData(1)
        finally:
            view.Close()

    def isMsiInstalled(self, msi_path):
        productCode = self.getProperty(msi_path, "ProductCode")

        try:
            self._installer.ProductInfo(productCode, "VersionString")
            return True
        except Exception:
            return False

    def installProduct(self, msi_path):
        self._installer.InstallProduct(msi_path, "REBOOT=ReallySuppress ALLUSERS=1")