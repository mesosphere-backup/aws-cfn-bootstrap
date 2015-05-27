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

from cfnbootstrap.util import ProcessHelper
import logging
import os
from cfnbootstrap.construction_errors import ToolError
import subprocess

log = logging.getLogger("cfn.init")

class AptTool(object):
    """
    Installs packages via APT

    """

    def apply(self, action, auth_config=None):
        """
        Install a set of packages via APT, returning the packages actually installed or updated.

        Arguments:
        action -- a dict of package name to version; version can be empty, a single string or a list of strings

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action:
            log.debug("No packages specified for APT")
            return pkgs_changed

        cache_result = ProcessHelper(['apt-cache', '-q', 'gencaches']).call()

        if cache_result.returncode:
            log.error("APT gencache failed. Output: %s", cache_result.stdout)
            raise ToolError("Could not create apt cache", cache_result.returncode)

        pkg_specs = []

        for pkg_name in action:
            if action[pkg_name]:
                if isinstance(action[pkg_name], basestring):
                    pkg_keys = ['%s=%s' % (pkg_name, action[pkg_name])]
                else:
                    pkg_keys = ['%s=%s' % (pkg_name, ver) if ver else pkg_name for ver in action[pkg_name]]
            else:
                pkg_keys = [pkg_name]

            pkgs_filtered = [pkg_key for pkg_key in pkg_keys if self._pkg_filter(pkg_key, pkg_name)]
            if pkgs_filtered:
                pkg_specs.extend(pkgs_filtered)
                pkgs_changed.append(pkg_name)

        if not pkg_specs:
            log.info("All APT packages were already installed")
            return []

        log.info("Attempting to install %s via APT", pkg_specs)

        env = dict(os.environ)
        env['DEBIAN_FRONTEND'] = 'noninteractive'

        result = ProcessHelper(['apt-get', '-q', '-y', 'install'] + pkg_specs, env=env).call()

        if result.returncode:
            log.error("apt-get failed. Output: %s", result.stdout)
            raise ToolError("Could not successfully install APT packages", result.returncode)

        log.info("APT installed %s", pkgs_changed)
        log.debug("APT output: %s", result.stdout)

        return pkgs_changed

    def _pkg_filter(self, pkg, pkg_name):
        if self._pkg_installed(pkg, pkg_name):
            log.debug("%s will not be installed as it is already present", pkg)
            return False
        elif not self._pkg_available(pkg):
            log.error("%s is not available to be installed", pkg)
            raise ToolError("APT does not have %s available for installation" % pkg)
        else:
            return True

    def _pkg_available(self, pkg):
        result = ProcessHelper(['apt-cache', '-q', 'show', pkg]).call()

        return result.returncode == 0

    def _pkg_installed(self, pkg, pkg_name):
        """
        Test if a package is installed (exact version match if version is specified), returning a boolean.

        Arguments:
        pkg -- the full package specification (including version if specified) in pkg=version format
        pkg_name -- the name of the package
        """

        result = ProcessHelper(['dpkg-query', '-f', '${Status}|${Package}=${Version}', '-W', pkg_name], stderr=subprocess.PIPE).call()

        if result.returncode or not result.stdout:
            return False

        status,divider,spec = result.stdout.strip().partition('|')

        if status.rpartition(" ")[2] != 'installed':
            return False

        return spec.startswith(pkg)