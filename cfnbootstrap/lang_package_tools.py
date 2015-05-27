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
from cfnbootstrap.construction_errors import ToolError
import re

log = logging.getLogger("cfn.init")

class PythonTool(object):
    """
    Installs packages via easy_install

    """

    def apply(self, action, auth_config=None):
        """
        Install a set of packages via easy_install, returning the packages actually installed or updated.

        Arguments:
        action -- a dict of package name to version; version can be empty, a single string or a list of strings

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action.keys():
            log.debug("No packages specified for python")
            return pkgs_changed

        pkgs = []

        for pkg in action:
            if not action[pkg] or isinstance(action[pkg], basestring):
                pkgs.append(PythonTool._pkg_spec(pkg, action[pkg]))
            else:
                pkgs.extend(PythonTool._pkg_spec(pkg, ver) for ver in action[pkg])

            pkgs_changed.append(pkg)

        log.info("Attempting to install %s via easy_install", pkgs)

        result = ProcessHelper(['easy_install'] + pkgs).call()

        if result.returncode:
            log.error("easy_install failed. Output: %s", result.stdout)
            raise ToolError("Could not successfully install python packages", result.returncode)
        else:
            log.info("easy_install installed %s", pkgs)
            log.debug("easy_install output: %s", result.stdout)

        return pkgs_changed

    _url_pattern = re.compile(r'^https?://.*$')

    @classmethod
    def _pkg_spec(cls, pkg, ver):
        if not ver:
            return pkg
        if cls._url_pattern.match(ver.lower()):
            return ver
        return '%s==%s' % (pkg, ver)

class GemTool(object):
    """
    Installs packages via rubygems

    """

    def apply(self, action, auth_config=None):
        """
        Install a set of packages via rubygems, returning the packages actually installed or updated.

        Arguments:
        action -- a dict of package name to version; version can be empty, a single string or a list of strings

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action.keys():
            log.debug("No gems specified")
            return pkgs_changed

        for pkg in action:
            installed = False
            if not action[pkg]:
                installed = self._install_gem(pkg)
            else:
                if isinstance(action[pkg], basestring):
                    installed = self._install_gem(pkg, action[pkg])
                else:
                    for ver in action[pkg]:
                        if self._install_gem(pkg, ver):
                            installed = True

            if installed:
                pkgs_changed.append(pkg)

        return pkgs_changed

    def _gem_is_installed(self, pkg, ver=None):
        """"
        Check to see if a package at version ver is installed.
        If ver is not specified, just check for the package.
        """
        log.debug("Checking to see if %s-%s is already installed", pkg, ver)

        queryCmd = ['gem', 'query', '-i', '-n', '^%s$' % pkg]

        if ver:
            queryCmd.extend(['-v', '%s' % ver])

        result = ProcessHelper(queryCmd).call()

        if result.returncode:
            return False
        else:
            return True

    def _install_gem(self, pkg, ver=None):
        """Install a gem if the version is not already installed; return True if installed, False if skipped."""
        if self._gem_is_installed(pkg, ver):
            log.info("%s-%s is already installed, skipping.", pkg, ver)
            return False
        else:
            log.info("Installing %s version %s via gem", pkg, ver)

            install_command = ['gem', 'install', '-b', '--no-ri', '--no-rdoc', pkg];

            if ver:
                install_command.extend(['-v', '= %s' % ver])

            result = ProcessHelper(install_command).call()

            if result.returncode:
                log.error("Gem failed. Output: %s", result.stdout)
                raise ToolError("Failed to install gem: %s-%s" % (pkg, ver), result.returncode)
            else:
                log.info("Gem installed: %s-%s", pkg, ver)
                log.debug("Gem output: %s", result.stdout)
                return True