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
from cfnbootstrap.construction_errors import ToolError
from cfnbootstrap.util import ProcessHelper, LoggingProcessHelper
import logging
import re
import subprocess

log = logging.getLogger("cfn.init")

class YumTool(object):
    """
    Installs packages via Yum

    """

    def apply(self, action, auth_config=None):
        """
        Install a set of packages via yum, returning the packages actually installed or updated.

        Arguments:
        action -- a dict of package name to version; version can be empty, a single string or a list of strings

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action.keys():
            log.debug("No packages specified for yum")
            return pkgs_changed

        cache_result = ProcessHelper(['yum', '-y', 'makecache']).call()

        if cache_result.returncode:
            log.error("Yum makecache failed. Output: %s", cache_result.stdout)
            raise ToolError("Could not create yum cache", cache_result.returncode)

        pkg_specs_to_upgrade = []
        pkg_specs_to_downgrade = []

        for pkg_name in action:
            if action[pkg_name]:
                if isinstance(action[pkg_name], basestring):
                    pkg_ver = action[pkg_name]
                else:
                    # Yum only cares about one version anyway... so take the max specified version in the list
                    pkg_ver = RpmTool.max_version(action[pkg_name])
            else:
                pkg_ver = None

            pkg_spec = '%s-%s' % (pkg_name, pkg_ver) if pkg_ver else pkg_name

            if self._pkg_installed(pkg_spec):
                # If the EXACT requested spec is installed, don't do anything
                log.debug("%s will not be installed as it is already present", pkg_spec)
            elif not self._pkg_available(pkg_spec):
                # If the requested spec is not available, blow up
                log.error("%s is not available to be installed", pkg_spec)
                raise ToolError("Yum does not have %s available for installation" % pkg_spec)
            elif not pkg_ver:
                # If they didn't request a specific version, always upgrade
                pkg_specs_to_upgrade.append(pkg_spec)
                pkgs_changed.append(pkg_name)
            else:
                # They've requested a specific version that's available but not installed.
                # Figure out if it's an upgrade or a downgrade
                installed_version = RpmTool.get_package_version(pkg_name, False)[1]
                if self._should_upgrade(pkg_ver, installed_version):
                    pkg_specs_to_upgrade.append(pkg_spec)
                    pkgs_changed.append(pkg_name)
                else:
                    log.debug("Downgrading to %s from installed version %s", pkg_spec, installed_version)
                    pkg_specs_to_downgrade.append(pkg_spec)
                    pkgs_changed.append(pkg_name)


        if not pkgs_changed:
            log.debug("All yum packages were already installed")
            return []

        if pkg_specs_to_upgrade:
            log.debug("Installing/updating %s via yum", pkg_specs_to_upgrade)

            result = LoggingProcessHelper(['yum', '-y', 'install'] + pkg_specs_to_upgrade).call()

            if result.returncode:
                log.error("Yum failed. Output: %s", result.stdout)
                raise ToolError("Could not successfully install/update yum packages", result.returncode)

        if pkg_specs_to_downgrade:
            log.debug("Downgrading %s via yum", pkg_specs_to_downgrade)

            result = LoggingProcessHelper(['yum', '-y', 'downgrade'] + pkg_specs_to_downgrade).call()

            if result.returncode:
                log.error("Yum failed. Output: %s", result.stdout)
                raise ToolError("Could not successfully downgrade yum packages", result.returncode)


        log.info("Yum installed %s", pkgs_changed)

        return pkgs_changed


    def _should_upgrade(self, requested_ver, installed_version):
        # If they haven't requested a version, always install
        if not requested_ver:
            return True
        #Now we need to detect whether or not we need to upgrade
        ver_cmp = RpmTool.compare_rpm_versions(requested_ver, installed_version)
        if ver_cmp > 0:
            log.debug("Requested version %s is greater than installed version %s, so we will upgrade", requested_ver, installed_version)
            return True
        else:
            log.debug("Requested version %s is NOT greater than installed version %s, so we will NOT upgrade", requested_ver, installed_version)
            return False

    def _pkg_installed(self, pkg):
        result = ProcessHelper(['yum', '-C', '-y', 'list', 'installed', pkg]).call()

        return result.returncode == 0

    def _pkg_available(self, pkg):
        # --showduplicates seems to be required to see downgradable versions when running yum non-interactively
        # but not when running interactively -- but we rarely run interactively
        result = ProcessHelper(['yum', '-C', '-y', '--showduplicates', 'list', 'available', pkg]).call()

        return result.returncode == 0

class RpmTool(object):

    def apply(self, action, auth_config=None):
        """
        Install a set of packages via RPM, returning the packages actually installed or updated.

        Arguments:
        action -- a dict of package name to version; version can be empty, a single string or a list of strings

        Exceptions:
        ToolError -- on expected failures (such as a non-zero exit code)
        """

        pkgs_changed = []

        if not action.keys():
            log.debug("No packages installed for RPM")
            return pkgs_changed

        pkgs = []

        for pkg_name, loc in action.iteritems():
            pkgs_to_process = ([loc] if isinstance(loc, basestring) else loc)
            pkgs_filtered = [pkg_key for pkg_key in pkgs_to_process if self._package_filter(pkg_key)]
            if pkgs_filtered:
                pkgs.extend(pkgs_filtered)
                pkgs_changed.append(pkg_name)


        if not pkgs:
            log.info("All RPMs were already installed")
            return []

        log.debug("Installing %s via RPM", pkgs)

        result = ProcessHelper(['rpm', '-U', '--quiet', '--nosignature', '--replacepkgs'] + pkgs).call()

        if result.returncode:
            log.error("RPM failed. Output: %s", result.stdout)
            raise ToolError("Could not successfully install rpm packages", result.returncode)
        else:
            log.debug("RPM output: %s", result.stdout)

        return pkgs_changed

    def _package_filter(self, pkg):
        if not pkg:
            log.warn("RPM specified with no location")
            return False

        if self._is_installed(pkg):
            log.debug("Skipping RPM at %s as it is already installed", pkg)
            return False

        return True

    @classmethod
    def get_package_version(cls, pkg, is_file=True):
        """
        Given the name of an installed package or package location, return a tuple of (name, version-release)
        of either the installed package or the specified package location

        Parameters:
            - pkg: the package name/location
            - is_file : if True, pkg refers to a package location; if False, the name of an installed package
        """

        query_mode = '-qp' if is_file else '-qa'

        log.debug("Querying for version of package %s", pkg)

        query_result = ProcessHelper(['rpm', query_mode, '--queryformat', '%{NAME}|%{VERSION}-%{RELEASE}', '--nosignature', pkg], stderr=subprocess.PIPE).call()

        log.debug("RPM stdout: %s", query_result.stdout)
        log.debug("RPM stderr: %s", query_result.stderr)

        if query_result.returncode:
            log.error("Could not determine package contained by rpm at %s", pkg)
            return (None, None)

        # The output from the command is just name|version-release
        name, sep, version = query_result.stdout.strip().partition('|')

        return (name, version)

    @classmethod
    def order_versions(cls, pkg_vers):
        return sorted(pkg_vers, cmp=cls.compare_rpm_versions)

    @classmethod
    def max_version(cls, versions):
        max_ver = None
        for ver in versions:
            if cls.compare_rpm_versions(max_ver, ver) < 0:
                max_ver = ver

        return max_ver

    @classmethod
    def compare_rpm_versions(cls, first_pkg, second_pkg):
        """
        Given two package versions in form VERSION-RELEASE, (-RELEASE optional), compare them
        based on "newness" (where "greater than" equals "newer")
        """

        # Partition the RPM version strings into (VERSION, RELEASE)
        first_fields = first_pkg.split('-', 1) if first_pkg else ()
        second_fields = second_pkg.split('-', 1) if second_pkg else ()

        # Compare VERSION and then RELEASE
        for i in range(2):
            # Build a list of wholly-alpha and wholly-numeric fields; treat non-alphanumeric sequences as separators
            first_chars = re.findall('[a-zA-Z]+|[0-9]+', first_fields[i]) if i < len(first_fields) else []
            second_chars = re.findall('[a-zA-Z]+|[0-9]+', second_fields[i]) if i < len(second_fields) else []

            # Compare position by position
            for j in range(min(len(first_chars), len(second_chars))):
                c1 = first_chars[j]
                c2 = second_chars[j]
                if c1.isdigit():
                    if c2.isdigit():
                        # If both fields are numeric, compare based on int values
                        int_cmp = cmp(int(c1), int(c2))
                        if int_cmp:
                            return int_cmp
                    else:
                        # If one is alpha and one is numeric, then numeric is "greater"
                        return 1
                elif c2.isdigit():
                    # If one is alpha and one is numeric, then numeric is "greater"
                    return -1
                else:
                    # If they're both strings, just compare lexicographically
                    str_cmp = cmp(c1, c2)
                    if str_cmp:
                        return str_cmp

            # If all of the intersecting fields match, the longer string is newer
            len_cmp = cmp(len(first_chars), len(second_chars))
            if len_cmp:
                return len_cmp

        # If both VERSION and RELEASE match for both RPMs, ignoring non-alphanumeric chars, they are equal
        return 0

    def _is_installed(self, pkg):
        pkg_with_version = RpmTool.get_package_version(pkg)

        if not pkg_with_version or not pkg_with_version[0]:
            # If there's an error retrieving the version, assume we have to install it (a failure there will be terminal)
            return True

        pkg_spec = '-'.join(pkg_with_version) if pkg_with_version[1] else pkg_with_version[0]

        # rpm -q will try to find the specific RPM in the local system
        # --quiet will reduce this command to just an exit code
        test_result = ProcessHelper(['rpm', '-q', '--quiet', pkg_spec]).call()

        # if rpm -q returns 0, that means the package exists
        return test_result.returncode == 0


