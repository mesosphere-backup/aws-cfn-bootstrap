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
from cfnbootstrap.util import retry_on_failure
from tarfile import TarError
from zipfile import BadZipfile
import logging
import os.path
import re
import requests
import shutil
import tarfile
import tempfile
import zipfile

log = logging.getLogger("cfn.init")

class SourcesTool(object):
    """
    Explodes sources (archives) into locations on disk

    """

    _remote_pattern = re.compile(r'^(https?|ftp)://.*$', re.I)
    _github_pattern = re.compile(r'^https?://github.com/.*?/(zipball|tarball)/.*$')

    def apply(self, action, auth_config):
        """
        Extract archives to their corresponding destination directories, returning directories which were updated.

        Arguments:
        action -- a dict of directory to archive location, which can be either a path or URL
        auth_config -- an AuthenticationConfig object for managing authenticated downloads

        Exceptions:
        ToolError -- on expected failures
        """

        dirs_changed = []

        if not action:
            log.debug("No sources specified")
            return dirs_changed

        for (path, archive) in sorted(action.iteritems(), key=lambda pair: pair[0]):

            if SourcesTool._remote_pattern.match(archive):
                try:
                    archive_file = self._archive_from_url(archive, auth_config)
                except IOError, e:
                    raise ToolError("Failed to retrieve %s: %s" % (archive, e.strerror))
            else:
                if not os.path.isfile(archive):
                    raise ToolError("%s does not exist" % archive)
                archive_file = file(archive, 'rb')

            if TarWrapper.is_compatible(archive_file):
                log.debug("Treating %s as a tarball", archive)
                archive_wrapper = TarWrapper(archive_file)
            elif ZipWrapper.is_compatible(archive_file):
                log.debug("Treating %s as a zip archive", archive)
                archive_wrapper = ZipWrapper(archive_file)
            else:
                raise ToolError("Unsupported source file (not zip or tarball): %s" % archive)

            log.debug("Checking to ensure that all archive members fall under path %s" % path)
            self._check_all_members_in_path(path, archive_wrapper)

            if SourcesTool._github_pattern.match(archive.lower()):
                log.debug("Attempting to magically strip GitHub parent directory from archive")
                archive_wrapper=self._perform_github_magic(archive_wrapper);

            log.debug("Expanding %s into %s", archive, path)
            archive_wrapper.extract_all(path)
            dirs_changed.append(path)

        return dirs_changed

    def _perform_github_magic(self, archive):
        """
        The tarballs that GitHub autogenerates via their HTTP API put the contents
        of the tree into a top-level directory that has no value or predictability.
        This essentially "strips" that top level directory -- unfortunately, python has no
        equivalent of tar's --strip-components.  So we unarchive it and then rearchive
        a subtree.
        """
        tempdir = tempfile.mkdtemp()
        try:
            archive.extract_all(tempdir)
            tempmembers = os.listdir(tempdir)
            if len(tempmembers) != 1:
                log.debug("GitHub magic is not possible; archive does not contain exactly one directory")
                return archive
            else:
                temparchive = tempfile.TemporaryFile()
                tf = tarfile.TarFile(fileobj=temparchive, mode='w')
                parent = os.path.join(tempdir, tempmembers[0])
                log.debug("Creating temporary tar from %s", parent)
                for member in os.listdir(parent):
                    tf.add(os.path.join(parent, member), arcname=member)
                tf.close()
                temparchive.seek(0, 0)
                return TarWrapper(temparchive)
        finally:
            shutil.rmtree(tempdir, True)

    def _check_all_members_in_path(self, path, archive):
        """
        This does a best-effort test to make sure absolute paths
        or ../../../../ nonsense in archives makes files "escape"
        their destination
        """

        normalized_parent = os.path.normcase(os.path.abspath(path))
        for member in archive.files():
            if os.path.isabs(member):
                prefix = os.path.commonprefix([os.path.normcase(os.path.normpath(member)), normalized_parent])
            else:
                prefix = os.path.commonprefix([os.path.normcase(os.path.normpath(os.path.join(normalized_parent, member))), normalized_parent])

            if prefix != normalized_parent:
                raise ToolError("%s is not a sub-path of %s" % (member, path))

    @retry_on_failure()
    def _archive_from_url(self, archive, auth_config):
        tf = tempfile.TemporaryFile()
        opts = util.req_opts({'auth': auth_config.get_auth(None)})
        util.EtagCheckedResponse(requests.get(archive, **opts)).write_to(tf)
        tf.flush()
        tf.seek(0, os.SEEK_SET)
        return tf

class ZipWrapper(object):

    def __init__(self, f):
        self.file = zipfile.ZipFile(f, mode='r')

    @classmethod
    def is_compatible(cls, f):
        try:
            z = zipfile.ZipFile(f, mode='r')
            z.close()
            f.seek(0, 0)
            return True
        except BadZipfile:
            return False

    def files(self):
        return (info.filename for info in self.file.infolist())

    def extract_all(self, dest):
        self.file.extractall(dest)

class TarWrapper(object):

    def __init__(self, f):
        self.file = tarfile.open(fileobj = f, mode='r:*')

    @classmethod
    def is_compatible(cls, f):
        try:
            t = tarfile.open(fileobj = f, mode='r:*')
            t.close()
            f.seek(0, 0)
            return True
        except TarError:
            return False

    def files(self):
        return self.file.getnames()

    def extract_all(self, dest):
        self.file.extractall(dest)
