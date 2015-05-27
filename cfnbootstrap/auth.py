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
import urllib
import operator
from cfnbootstrap.packages.requests.auth import AuthBase, HTTPBasicAuth
import base64
import datetime
import hashlib
import hmac
import logging
import re
import urlparse
import util

log = logging.getLogger("cfn.init")

class S3Signer(object):

    def __init__(self, creds, region=None):
        self._creds = creds
        self._region = region
        self._nowfunction = datetime.datetime.utcnow

    def sign(self, req):
        # Requests only quotes illegal characters in a URL, leaving reserved chars.
        # We want to fully quote the URL, so we first unquote the url before requoting it in our signature calculation
        full_url = urllib.unquote(req.full_url if hasattr(req, 'full_url') else req.url)
        region = self._extract_region(full_url) if not self._region else self._region

        if not region:
            log.warn('Falling back to Signature Version 2 as no region was specified in S3 URL')
            return S3V2Signer(self._creds).sign(req)

        parsed = urlparse.urlparse(full_url)

        timestamp = self._nowfunction()
        timestamp_formatted = timestamp.strftime('%Y%m%dT%H%M%SZ')
        timestamp_short = timestamp.strftime('%Y%m%d')

        scope =  timestamp_short + '/' + region + '/s3/aws4_request'

        req.headers['x-amz-date'] = timestamp_formatted
        if self._creds.security_token:
            req.headers['x-amz-security-token'] = self._creds.security_token
        req.headers['host'] = parsed.netloc

        hashed_payload = hashlib.sha256(req.body if req.body is not None else '').hexdigest()
        req.headers['x-amz-content-sha256'] = hashed_payload

        canonical_request = req.method + '\n'
        canonical_request += self._canonicalize_uri(full_url) + '\n'
        canonical_request += self._canonicalize_query(urlparse.parse_qs(parsed.query, True)) + '\n'

        headers_to_sign = req.headers.copy()
        (canonical_headers, signed_headers) = self._canonicalize_headers(headers_to_sign)
        canonical_request += canonical_headers + '\n' + signed_headers + '\n'
        canonical_request += hashed_payload

        string_to_sign = 'AWS4-HMAC-SHA256\n' + timestamp_formatted + '\n' + scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        derived_key = hmac.new(("AWS4" + self._creds.secret_key).encode('utf-8'), timestamp_short.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, region.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, 's3'.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, "aws4_request".encode('utf-8'), hashlib.sha256).digest()

        signature = hmac.new(derived_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        credential = self._creds.access_key + '/' + scope
        req.headers['Authorization'] = 'AWS4-HMAC-SHA256 Credential=%s,SignedHeaders=%s,Signature=%s' % (credential, signed_headers, signature)

        return req

    def _extract_region(self, full_url):
        url = urlparse.urlparse(full_url)
        match = re.match(r'^(([-\w.]+?)\.)?s3[-.]([\w\d-]+).amazonaws.*$', url.netloc, re.IGNORECASE)
        if match:
            if match.group(3).startswith('external'):
                return 'us-east-1'
            return match.group(3)
        return None

    def _canonicalize_uri(self, uri):
        split = urlparse.urlsplit(uri)
        if not split.path:
            return '/'
        path = urlparse.urlsplit(urlparse.urljoin('http://foo.com', split.path.lstrip('/'))).path
        return urllib.quote(path, '/~') if path else '/'

    def _canonicalize_query(self, params):
        if not params:
            return ''
        encoded_pairs = []
        for entry in params.iteritems():
            for value in entry[1]:
                encoded_pairs.append((urllib.quote(entry[0], '~'), urllib.quote(value, '~') if value else ''))

        sorted_pairs = sorted(encoded_pairs, key=operator.itemgetter(0, 1))

        return '&'.join(('='.join(pair) for pair in sorted_pairs))

    def _canonicalize_headers(self, headers):
        canon_headers = {}
        for key, value in ((key.lower(), re.sub(r'(?su)[\s]+', ' ', value).strip()) for key, value in headers.iteritems()):
            if key in canon_headers:
                canon_headers[key] = canon_headers[key] + ',' + value
            else:
                canon_headers[key] = value

        sorted_entries = sorted(canon_headers.iteritems(), key=operator.itemgetter(0))

        return '\n'.join((':'.join(entry) for entry in sorted_entries)) + '\n', ';'.join((entry[0] for entry in sorted_entries))


class S3V2Signer(object):

    def __init__(self, creds):
        self._creds = creds

    def sign(self, req):
        if 'Date' not in req.headers:
            req.headers['X-Amz-Date'] = datetime.datetime.utcnow().replace(microsecond=0).strftime("%a, %d %b %Y %H:%M:%S GMT")

        if self._creds.security_token:
            req.headers['x-amz-security-token'] = self._creds.security_token

        stringToSign = req.method + '\n'
        stringToSign += req.headers.get('content-md5', '') + '\n'
        stringToSign += req.headers.get('content-type', '') + '\n'
        stringToSign += req.headers.get('date', '') + '\n'
        stringToSign += self._canonicalize_headers(req)
        stringToSign += self._canonicalize_resource(req)

        signed = base64.encodestring(hmac.new(self._creds.secret_key.encode('utf-8'), stringToSign.encode('utf-8'), hashlib.sha1).digest()).strip()

        req.headers['Authorization'] = 'AWS %s:%s' % (self._creds.access_key, signed)

        return req

    def _canonicalize_headers(self, req):
        headers = [(hdr.lower(), val) for hdr, val in req.headers.iteritems() if hdr.lower().startswith('x-amz')]
        return '\n'.join([hdr + ':' + val for hdr, val in sorted(headers)]) + '\n' if headers else ''

    def _canonicalize_resource(self, req):
        url = urlparse.urlparse(req.full_url if hasattr(req, 'full_url') else req.url)
        match = re.match(r'^([-\w.]+?)\.s3([-.][\w\d-]+)?.amazonaws.*', url.netloc, re.IGNORECASE)
        if match:
            return '/' + match.group(1) + url.path
        return url.path

class S3DefaultAuth(AuthBase):

    def __init__(self):
        self._bucketToAuth = {}

    def add_auth_for_bucket(self, bucket, auth_impl):
        self._bucketToAuth[bucket] = auth_impl

    def __call__(self, req):
        bucket = self._extract_bucket(req)
        if bucket and bucket in self._bucketToAuth:
            return self._bucketToAuth[bucket](req)
        return req

    def _extract_bucket(self, req):
        url = urlparse.urlparse(req.full_url if hasattr(req, 'full_url') else req.url)
        match = re.match(r'^([-\w.]+\.)?s3([-.][\w\d-]+)?.amazonaws.*$', url.netloc, re.IGNORECASE)
        if not match:
            # Not an S3 URL, skip
            return None
        elif match.group(1):
            # Subdomain-style S3 URL
            return match.group(1).rstrip('.')
        else:
            # This means that we're using path-style buckets
            # lop off the first / and return everything up to the next /
            return url.path[1:].partition('/')[0]


class S3RoleAuth(AuthBase):

    def __init__(self, roleName):
        self._roleName=roleName

    def __call__(self, req):
        return S3Signer(util.get_role_creds(self._roleName)).sign(req)

class S3Auth(AuthBase):

    def __init__(self, access_key, secret_key):
        self._signer = S3Signer(util.Credentials(access_key, secret_key))

    def __call__(self, req):
        return self._signer.sign(req)

class BasicDefaultAuth(AuthBase):

    def __init__(self):
        self._auths = {}

    def __call__(self, req):
        base_uri = urlparse.urlparse(req.full_url if hasattr(req, 'full_url') else req.url).netloc
        if base_uri in self._auths:
            return self._auths[base_uri](req)
        return req

    def add_password(self, uri, username, password):
        self._auths[uri] = HTTPBasicAuth(username, password)

class DefaultAuth(AuthBase):

    def __init__(self, s3, basic):
        self._s3 = s3
        self._basic = basic

    def __call__(self, req):
        return self._s3(self._basic(req))

class AuthenticationConfig(object):

    def __init__(self, model):

        self._auths = {}

        s3Auth = S3DefaultAuth()
        basicAuth = BasicDefaultAuth()

        for key, config in model.iteritems():
            configType = config.get('type', '')
            if 's3' == configType.lower():
                auth_impl = None
                if 'accessKeyId' in config and 'secretKey' in config:
                    auth_impl = S3Auth(config['accessKeyId'], config['secretKey'])
                elif 'roleName' in config:
                    auth_impl = S3RoleAuth(config['roleName'])
                else:
                    log.warn('S3 auth requires either "accessKeyId" and "secretKey" or "roleName"')
                    continue

                self._auths[key] = auth_impl

                if 'buckets' in config:
                    buckets = [config['buckets']] if isinstance(config['buckets'], basestring) else config['buckets']
                    for bucket in buckets:
                        s3Auth.add_auth_for_bucket(bucket, auth_impl)

            elif 'basic' == configType.lower():
                self._auths[key] = HTTPBasicAuth(config.get('username'), config.get('password'))
                if 'uris' in config:
                    if isinstance(config['uris'], basestring):
                        basicAuth.add_password(config['uris'], config.get('username'), config.get('password'))
                    else:
                        for u in config['uris']:
                            basicAuth.add_password(u, config.get('username'), config.get('password'))
            else:
                log.warn("Unrecognized authentication type: %s", configType)

        self._defaultAuth = DefaultAuth(s3Auth, basicAuth)

    def get_auth(self, key):
        if not key or not key in self._auths:
            return self._defaultAuth

        return self._auths[key]
