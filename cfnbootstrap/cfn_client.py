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
CloudFormation client-related classes

Classes:
CloudFormationClient - an HTTP client that makes API calls against CloudFormation
StackResourceDetail  - detailed information about a StackResource

"""
from cfnbootstrap import aws_client, util
from cfnbootstrap.aws_client import CFNSigner, V4Signer
from cfnbootstrap.util import retry_on_failure, timeout
import datetime
import logging
import re
from util import Credentials

try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger("cfn.client")

class CloudFormationClient(aws_client.Client):
    """
    Makes API calls against CloudFormation

    Notes:
    - Public methods of this class have a 1-to-1 equivalence to published CloudFormation APIs.
    - Calls are retried internally when appropriate; callers should not retry.

    Attributes:
    _apiVersion - the CloudFormation API version
    _endpoints  - CloudFormation service endpoints differing from the https://cloudformation.<region>.amazonaws.com format

    """

    _apiVersion = "2010-05-15"
    _endpoints = { "cn-north-1": "https://cloudformation.cn-north-1.amazonaws.com.cn" }

    def __init__(self, credentials, url=None, region='us-east-1', proxyinfo=None):

        if not url:
            endpoint = CloudFormationClient.endpointForRegion(region)
        else:
            endpoint = url

        self.using_instance_identity = (not credentials or not credentials.access_key) and util.is_ec2()

        if not self.using_instance_identity and (not credentials or not credentials.access_key or not credentials.secret_key):
            raise ValueError('In order to sign requests, 169.254.169.254 must be accessible or valid credentials must '
                             'be set. Please ensure your proxy environment variables allow access to 169.254.169.254 '
                             '(NO_PROXY) or that your credentials have a valid access key and secret key.')

        if not self.using_instance_identity:
            if not region:
                region = CloudFormationClient.regionForEndpoint(endpoint)

            if not region:
                raise ValueError('Region is required for AWS V4 Signatures')

        signer = CFNSigner() if self.using_instance_identity else V4Signer(region, 'cloudformation')

        super(CloudFormationClient, self).__init__(credentials, True, endpoint, signer, proxyinfo=proxyinfo)

        log.debug("CloudFormation client initialized with endpoint %s", endpoint)

    @classmethod
    def endpointForRegion(cls, region):
        if region in CloudFormationClient._endpoints:
            return CloudFormationClient._endpoints[region]
        return 'https://cloudformation.%s.amazonaws.com' % region

    @classmethod
    def regionForEndpoint(cls, endpoint):
        match = re.match(r'https://cloudformation.([\w\d-]+).amazonaws.com', endpoint)
        if match:
            return match.group(1)
        log.warn("Non-standard CloudFormation endpoint: %s", endpoint)
        return None

    @retry_on_failure(http_error_extractor=aws_client.Client._extract_json_message)
    @timeout()
    def describe_stack_resource(self, logicalResourceId, stackName, request_credentials=None):
        """
        Calls DescribeStackResource and returns a StackResourceDetail object.

        Throws an IOError on failure.
        """
        log.debug("Describing resource %s in stack %s", logicalResourceId, stackName)

        return StackResourceDetail(self._call({"Action" : "DescribeStackResource",
                                               "LogicalResourceId" : logicalResourceId,
                                               "ContentType" : "JSON",
                                               "StackName": stackName,
                                               "Version": CloudFormationClient._apiVersion },
                                               request_credentials=request_credentials))

    @retry_on_failure(http_error_extractor=aws_client.Client._extract_json_message)
    @timeout()
    def signal_resource(self, logicalResourceId, stackName, uniqueId, status="SUCCESS", request_credentials=None):
        """
        Calls SignalResource.

        Throws an IOError on failure.
        """
        log.debug("Signaling resource %s in stack %s with unique ID %s and status %s", logicalResourceId,
                                                                                       stackName,
                                                                                       uniqueId,
                                                                                       status)
        self._call({"Action": "SignalResource",
                    "LogicalResourceId": logicalResourceId,
                    "StackName": stackName,
                    "UniqueId": uniqueId,
                    "Status": status,
                    "ContentType": "JSON",
                    "Version": CloudFormationClient._apiVersion },
                    request_credentials=request_credentials)

    @retry_on_failure(http_error_extractor=aws_client.Client._extract_json_message)
    @timeout()
    def register_listener(self, stack_name, listener_id=None, request_credentials=None):
        """
        Calls RegisterListener and returns a Listener object

        Throws an IOError on failure.
        """
        log.debug("Registering listener %s for stack %s", listener_id, stack_name)

        params = {"Action" : "RegisterListener",
                  "StackName" : stack_name,
                  "ContentType" : "JSON"}

        if not self.using_instance_identity:
            params["ListenerId"] = listener_id

        return Listener(self._call(params, request_credentials = request_credentials))

    @retry_on_failure(http_error_extractor=aws_client.Client._extract_json_message)
    @timeout()
    def elect_command_leader(self, stack_name, command_name, invocation_id, listener_id=None, request_credentials=None):
        """
        Calls ElectCommandLeader and returns the listener id of the leader

        Throws an IOError on failure.
        """
        log.debug("Attempting to elect '%s' as leader for stack: %s, command: %s, invocation: %s",
                  listener_id, stack_name, command_name, invocation_id)

        params = {"Action" : "ElectCommandLeader",
                  "CommandName" : command_name,
                  "InvocationId" : invocation_id,
                  "StackName" : stack_name,
                  "ContentType" : "JSON"}

        if not self.using_instance_identity:
            params["ListenerId"] = listener_id

        result_data = self._call(params, request_credentials = request_credentials).json()

        return result_data['ElectCommandLeaderResponse']['ElectCommandLeaderResult']['ListenerId']

    @retry_on_failure(http_error_extractor=aws_client.Client._extract_json_message)
    @timeout()
    def get_listener_credentials(self, stack_name, listener_id=None, request_credentials=None):
        """
        Calls GetListenerCredentials and returns a Credentials object

        Throws an IOError on failure.
        """
        log.debug("Get listener credentials for listener %s in stack %s", listener_id, stack_name)

        params = {"Action" : "GetListenerCredentials",
                  "StackName" : stack_name,
                  "ContentType" : "JSON"}

        if not self.using_instance_identity:
            params["ListenerId"] = listener_id

        resp = self._call(params, request_credentials = request_credentials)
        body = resp.json()['GetListenerCredentialsResponse']['GetListenerCredentialsResult']['Credentials']
        return Credentials(body['AccessKeyId'],
            body['SecretAccessKey'],
            body['SessionToken'],
            datetime.datetime.utcfromtimestamp(body['Expiration']))


class Listener(object):
    """Result of RegisterListener"""

    def __init__(self, resp):
        result = resp.json()['RegisterListenerResponse']['RegisterListenerResult']
        self._queue_url = result['QueueUrl']

    @property
    def queue_url(self):
        return self._queue_url

class StackResourceDetail(object):
    """Detailed information about a stack resource"""

    def __init__(self, resp):
        detail = resp.json()['DescribeStackResourceResponse']['DescribeStackResourceResult']['StackResourceDetail']

        self._description = detail.get('Description')
        self._lastUpdated = datetime.datetime.utcfromtimestamp(detail['LastUpdatedTimestamp'])
        self._logicalResourceId = detail['LogicalResourceId']

        _rawMetadata = detail.get('Metadata')
        self._metadata = json.loads(_rawMetadata) if _rawMetadata else None

        self._physicalResourceId = detail.get('PhysicalResourceId')
        self._resourceType = detail['ResourceType']
        self._resourceStatus = detail['ResourceStatus']
        self._resourceStatusReason = detail.get('ResourceStatusReason')
        self._stackId = detail.get('StackId')
        self._stackName = detail.get('StackName')

    @property
    def logicalResourceId(self):
        """The resource's logical resource ID"""
        return self._logicalResourceId

    @property
    def description(self):
        """The resource's description"""
        return self._description

    @property
    def lastUpdated(self):
        """The timestamp of this resource's last status change as a datetime object"""
        return self._lastUpdated

    @property
    def metadata(self):
        """The resource's metadata as python object (not as a JSON string)"""
        return self._metadata

    @property
    def physicalResourceId(self):
        """The resource's physical resource ID"""
        return self._physicalResourceId

    @property
    def resourceType(self):
        """The resource's type"""
        return self._resourceType

    @property
    def resourceStatus(self):
        """The resource's status"""
        return self._resourceStatus

    @property
    def resourceStatusReason(self):
        """The reason for this resource's status"""
        return self._resourceStatusReason

    @property
    def stackId(self):
        """The ID of the stack this resource belongs to"""
        return self._stackId

    @property
    def stackName(self):
        """The name of the stack this resource belongs to"""
        return self._stackName
