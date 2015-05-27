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
SQS client-related classes

Classes:
SQSClient - an HTTP client that makes API calls against SQS
Message  - a message from an SQS queue

"""
from cfnbootstrap import aws_client
from cfnbootstrap.aws_client import V4Signer
from cfnbootstrap.util import retry_on_failure, timeout
from xml.etree import ElementTree
import StringIO
import logging
import re

log = logging.getLogger("cfn.client")

class SQSClient(aws_client.Client):
    """
    Makes API calls against SQS

    Notes:
    - Public methods of this class have a 1-to-1 equivalence to published SQS APIs.
    - Calls are retried internally when appropriate; callers should not retry.

    Attributes:
    _apiVersion - the SQS API version
    _xmlns      - the XML namespace for the SQS API version in use
    _endpoints  - SQS service endpoints differing from the https://<region>.queue.amazonaws.com format

    """

    _apiVersion = "2012-11-05"
    _xmlns='http://queue.amazonaws.com/doc/%s/' % _apiVersion
    _endpoints = { 'us-east-1': 'https://queue.amazonaws.com',
                   'cn-north-1': 'https://cn-north-1.queue.amazonaws.com.cn' }

    def __init__(self, credentials, url=None, region='us-east-1', proxyinfo=None):
        if not url:
            endpoint = SQSClient.endpointForRegion(region)
        else:
            endpoint = self._fix_endpoint(url)

        if not region:
            region = SQSClient.regionForEndpoint(endpoint)

        if not region:
            raise ValueError('Region is required for AWS V4 Signatures')

        signer = V4Signer(region, 'sqs')

        super(SQSClient, self).__init__(credentials, False, endpoint, signer=signer, xmlns='http://queue.amazonaws.com/doc/%s/' % SQSClient._apiVersion, proxyinfo=proxyinfo)
        log.debug("SQS client initialized with endpoint %s", endpoint)

    # SQS SSL certificates have CNs based on queue.amazonaws.com
    # Python2.6 will fail to verify the hostname of the certificate
    # Due to http://bugs.python.org/issue13034 only being fixed in 2.7 and 3.2
    def _fix_endpoint(self, url):
        m = re.match(r'^https://sqs\.(.*?)\.amazonaws\.com(.*)$', url)
        if m:
            if m.group(1) == 'us-east-1':
                return 'https://queue.amazonaws.com%s' % m.group(2)
            return 'https://%s.queue.amazonaws.com%s' % m.group(1, 2)
        return url

    @classmethod
    def endpointForRegion(cls, region):
        if region in SQSClient._endpoints:
            return SQSClient._endpoints[region]
        return 'https://%s.queue.amazonaws.com' % region

    @classmethod
    def regionForEndpoint(cls, endpoint):
        match = re.match(r'https://([\w\d-]+).queue.amazonaws.com', endpoint)
        if match:
            return match.group(1)
        inverse_endpoints = dict((v,k) for k, v in SQSClient._endpoints.iteritems())
        if endpoint in inverse_endpoints:
            return inverse_endpoints[endpoint]
        log.warn("Non-standard SQS endpoint: %s", endpoint)
        return None

    @retry_on_failure(http_error_extractor=aws_client.Client._get_xml_extractor(_xmlns))
    @timeout(60)
    def receive_message(self, queue_url, attributes=None, max_messages=1, visibility_timeout=None,
                              request_credentials=None, wait_time=None):
        """
        Calls ReceiveMessage and returns a list of Message objects

        Throws an IOError on failure.
        """
        if not attributes: attributes = ['All']
        queue_url = self._fix_endpoint(queue_url)
        log.debug("Receiving messages for queue %s", queue_url)

        params = { "Action" : "ReceiveMessage", "Version" : SQSClient._apiVersion, "MaxNumberOfMessages" : str(max_messages) }
        for i in range(len(attributes)):
            params['AttributeName.%s' % (i + 1)]=attributes[i]
        if visibility_timeout:
            params['VisibilityTimeout'] = str(visibility_timeout)
        if wait_time:
            params['WaitTimeSeconds'] = str(wait_time)

        response_content = self._call(params, queue_url, request_credentials,
                                      timeout=wait_time + 3 if wait_time else None).content
        return Message._parse_list(StringIO.StringIO(response_content), self._xmlns)

    @retry_on_failure(max_tries=25, http_error_extractor=aws_client.Client._get_xml_extractor(_xmlns))
    @timeout()
    def send_message(self, queue_url, message_body, delay_seconds=None, request_credentials=None):
        """
        Calls SendMessage and returns a tuple of (MessageId, MD5OfMessageBody)

        Throws an IOError on failure.
        """
        queue_url = self._fix_endpoint(queue_url)
        log.debug("Sending %s to queue %s", message_body, queue_url)

        params = { "Action" : "SendMessage", "Version" : SQSClient._apiVersion, "MessageBody" : message_body}

        if delay_seconds:
            params["DelaySeconds"] = delay_seconds

        root = ElementTree.ElementTree(file=StringIO.StringIO(self._call(params, queue_url, request_credentials, verb='POST').content))
        message_id = root.findtext('{%s}SendMessageResult/{%s}MessageId' % (self._xmlns, self._xmlns))
        md5_of_body = root.findtext('{%s}SendMessageResult/{%s}MD5OfMessageBody' % (self._xmlns, self._xmlns))

        return (message_id, md5_of_body)

    @retry_on_failure(http_error_extractor=aws_client.Client._get_xml_extractor(_xmlns))
    @timeout()
    def delete_message(self, queue_url, receipt_handle, request_credentials=None):
        """
        Calls DeleteMessage on a specified receipt handle

        Throws an IOError on failure.
        """
        queue_url = self._fix_endpoint(queue_url)
        log.debug("Deleting %s from queue %s", receipt_handle, queue_url)

        params = { "Action" : "DeleteMessage", "Version" : SQSClient._apiVersion, "ReceiptHandle" : receipt_handle}

        self._call(params, queue_url, request_credentials)

class Message(object):
    """A message off of an SQS queue"""

    @classmethod
    def _parse_list(cls, data, xmlns):
        if not data:
            return []
        root = ElementTree.ElementTree(file=data)
        msgs = root.findall('{%s}ReceiveMessageResult/{%s}Message' % (xmlns, xmlns))
        return [cls._from_elem(elem, xmlns) for elem in msgs]

    @classmethod
    def _from_elem(cls, elem, xmlns):
        attribs = {}
        for attrib in elem.findall('{%s}Attribute' % xmlns):
            attribs[attrib.findtext('{%s}Name' % xmlns)] = attrib.findtext('{%s}Value' % xmlns)

        return Message(elem.findtext('{%s}MessageId' % xmlns),
                       elem.findtext('{%s}ReceiptHandle' % xmlns),
                       elem.findtext('{%s}MD5OfBody' % xmlns),
                       elem.findtext('{%s}Body' % xmlns),
                       attribs)

    def __init__(self, msg_id, handle, md5, body, attribs):
        self._message_id = msg_id
        self._receipt_handle = handle
        self._md5_of_body = md5
        self._body = body
        self._attributes = dict(attribs)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return 'Message[MessageId:%s, ReceiptHandle:%s, MD5OfBody:%s, Body:%s, Attributes:%s]' % (self.message_id,
                                                                                                  self.receipt_handle,
                                                                                                  self.md5_of_body,
                                                                                                  self.body,
                                                                                                  self.attributes)

    @property
    def message_id(self):
        return self._message_id

    @property
    def receipt_handle(self):
        return self._receipt_handle

    @property
    def md5_of_body(self):
        return self._md5_of_body

    @property
    def body(self):
        return self._body

    @property
    def attributes(self):
        return self._attributes
