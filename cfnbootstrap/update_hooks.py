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
import threading
from cfnbootstrap import util
from cfnbootstrap.cfn_client import CloudFormationClient
from cfnbootstrap.sqs_client import SQSClient
from cfnbootstrap.util import ProcessHelper
from threading import Timer
import ConfigParser
import calendar
import contextlib
import datetime
import logging
import os
import random
import shelve
import socket
import subprocess
import tempfile
import time
from util import Credentials

try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger("cfn.hup")

def parse_config(config_path):
    main_conf_path = os.path.join(config_path, 'cfn-hup.conf')
    if not os.path.isfile(main_conf_path):
        raise ValueError("Could not find main configuration at %s" % main_conf_path)

    main_config = ConfigParser.SafeConfigParser()
    main_config.read(main_conf_path)

    if not main_config.has_option('main', 'stack'):
        raise ValueError("[main] section must contain stack option")

    stack = main_config.get('main', 'stack')

    if main_config.has_option('main', 'role'):
        credentials = util.RoleBasedCredentials(main_config.get('main', 'role'))
    elif main_config.has_option('main', 'credential-file'):
        try:
            credentials = util.extract_credentials(main_config.get('main', 'credential-file'))
        except IOError, e:
            raise ValueError("Could not retrieve credentials from file:\n\t%s" % e.strerror)
    else:
        credentials = Credentials('', '')

    additional_hooks_path = os.path.join(config_path, 'hooks.d')
    additional_files = []
    if os.path.isdir(additional_hooks_path):
        for hook_file in os.listdir(additional_hooks_path):
            if os.path.isfile(os.path.join(additional_hooks_path, hook_file)):
                additional_files.append(os.path.join(additional_hooks_path, hook_file))

    hooks_config = ConfigParser.SafeConfigParser()
    files_read = hooks_config.read([os.path.join(config_path, 'hooks.conf')] + additional_files)

    if not files_read:
        raise ValueError("No hook configurations found at %s or %s.", os.path.join(config_path, 'hooks.conf'), additional_hooks_path)

    hooks = []
    cmd_hooks = []

    for section in hooks_config.sections():
        if not hooks_config.has_option(section, 'triggers'):
            logging.error("No triggers specified for hook %s", section)
            continue

        triggers = [s.strip() for s in hooks_config.get(section, 'triggers').split(',')]

        if not hooks_config.has_option(section, 'path'):
            logging.error("No path specified for hook %s", section)
            continue

        if not hooks_config.has_option(section, 'action'):
            logging.error("No action specified for hook %s", section)
            continue

        runas = None
        if hooks_config.has_option(section, 'runas'):
            runas = hooks_config.get(section, 'runas').strip()

        hook = Hook(section,
                    triggers,
                    hooks_config.get(section, 'path').strip(),
                    hooks_config.get(section, 'action'),
                    runas)
        if hook.is_cmd_hook():
            if hooks_config.has_option(section, 'singleton'):
                hook.singleton = util.interpret_boolean(hooks_config.get(section, 'singleton'))
            if hooks_config.has_option(section, 'send_result'):
                hook.send_result = util.interpret_boolean(hooks_config.get(section, 'send_result'))
            cmd_hooks.append(hook)
        else:
            hooks.append(hook)

    if not hooks and not cmd_hooks:
        raise ValueError("No valid hooks found")

    region = 'us-east-1'
    if main_config.has_option('main', 'region'):
        region = main_config.get('main', 'region')

    cfn_url = CloudFormationClient.endpointForRegion(region)

    if main_config.has_option('main', 'url'):
        cfn_url = main_config.get('main', 'url')

    cfn_client = CloudFormationClient(credentials, cfn_url, region)

    if main_config.has_option('main', 'multi-threaded'):
        value = main_config.get('main', 'multi-threaded')
        multi_threaded = util.interpret_boolean(value)
    else:
        multi_threaded = True

    if hooks:
        processor = HookProcessor(hooks, stack, cfn_client)
    else:
        processor = None

    if cmd_hooks:
        sqs_url = SQSClient.endpointForRegion(region)
        if main_config.has_option('main', 'sqs_url'):
            sqs_url = main_config.get('main', 'sqs_url')

        sqs_client = SQSClient(credentials, sqs_url, region=region)

        cmd_processor = CmdProcessor(stack, cmd_hooks, sqs_client,
                                     CloudFormationClient(credentials, cfn_url, region),
                                     multi_threaded)
    else:
        cmd_processor = None

    return (main_config, processor, cmd_processor)

class FatalUpdateError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class InFlightStatusError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class Hook(object):

    def __init__(self, name, triggers, path, action, runas):
        self._triggers = triggers[:]
        self._path = path
        self._action = action
        self._name = name
        self._runas = runas
        self.singleton = False
        self.send_result = True

    @property
    def triggers(self):
        return self._triggers

    @property
    def path(self):
        return self._path

    @property
    def action(self):
        return self._action

    @property
    def name(self):
        return self._name

    @property
    def runas(self):
        return self._runas

    def is_cmd_hook(self):
        return self._triggers == ['on.command']

class AutoRefreshingCredentialsProvider(object):

    def __init__(self, cfn_client, stack_name, listener_id):
        self._cfn_client = cfn_client
        self._stack_name = stack_name
        self._listener_id = listener_id
        self._creds = None
        self._last_timer = None
        self.listener_expired = False
        self._refresh_lock = threading.Lock()

    def refresh(self):
        with self._refresh_lock:
            log.info("Refreshing listener credentials")
            if self._last_timer:
                self._last_timer.cancel()

            try:
                self._creds = self._cfn_client.get_listener_credentials(self._stack_name, self._listener_id)
                self.listener_expired = False
            except IOError, e:
                if hasattr(e, 'error_code') and 'ListenerExpired' == e.error_code:
                    self.listener_expired = True
                    log.exception("Listener expired")
                else:
                    self.listener_expired = False
                    log.exception("IOError caught while refreshing credentials")
            except Exception:
                self.listener_expired = False
                log.exception("Exception refreshing credentials")

            now = time.time()
            expiration = calendar.timegm(self._creds.expiration.utctimetuple()) if self._creds else now
            remaining = expiration - now

            if remaining > 30 * 60:
                next_refresh = min(2 * 60 * 60, remaining / 2)
            else:
                next_refresh = 60 * random.random()

            log.info("Scheduling next credential refresh in %s seconds", next_refresh)
            t = Timer(next_refresh, self.refresh)
            t.daemon = True
            t.start()
            self._last_timer = t

    def creds_expired(self):
        return self._creds and self._creds.expiration < datetime.datetime.utcnow()

    @property
    def credentials(self):
        for i in range(3):
            if self._creds:
                break
            self.refresh()

        if not self._creds:
            raise ValueError('Could not retrieve listener credentials')

        return self._creds

class CmdProcessor(object):
    """Processes CommandService hooks"""

    def __init__(self, stack_name, hooks, sqs_client, cfn_client, multi_threaded):
        """Takes a list of Hook objects and processes them"""
        self.stack_name = stack_name
        self.hooks = self._hooks_by_path(hooks)
        self.sqs_client = sqs_client
        self.cfn_client = cfn_client
        self.multi_threaded = multi_threaded
        if not self.multi_threaded:
            log.debug("Enabled single threading mode.");

        if util.is_ec2():
            self.listener_id = util.get_instance_id()
        elif not cfn_client.using_instance_identity:
            self.listener_id = socket.getfqdn()
        else:
            raise ValueError("Could not retrieve instance id")

        self._creds_provider = AutoRefreshingCredentialsProvider(self.cfn_client, self.stack_name, self.listener_id)
        self.queue_url = None

        self._create_storage_dir()
        self._runfile = os.path.join(self.storage_dir, 'commands_run.json')

        self._commands_run = self._load_commands_run()

        if not 'by_id' in self._commands_run:
            self._commands_run['by_id'] = {}

        if not 'by_day' in self._commands_run:
            self._commands_run['by_day'] = {}

        self._currently_running = set()

        self._currently_running_lock = threading.RLock()
        self._commands_run_lock = threading.RLock()

    def _load_commands_run(self):
        if os.path.isfile(self._runfile):
            with file(self._runfile, 'r') as f:
                try:
                    return json.load(f)
                except Exception:
                    log.exception("Could not load previously run commands")
                    os.remove(self._runfile)
                    return {}
        else:
            return {}


    def is_registered(self):
        return self.queue_url is not None and not self._creds_provider.listener_expired

    def creds_expired(self):
        return self._creds_provider.creds_expired()

    def register(self):
        self.queue_url = self.cfn_client.register_listener(self.stack_name, self.listener_id).queue_url
        self._creds_provider.listener_expired = False

    def _create_storage_dir(self):
        if os.name == 'nt':
            self.storage_dir = os.path.expandvars(r'${SystemDrive}\cfn\cfn-hup\data')
        else:
            self.storage_dir = '/var/lib/cfn-hup/data'
        if not os.path.isdir(self.storage_dir):
            log.debug("Creating %s", self.storage_dir)
            try:
                os.makedirs(self.storage_dir)
            except OSError:
                log.warn("Could not create %s; using temporary directory", self.storage_dir)
                self.storage_dir = tempfile.mkdtemp()

    def _command_completed(self, msg):
        now = datetime.datetime.utcnow()
        cmd_time = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        with self._commands_run_lock:
            self._commands_run['by_id'][self._get_id(msg)] = True

            if cmd_time not in self._commands_run['by_day']:
                self._commands_run['by_day'][cmd_time] = []

            self._commands_run['by_day'][cmd_time].append(self._get_id(msg))

            try:
                keys_to_delete = []
                for key in self._commands_run['by_day'].iterkeys():
                    if now - datetime.datetime.strptime(key, '%Y-%m-%dT%H:%M:%S') > datetime.timedelta(days=2):
                        for cmd_id in self._commands_run['by_day'][key]:
                            del self._commands_run['by_id'][cmd_id]

                        keys_to_delete.append(key)

                for key in keys_to_delete:
                    del self._commands_run['by_day'][key]

                self._write_commands_run()
            except Exception:
                log.exception('Could not write runfile to %s', self._runfile)

    def _write_commands_run(self):
        with file(self._runfile, 'w') as f:
            json.dump(self._commands_run, f)


    def _delete_message(self, receipt_handle):
        try:
            self.sqs_client.delete_message(self.queue_url, receipt_handle, request_credentials = self._creds_provider.credentials)
        except Exception:
            log.exception("Could not delete message for handle %s", receipt_handle)

    def _get_id(self, msg):
        return msg['DispatcherId'] + '|' + msg['CommandName'] + '|' + msg['InvocationId']

    def _already_run(self, msg):
        with self._commands_run_lock:
            return self._get_id(msg) in self._commands_run['by_id']

    def _parse(self, msg):
        try:
            return json.loads(json.loads(msg.body)['Message'])
        except Exception:
            log.exception("Received invalid message")
            return None

    def process(self):
        if self.queue_url is None:
            raise FatalUpdateError("Cannot process command hooks before registering")

        threads  = []

        try:
            for msg in self.sqs_client.receive_message(self.queue_url, request_credentials = self._creds_provider.credentials, wait_time=20):
                cmd_msg = self._parse(msg)
                if not cmd_msg:
                    log.info("Invalid message, deleting: %s", msg)
                    self._delete_message(msg.receipt_handle)
                    continue

                if self._already_run(cmd_msg):
                    log.info("Already ran %s, deleting", self._get_id(cmd_msg))
                    self._delete_message(msg.receipt_handle)
                    continue

                with self._currently_running_lock:
                    if self._get_id(cmd_msg) not in self._currently_running and not self._already_run(cmd_msg):
                        self._currently_running.add(self._get_id(cmd_msg))

                        if self.multi_threaded:
                            thread = threading.Thread(target=self._process_msg, args=(cmd_msg, msg.receipt_handle))
                            thread.daemon = True
                            threads.append(thread)
                            thread.start()
                        else:
                            self._process_msg(cmd_msg, msg.receipt_handle)

        except FatalUpdateError:
            raise
        except IOError, e:
            if hasattr(e, 'error_code') and 'AWS.SimpleQueueService.NonExistentQueue' == e.error_code:
                self.queue_url = None
            log.exception("IOError caught while processing messages")
        except Exception:
            log.exception("Exception caught while processing messages")

        return threads

    def _process_msg(self, cmd_msg, receipt_handle):
        log.debug("Processing message: %s", cmd_msg)
        delete = False

        try:
            log.debug("Command message: %s", cmd_msg)

            expiration = datetime.datetime.utcfromtimestamp(int(cmd_msg['Expiration']) / 1000)

            if expiration < datetime.datetime.utcnow():
                log.info("Invocation %s of command %s for stack %s expired at %s; skipping",
                            cmd_msg['InvocationId'], cmd_msg['CommandName'], cmd_msg['DispatcherId'],
                            expiration.isoformat())
                delete = True
            else:
                log.info("Received command %s (invocation id: %s)", cmd_msg['CommandName'], cmd_msg['InvocationId'])
                hook_to_run = self.hooks.get(cmd_msg['CommandName'])
                if not hook_to_run or self._run_hook(hook_to_run, cmd_msg):
                    self._command_completed(cmd_msg)
                    delete = True
        except (ValueError, KeyError):
            log.exception("Invalid message received; deleting it")
            delete = True
        except Exception:
            log.exception("Unexpected exception running command")
        finally:
            if delete:
                self._delete_message(receipt_handle)
            with self._currently_running_lock:
                self._currently_running.remove(self._get_id(cmd_msg))

    def _run_hook(self, hook, cmd_msg):
        if hook.singleton:
            log.info("Hook %s is configured to run as a singleton", hook.name)
            leader = self.cfn_client.elect_command_leader(self.stack_name,
                                                          cmd_msg['CommandName'],
                                                          cmd_msg['InvocationId'],
                                                          self.listener_id)
            if leader == self.listener_id:
                log.info("This listener is the leader.  Continuing with action")
            else:
                log.info("This listener is not the leader; %s is the leader.", leader)
                return True

        action_env = self._get_environment(cmd_msg)
        result_queue = cmd_msg['ResultQueue']

        log.info("Running action for %s", hook.name)
        log.debug("Action environment: %s", action_env)

        action = hook.action
        if hook.runas:
            if os.name == 'posix':
                action = ['su', hook.runas, '-c', action]
            else:
                log.warn('runas is not supported on this operating system')

        result = ProcessHelper(action, stderr=subprocess.PIPE, env=action_env).call()

        log.debug("Action for %s output: %s", hook.name, result.stdout if result.stdout else '<None>')

        if not hook.send_result:
            return True

        result_msg = { 'DispatcherId' : cmd_msg['DispatcherId'],
                       'InvocationId' : cmd_msg['InvocationId'],
                       'CommandName' : cmd_msg['CommandName'],
                       'Status' : "FAILURE" if result.returncode else "SUCCESS",
                       'ListenerId' : self.listener_id }

        if result.returncode:
            result_stderr = result.stderr.rstrip()
            log.warn("Action for %s exited with %s, returning FAILURE", hook.name, result.returncode)
            result_msg['Message'] = result_stderr if len(result_stderr) <= 1024 else result_stderr[0:500] + '...' + result_stderr[-500:]
        else:
            result_stdout = result.stdout.rstrip()
            if len(result_stdout) > 1024:
                log.error("stdout for %s was greater than 1024 in length, which is not allowed", hook.name)
                result_msg['Status'] = 'FAILURE'
                result_msg['Message'] = 'Result data was longer than 1024 bytes. Started with: ' + result_stdout[0:100]
            else:
                log.info("Action for %s succeeded, returning SUCCESS", hook.name)
                result_msg['Data'] = result_stdout

        try:
            self.sqs_client.send_message(result_queue, json.dumps(result_msg), request_credentials=self._creds_provider.credentials)
        except Exception:
            log.exception('Error sending result; will leave message in queue')
            return False

        return True

    def _hooks_by_path(self, hooks):
        ret_hooks = {}
        for hook in hooks:
            if hook.path in ret_hooks:
                raise FatalUpdateError("Multiple hooks for the same command (%s)" % hook.path)
            ret_hooks[hook.path] = hook
        return ret_hooks

    def _get_environment(self, cmd_msg):
        action_env = dict(os.environ)
        if 'Data' in cmd_msg:
            action_env['CMD_DATA'] = cmd_msg['Data']
        action_env['INVOCATION_ID'] = cmd_msg['InvocationId']
        action_env['DISPATCHER_ID'] = cmd_msg['DispatcherId']
        action_env['CMD_NAME'] = cmd_msg['CommandName']
        action_env['STACK_NAME'] = self.stack_name
        action_env['LISTENER_ID'] = self.listener_id
        action_env['RESULT_QUEUE'] = cmd_msg['ResultQueue']
        if 'EventHandle' in cmd_msg:
            action_env['EVENT_HANDLE'] = cmd_msg['EventHandle']
        creds = self._creds_provider.credentials
        action_env['RESULT_ACCESS_KEY'] = creds.access_key
        action_env['RESULT_SECRET_KEY'] = creds.secret_key
        action_env['RESULT_SESSION_TOKEN'] = creds.security_token
        return action_env


class HookProcessor(object):
    """Processes update hooks"""

    def __init__(self, hooks, stack_name, client):
        """Takes a list of Hook objects and processes them"""
        self.hooks = hooks
        if os.name == 'nt':
            self.dir = os.path.expandvars(r'${SystemDrive}\cfn\cfn-hup\data')
        else:
            self.dir = '/var/lib/cfn-hup/data'
        if not os.path.isdir(self.dir):
            log.debug("Creating %s", self.dir)
            try:
                os.makedirs(self.dir)
            except OSError:
                log.warn("Could not create %s; using temporary directory", self.dir)
                self.dir = tempfile.mkdtemp()

        self.client = client
        self.stack_name = stack_name

    def process(self):
        with contextlib.closing(shelve.open('%s/metadata_db' % self.dir)) as shelf:
            self._resource_cache = {}
            for hook in self.hooks:
                try:
                    self._process_hook(hook, shelf)
                except FatalUpdateError:
                    raise
                except Exception:
                    log.exception("Exception caught while running hook %s", hook.name)

    def _process_hook(self, hook, shelf):
        try:
            new_data = self._retrieve_path_data(hook.path)
        except InFlightStatusError:
            return

        old_data = shelf.get(hook.name + "|" + hook.path, None)

        if 'post.add' in hook.triggers and not old_data and new_data:
            log.info("Previous state not found; action for %s will be run", hook.name)
        elif 'post.remove' in hook.triggers and old_data and not new_data:
            log.info('Path %s was removed; action for %s will be run', hook.path, hook.name)
        elif 'post.update' in hook.triggers and old_data and new_data and old_data != new_data:
            log.info("Data has changed from previous state; action for %s will be run", hook.name)
        else:
            log.debug("No change in path %s for hook %s", hook.path, hook.name)
            shelf[hook.name + '|' + hook.path] = new_data
            return

        log.info("Running action for %s", hook.name)
        action_env = dict(os.environ)
        env_key = self._retrieve_env_key(hook.path)
        if old_data:
            action_env['CFN_OLD_%s' % env_key] = self._as_string(old_data)
        if new_data:
            action_env['CFN_NEW_%s' % env_key] = self._as_string(new_data)

        action = hook.action
        if hook.runas:
            action = ['su', hook.runas, '-c', action]

        result = ProcessHelper(action, env=action_env).call()

        if result.returncode:
            log.warn("Action for %s exited with %s; will retry on next iteration", hook.name, result.returncode)
        else:
            shelf[hook.name + '|' + hook.path] = new_data
        log.debug("Action for %s output: %s", hook.name, result.stdout if result.stdout else '<None>')

    def _as_string(self, obj):
        if isinstance(obj, basestring):
            return obj
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return json.dumps(obj)

    def _retrieve_env_key(self, path):
        """Given a hook path, return the key to append to environment variables for old/new data"""
        parts = path.split('.', 3)

        if len(parts) < 3:
            return 'LAST_UPDATED'
        elif parts[2].lower() == 'metadata':
            return 'METADATA'
        elif parts[2].lower() == 'physicalresourceid':
            return 'PHYSICAL_RESOURCE_ID'

    def _retrieve_path_data(self, path):
        parts = path.split('.', 3)
        if len(parts) < 2:
            raise FatalUpdateError("Unsupported path: paths must be in the form Resources.<LogicalResourceId>(.Metadata|PhysicalResourceId)(.<optional Metadata subkey>). Input: %s" % path)

        if parts[0].lower() != 'resources':
            raise FatalUpdateError('Unsupported path: only changes to Resources are supported (path: %s)' % path)

        if len(parts) == 2:
            resourcePart = None
        elif parts[2].lower() not in ['metadata', 'physicalresourceid']:
            raise FatalUpdateError("Unsupported path: only Metadata or PhysicalResourceId can be specified after LogicalResourceId (path: %s)" % path)
        else:
            resourcePart = parts[2].lower()

        logical_id = parts[1]
        subpath = ('' if len(parts) < 4 else parts[3])

        if logical_id not in self._resource_cache:
            self._resource_cache[logical_id] = self.client.describe_stack_resource(logical_id, self.stack_name)

        resource = self._resource_cache[logical_id]
        status = resource.resourceStatus

        if status and status.endswith('_IN_PROGRESS'):
            log.debug("Skipping resource %s in %s as it is in status %s", logical_id, self.stack_name, status)
            raise InFlightStatusError('%s in %s is in status %s' % (logical_id, self.stack_name, status))

        if resourcePart == 'metadata':
            if not resource.metadata:
                log.warn("No metadata for %s in %s", logical_id, self.stack_name)
                return None

            return util.extract_value(resource.metadata, subpath)
        elif 'DELETE_COMPLETE' == status:
            return None
        elif resourcePart == 'physicalresourceid':
            return resource.physicalResourceId
        else:
            return resource.lastUpdated
