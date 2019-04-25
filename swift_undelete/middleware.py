# Copyright (c) 2014 SwiftStack, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Middleware for OpenStack Swift that implements undelete functionality.

When this middleware is installed, an object DELETE request will cause a copy
of the object to be saved into a "trash location" prior to deletion.
Subsequently, an administrator can recover the deleted object.

Caveats:

 * This does not provide protection against overwriting an object. Use Swift's
   object versioning if you require overwrite protection.

 * If your account names are near the maximum length, this middleware will
   fail to create trash accounts, leaving some objects unable to be deleted.

 * If your container names are near the maximum length, this middleware will
   fail to create trash containers, leaving some objects unable to be deleted.

 * If your cluster is too full to allow an object to be copied, you will be
   unable to delete it. In extremely full clusters, this may result in a
   situation where you need to add capacity before you can delete objects.

 * Requires Swift 1.12.0+, which introduced system metadata.

Future work:

 * Move to separate account, not container, for trash. This requires Swift to
   allow cross-account COPY requests.

 * If block_trash_deletes is on, modify the Allow header in responses (both
   OPTIONS responses and any other 405 response).

"""
import requests
import time

from datetime import datetime, timedelta

from swift.common import http, swob, utils, wsgi
from swift.common.request_helpers import get_sys_meta_prefix
from swift.proxy.controllers.base import get_account_info, get_container_info

HOST = "localhost"
PORT = "8081"
DEFAULT_TRASH_PREFIX = ".trash-"
DEFAULT_TRASH_LIFETIME = 86400 * 90  # 90 days expressed in seconds
SYSMETA_UNDELETE_ENABLED = "undelete-enabled"
SYSMETA_ACCOUNT = get_sys_meta_prefix('account') + SYSMETA_UNDELETE_ENABLED
SYSMETA_CONTAINER = get_sys_meta_prefix('container') + SYSMETA_UNDELETE_ENABLED


try:
    from swift.common.request_helpers import close_if_possible
except ImportError:
    # Pre-1.13.0 (ref. https://github.com/openstack/swift/commit/1f67eb7)
    def close_if_possible(maybe_closable):
        close_method = getattr(maybe_closable, 'close', None)
        if callable(close_method):
            return close_method()


def friendly_error(orig_error):
    return "Error copying object to trash:\n" + orig_error


class ContainerContext(wsgi.WSGIContext):
    """
    Helper class to perform a container PUT request.
    """

    def create(self, env, account, container, versions=None):
        """
        Perform a container PUT request

        :param env: WSGI environment for original request
        :param account: account in which to create the container
        :param container: container name
        :param versions: value for X-Versions-Location header (for container versioning)

        :returns: None
        :raises: HTTPException on failure (non-2xx response)
        """
        path_info = "/".join(env.environ['PATH_INFO'].split('/')[1:3])
        token = env.environ['keystone.token_info']['token']['auth_token']
        url = "http://%s:%s/%s/%s" % (HOST, PORT, path_info, container)
        headers = {"X-Auth-Token": token}

        if versions:
            headers["X-Versions-Location"] = versions

        return requests.request('PUT', headers=headers, url=url)


class CopyContext(wsgi.WSGIContext):
    """
    Helper class to perform an object COPY request.
    """

    def copy(self, env, destination_container, destination_object,
             delete_after=None):
        """
        Perform a COPY from source to destination.

        :param env: WSGI environment for a request aimed at the source object.
        :param destination_container: container to copy into.
            Note: this must not contain any slashes or the request is guaranteed to fail.
        :param destination_object: destination object name
        :param delete_after: value of X-Delete-At; object will be deleted
                             after that many seconds have elapsed. Set to 0 or
                             None to keep the object forever.

        :returns: 3-tuple (HTTP status code, response headers,
                           full response body)
        """
        host = env.headers['Host']
        path_info = env.environ['PATH_INFO']
        url = "http://%s:%s%s" % (HOST, PORT, path_info)

        token = env.environ['keystone.token_info']['token']['auth_token']
        destination = '/'.join((destination_container, destination_object))
        headers = {"X-Auth-Token": token, "Destination": destination}

        if delete_after:
            delete_at = datetime.now() + timedelta(seconds=delete_after)
            unix_time = int(time.mktime(delete_at.timetuple()))
            headers["X-Delete-At"] = str(unix_time)

        return requests.request('COPY', headers=headers, url=url)


class UndeleteMiddleware(object):
    def __init__(self, app, trash_prefix=DEFAULT_TRASH_PREFIX,
                 trash_lifetime=DEFAULT_TRASH_LIFETIME,
                 block_trash_deletes=False,
                 enable_by_default=True):
        self.app = app
        self.trash_prefix = trash_prefix
        self.trash_lifetime = trash_lifetime
        self.block_trash_deletes = block_trash_deletes
        self.enable_by_default = enable_by_default

    @swob.wsgify
    def __call__(self, req):
        try:
            vrs, acc, con, obj = req.split_path(2, 4, rest_with_last=True)
        except ValueError:
            # /info or similar...
            return self.app

        # Check if it's an account request...
        if con is None:
            return self.translate_sysmeta_and_complete(req, {
                'x-' + SYSMETA_UNDELETE_ENABLED: SYSMETA_ACCOUNT})

        # ...or a container request...
        if obj is None:
            return self.translate_sysmeta_and_complete(req, {
                'x-' + SYSMETA_UNDELETE_ENABLED: SYSMETA_CONTAINER})

        # ...must be object.
        # We only want to step in on object DELETE requests
        if req.method != 'DELETE':
            return self.app

        # Okay, this is definitely an object DELETE request; let's see if it's
        # one we want to step in for.
        if self.is_trash(con) and self.block_trash_deletes:
            return swob.HTTPMethodNotAllowed(
                content_type="text/plain",
                body=("Attempted to delete from a trash container, but "
                      "block_trash_deletes is enabled\n"))
        elif self.is_trash(con) and not self.is_superuser(req.environ):
            return swob.HTTPForbidden(
                content_type="text/plain",
                body=("Attempted to delete from a trash container, but "
                      "user is not a superuser\n"))
        elif not self.should_save_copy(req.environ, con, obj):
            return self.app

        trash_container = self.trash_prefix + con
        response = self.copy_object(req, trash_container, obj)

        if response.status_code == 404:
            self.create_trash_container(req, acc, trash_container)
            response = self.copy_object(req, trash_container, obj)
        elif not http.is_success(response.status_code):
            # other error; propagate this to the client
            return swob.Response(
                body=friendly_error(response.content),
                status=response.status_code,
                headers=response.headers)
        return self.app

    def translate_sysmeta_and_complete(self, req, mapping):
        """
        Translate some client HTTP headers to sysmeta headers (if superuser),
        pass the request down the pipeline, and translate sysmeta headers back
        to HTTP headers (for all users).

        :param req: the request thus far
        :param mapping: a mapping of HTTP headers to sysmeta headers
        """
        if self.is_superuser(req.environ):
            for client_header, sysmeta_header in mapping.items():
                val = req.headers.get(client_header)
                if val is None:
                    pass
                elif utils.config_true_value(val):
                    req.headers[sysmeta_header] = 'True'
                elif val.lower() == 'default':
                    req.headers[sysmeta_header] = ''
                else:
                    req.headers[sysmeta_header] = 'False'
        resp = req.get_response(self.app)
        for client_header, sysmeta_header in mapping.items():
            if sysmeta_header in resp.headers:
                resp.headers[client_header] = resp.headers[sysmeta_header]
        return resp

    def copy_object(self, req, trash_container, obj):
        return CopyContext(self.app).copy(req, trash_container, obj,
                                          self.trash_lifetime)

    def create_trash_container(self, req, account, trash_container):
        """
        Create a trash container and its associated versions container.

        :raises HTTPException: if container creation failed
        """
        ctx = ContainerContext(self.app)
        versions_container = trash_container + "-versions"
        ctx.create(req, account, versions_container)
        ctx.create(req, account, trash_container,
                   versions=versions_container)

    def is_trash(self, con):
        """
        Whether a container is a trash container or not
        """
        return con.startswith(self.trash_prefix)

    def is_superuser(self, env):
        """
        Whether the request was made by a superuser or not
        """
        return bool(env.get('reseller_request'))

    def is_enabled_for(self, env):
        """
        Whether an account or container has meta-data to opt out of undelete
        protection
        """
        sysmeta_c = get_container_info(env, self.app)['sysmeta']
        # Container info gets & caches account info, so this is basically free
        sysmeta_a = get_account_info(env, self.app)['sysmeta']

        enabled = sysmeta_c.get(SYSMETA_UNDELETE_ENABLED)
        if enabled is None:
            enabled = sysmeta_a.get(SYSMETA_UNDELETE_ENABLED,
                                    self.enable_by_default)
        return utils.config_true_value(enabled)

    def should_save_copy(self, env, con, obj):
        """
        Determine whether or not we should save a copy of the object prior to
        its deletion. For example, if the object is one that's in a trash
        container, don't save a copy lest we get infinite metatrash recursion.
        """
        return not self.is_trash(con) and self.is_enabled_for(env)


def filter_factory(global_conf, **local_conf):
    """
    Returns the WSGI filter for use with paste.deploy.

    Parameters in config:

    # value to prepend to the account in order to compute the trash location
    trash_prefix = ".trash-"
    # how long, in seconds, trash objects should live before expiring. Set to 0
    # to keep trash objects forever.
    trash_lifetime = 7776000  # 90 days
    # whether to block trash objects from being deleted
    block_trash_deletes = no
    # whether to enable undelete functionality by default. Administrators may
    # explicitly enable or disable per account or container via the
    # X-Undelete-Enabled header. Set this header to 'default' to resume default
    # behavior.
    enable_by_default = yes
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    trash_prefix = conf.get("trash_prefix", DEFAULT_TRASH_PREFIX)
    trash_lifetime = int(conf.get("trash_lifetime", DEFAULT_TRASH_LIFETIME))
    block_trash_deletes = utils.config_true_value(
        conf.get('block_trash_deletes', 'no'))
    enable_by_default = utils.config_true_value(
        conf.get('enable_by_default', 'yes'))

    def filt(app):
        return UndeleteMiddleware(app, trash_prefix=trash_prefix,
                                  trash_lifetime=trash_lifetime,
                                  block_trash_deletes=block_trash_deletes,
                                  enable_by_default=enable_by_default)
    return filt
