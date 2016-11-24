# Copyright (C) 2016 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# We rely on https://github.com/sonyxperiadev/pygerrit

import jenkins
import ssl
import socket
from six.moves.urllib.request import build_opener, HTTPSHandler
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from six.moves.urllib.parse import urljoin

import sfauth


class SFJenkins(jenkins.Jenkins):
    def __init__(self, url, username=None, password=None, cookie=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 insecure=False):
        super(SFJenkins, self).__init__(urljoin(url, 'jenkins/'),
                                        username, password, timeout)
        if not cookie and (not username or not password):
            raise ValueError("Authentication needed")
        if not cookie:
            self.cookie = sfauth.get_cookie(url, username, password,
                                            use_ssl=True, verify=not insecure)
        else:
            self.cookie = cookie
        self.insecure = insecure
        self.opener = build_opener()
        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.opener.add_handler(HTTPSHandler(context=ctx))

    def jenkins_open(self, req, add_crumb=True):
        '''Utility routine for opening an HTTP request to a Jenkins server.
        Extended over the original method to allow connections to SF with a
        cookie.
        '''
        self.opener.addheaders = [('Cookie',
                                   'auth_pubtkt=%s' % self.cookie)]
        try:
            if add_crumb:
                self.maybe_add_crumb(req)
            response = self.opener.open(req, timeout=self.timeout).read()
            if response is None:
                raise jenkins.EmptyResponseException(
                    "Error communicating with server[%s]: "
                    "empty response" % self.server)
            return response.decode('utf-8')
        except HTTPError as e:
            # Jenkins's funky authentication means its nigh impossible to
            # distinguish errors.
            if e.code in [401, 403, 500]:
                # six.moves.urllib.error.HTTPError provides a 'reason'
                # attribute for all python version except for ver 2.6
                # Falling back to HTTPError.msg since it contains the
                # same info as reason
                raise jenkins.JenkinsException(
                    'Error in request. ' +
                    'Possibly authentication failed [%s]: %s' % (
                        e.code, e.msg)
                )
            elif e.code == 404:
                raise jenkins.NotFoundException(
                    'Requested item could not be found')
            else:
                raise
        except socket.timeout as e:
            raise jenkins.TimeoutException('Error in request: %s' % (e))
        except URLError as e:
            # python 2.6 compatibility to ensure same exception raised
            # since URLError wraps a socket timeout on python 2.6.
            if str(e.reason) == "timed out":
                raise jenkins.TimeoutException(
                    'Error in request: %s' % (e.reason))
        raise jenkins.JenkinsException('Error in request: %s' % (e.reason))


# Examples
if __name__ == "__main__":
    j = SFJenkins('https://sftests.com', username='admin',
                  password='userpass', insecure=True)
    print j.get_whoami()
