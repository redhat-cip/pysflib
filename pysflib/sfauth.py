#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

import json
import requests


class IntrospectionNotAvailableError(Exception):
    pass


def _old_get_cookie(auth_server,
                    username=None, password=None,
                    github_access_token=None,
                    use_ssl=False, verify=True):
    if username and password:
        url = "%s/auth/login" % auth_server
        params = {'username': username,
                  'password': password,
                  'back': '/'}
    elif github_access_token:
        url = "%s/auth/login/githubAPIkey/" % auth_server
        params = {'token': github_access_token,
                  'back': '/'}
    else:
        raise ValueError("Missing credentials")
    if use_ssl:
        url = "https://" + url
        resp = requests.post(url, params, allow_redirects=False,
                             verify=verify)
    else:
        url = "http://" + url
        resp = requests.post(url, params, allow_redirects=False)
    return resp.cookies.get('auth_pubtkt', '')


def get_cookie(auth_server,
               username=None, password=None,
               github_access_token=None,
               use_ssl=False, verify=True):
    try:
        cauth_info = get_cauth_info(auth_server, use_ssl, verify)
        url = "%s/auth/login" % auth_server
        if cauth_info['service']['version'] > '0.2.0':
            auth_params = {'back': '/',
                           'args': {}, }
            methods = cauth_info['service']['auth_methods']
            if (username and password and ('Password' in methods)):
                auth_params['args'] = {'username': username,
                                       'password': password}
                auth_params['method'] = 'Password'
            elif (github_access_token and
                  ('GithubPersonalAccessToken' in methods)):
                auth_params['args'] = {'token': github_access_token}
                auth_params['method'] = 'GithubPersonalAccessToken'
            else:
                m = "Missing credentials (accepted auth methods: %s)"
                methods = ','.join(methods)
                raise ValueError(m % methods)
            header = {'Content-Type': 'application/json'}
            if use_ssl:
                url = "https://" + url
                resp = requests.post(url, json.dumps(auth_params),
                                     allow_redirects=False,
                                     verify=verify,
                                     headers=header)
            else:
                url = "http://" + url
                resp = requests.post(url, json.dumps(auth_params),
                                     allow_redirects=False,
                                     headers=header)
            return resp.cookies.get('auth_pubtkt', '')
        else:
            return _old_get_cookie(auth_server, username, password,
                                   github_access_token, use_ssl, verify)
    except IntrospectionNotAvailableError:
        return _old_get_cookie(auth_server, username, password,
                               github_access_token, use_ssl, verify)


def _get_service_info(url, use_ssl=False, verify=True):
    if use_ssl:
        url = "https://" + url
        resp = requests.get(url, allow_redirects=False,
                            verify=verify)
    else:
        url = "http://" + url
        resp = requests.get(url, allow_redirects=False)
    if resp.status_code > 399:
        raise IntrospectionNotAvailableError()
    return resp.json()


def get_cauth_info(auth_server, use_ssl=False, verify=True):
    url = "%s/auth/about/" % auth_server
    return _get_service_info(url, use_ssl, verify)


def get_managesf_info(auth_server, use_ssl=False, verify=True):
    url = "%s/about/" % auth_server
    return _get_service_info(url, use_ssl, verify)
