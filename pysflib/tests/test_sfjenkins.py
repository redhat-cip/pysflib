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

from StringIO import StringIO
from six.moves.urllib.request import build_opener, HTTPSHandler
from six.moves.urllib.request import Request
from six.moves.urllib.response import addinfourl
from unittest import TestCase

from pysflib import sfjenkins


TEST_COOKIE = "123456789"


class TestHTTPSHandler(HTTPSHandler):
    def https_open(self, req):
        resp = addinfourl(StringIO(req.get_header('Cookie')),
                          "mock message",
                          req.get_full_url())
        resp.code = 200
        resp.msg = "OK"
        return resp


class TestSFJenkins(TestCase):

    @classmethod
    def setupClass(cls):
        cls.jenkins = sfjenkins.SFJenkins('https://jenkins.tests.dom',
                                          cookie=TEST_COOKIE)
        cls.jenkins.crumb = {"crumbRequestField": "DummyField",
                             "crumb": "DummyCrumb", }
        cls.jenkins.opener = build_opener(TestHTTPSHandler())

    def test_access_jenkins_with_cookie(self):
        mock_call = self.jenkins.jenkins_open(Request('https://blop'))
        self.assertEqual("auth_pubtkt=%s" % TEST_COOKIE,
                         mock_call,
                         "Received %s" % mock_call)
