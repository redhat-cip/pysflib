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

# We rely on https://github.com/maxtepkeev/python-redmine

import re
import json
import logging
import requests

from redmine import Redmine
from redmine.utilities import to_string
from redmine.exceptions import (AuthError,
                                ConflictError,
                                ImpersonateError,
                                ServerError,
                                ValidationError,
                                ResourceNotFoundError,
                                RequestEntityTooLargeError,
                                UnknownError)

from pysflib.interfaces.issuetracker import IssueTrackerUtils

logger = logging.getLogger(__name__)


class SFRedmine(Redmine):
    def __init__(self, *args, **kwargs):
        super(SFRedmine, self).__init__(*args, **kwargs)
        if 'auth_cookie' in kwargs:
            self.auth_cookie = kwargs['auth_cookie']
        else:
            self.auth_cookie = None
        self.debug_logs = set()

    def debug(self, msg):
        if msg in self.debug_logs:
            # ignore already logged message
            return
        self.debug_logs.add(msg)
        logger.debug(msg)

    def request(self, method, url, headers=None, params=None,
                data=None, raw_response=False):
        """Makes requests to Redmine and returns result in json format"""
        kwargs = dict(self.requests, **{
            'headers': headers or {},
            'params': params or {},
            'data': data or {},
        })

        if 'Content-Type' not in kwargs['headers'] and method in ('post',
                                                                  'put'):
            kwargs['data'] = json.dumps(data)
            kwargs['headers']['Content-Type'] = 'application/json'

        if self.impersonate is not None:
            kwargs['headers']['X-Redmine-Switch-User'] = self.impersonate

        # We would like to be authenticated by API key by default
        if self.key is not None:
            kwargs['params']['key'] = self.key
        if self.username and self.password:
            kwargs['auth'] = (self.username, self.password)
        if self.auth_cookie:
            kwargs['cookies'] = dict(auth_pubtkt=self.auth_cookie)

        self.debug("Send HTTP %s request %s with kwargs %s" %
                   (method, url, str(kwargs)))
        response = getattr(requests, method)(url, **kwargs)

        if response.status_code in (200, 201):
            if raw_response:
                return response
            elif not response.content.strip():
                return True
            else:
                return response.json()
        elif response.status_code == 401:
            raise AuthError
        elif response.status_code == 404:
            raise ResourceNotFoundError
        elif response.status_code == 409:
            raise ConflictError
        elif response.status_code == 412 and self.impersonate is not None:
            raise ImpersonateError
        elif response.status_code == 413:
            raise RequestEntityTooLargeError
        elif response.status_code == 422:
            raise ValidationError(to_string(', '.join(
                response.json()['errors'])))
        elif response.status_code == 500:
            raise ServerError

        raise UnknownError(response.status_code)


class RedmineUtils(IssueTrackerUtils):
    """ Utility class that eases calls on the Redmine API
    for software-factory. Provide the args you used to pass
    to python-redmine.Redmine and add auth_cookie to authenticate
    through SSO.
    """
    def __init__(self, *args, **kwargs):
        self.r = SFRedmine(*args, **kwargs)

    def _slugify(self, name):
        return name.strip().replace(' ', '-').replace('/', '_').lower()

    def project_exists(self, name):
        try:
            self.r.project.get(self._slugify(name))
        except ResourceNotFoundError:
            return False
        return True

    def get_issue_status(self, issueid):
        try:
            return self.r.issue.get(issueid).status
        except ResourceNotFoundError:
            return None

    def get_open_issues(self):
        url = "%s/issues.json?status_id=open" % self.r.url
        data = self.r.request('get', url)
        count = data.get('total_count')
        url = "%s&offset=0&limit=%s" % (url, count)
        return self.r.request('get', url)

    def get_issues_by_project(self, name):
        try:
            p = self.r.project.get(self._slugify(name))
        except ResourceNotFoundError:
            return None
        return [i.id for i in p.issues]

    def test_issue_status(self, issueid, status):
        s = self.get_issue_status(issueid)
        if s:
            if s.name == status:
                return True
            else:
                return False

    def set_issue_status(self, iid, status_id, message=None):
        try:
            return self.r.issue.update(iid,
                                       status_id=status_id,
                                       notes=message)
        except ResourceNotFoundError:
            return None

    def create_issue(self, name, subject='', **kwargs):
        name = self._slugify(name)
        issue = self.r.issue.create(project_id=name,
                                    subject=subject,
                                    **kwargs)
        return issue.id

    def delete_issue(self, issueid):
        try:
            return self.r.issue.delete(issueid)
        except ResourceNotFoundError:
            return None

    def check_user_role(self, name, username, role):
        name = self._slugify(name)
        for u in self.r.project_membership.filter(project_id=name):
            if self.r.user.get(u.user.id).firstname == username:
                for r in u.roles:
                    if r.name == role:
                        return True
        return False

    def create_project(self, name, description, private):
        identifier = self._slugify(name)
        name_re = re.compile('^[a-z][a-z0-9-_]{0,99}$')
        if not name_re.match(identifier):
            raise ValueError('The name should have a length between 1 and '
                             '100 characters. Only letters (a-z), numbers,'
                             ' dashes, spaces and underscores are '
                             'allowed, must start with a letter')
        self.r.project.create(name=name,
                              identifier=identifier,
                              description=description,
                              is_public='false' if private else 'true')

    def create_user(self, username, email, lastname):
        return self.r.user.create(login=username, firstname=username,
                                  lastname=lastname, mail=email)

    def get_user_id(self, mail):
        try:
            users = self.r.user.filter(mail=mail)
            for user in users:
                if user.mail == mail:
                    return user.id
        except ResourceNotFoundError:
            return None
        return None

    def get_user_id_by_username(self, username):
        try:
            users = self.r.user.filter(login=username)
            for user in users:
                if user.login == username:
                    return user.id
        except ResourceNotFoundError:
            return None
        return None

    def get_role_id(self, name):
        roles = self.r.role.all()
        for r in roles:
            if r.name == name:
                return r.id
        return None

    def get_role(self, id):
        return self.r.role.get(id)

    def get_projects(self):
        url = "%s/projects.json" % self.r.url
        return self.r.request('get', url)

    def get_project_membership_for_user(self, pname, uid):
        """ This function support both user or group id
        """
        try:
            pname = self._slugify(pname)
            memb = self.r.project_membership.filter(project_id=pname)
        except ResourceNotFoundError:
            return None
        for m in memb:
            if hasattr(m, 'user'):
                if m.user.id == uid:
                    return m.id
            if hasattr(m, 'group'):
                if m.group['id'] == uid:
                    return m.id
        return None

    def get_project_roles_for_user(self, pname, uid):
        """ This function support both user or group id
        """
        mid = self.get_project_membership_for_user(pname, uid)
        try:
            return [r['name'] for r in
                    self.r.project_membership.get(mid).roles]
        except ResourceNotFoundError:
            return []

    def update_membership(self, mid, role_ids):
        try:
            return self.r.project_membership.update(mid,
                                                    role_ids=role_ids)
        except ResourceNotFoundError:
            return None

    def update_project_membership(self, pname, memberships):
        for m in memberships:
            pname = self._slugify(pname)
            self.r.project_membership.create(project_id=pname,
                                             user_id=m['user_id'],
                                             role_ids=m['role_ids'])

    def delete_membership(self, id):
        try:
            return self.r.project_membership.delete(id)
        except ResourceNotFoundError:
            return None

    def delete_project(self, pname):
        try:
            return self.r.project.delete(self._slugify(pname))
        except ResourceNotFoundError:
            return None

    def active_users(self):
        try:
            return [(x.login, x.mail, ' '.join([x.firstname, x.lastname]))
                    for x in self.r.user.filter(status=1)]
        except ResourceNotFoundError:
            return None

    def get_sf_projects_url(self):
        return "%s/projects" % self.get_root_url()

    def get_root_url(self):
        return self.r.url

    def test_static_file(self):
        css_file = "/plugin_assets/redmine_backlogs/stylesheets/global.css"
        return self.get_root_url() + css_file

    def create_group(self, name):
        try:
            self.r.group.create(name=name)
        except ValidationError, e:
            if str(e) != 'Name has already been taken':
                return False
        return True

    def get_group_id(self, name):
        groups = self.r.group.all()
        try:
            gid = [g.id for g in groups if g.name == name][0]
        except IndexError:
            return None
        return gid

    def set_group_members(self, gid, user_ids):
        try:
            return self.r.group.update(gid, user_ids=user_ids)
        except ResourceNotFoundError:
            return None

    def list_group(self, gid):
        try:
            return self.r.group.get(gid, include='users').users
        except ResourceNotFoundError:
            return None

    def delete_group(self, gid):
        try:
            return self.r.group.delete(gid)
        except ResourceNotFoundError:
            return None


# Here an usage example.
if __name__ == "__main__":
    import sfauth
    c = sfauth.get_cookie('sftests.com', 'admin', 'userpass')
    a = RedmineUtils('http://sftests.com/redmine', auth_cookie=c)
    a.create_user('John', 'john@doe.com', 'John Doe')
