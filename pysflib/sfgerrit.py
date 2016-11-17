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

# We rely on https://github.com/sonyxperiadev/pygerrit

import json
import logging
import urllib
import requests
from requests.exceptions import HTTPError
from pygerrit.rest import GerritRestAPI
from pygerrit.rest import _decode_response

logger = logging.getLogger(__name__)


class SFGerritRestAPI(GerritRestAPI):
    def __init__(self, *args, **kwargs):
        if 'auth_cookie' in kwargs and 'auth' not in kwargs:
            auth_cookie = kwargs['auth_cookie']
            del kwargs['auth_cookie']
            super(SFGerritRestAPI, self).__init__(*args, **kwargs)
            # Re-add the auth prefix to URL because
            # the base init remove if as we does not pass
            # the auth arg
            self.url += 'r/a/'
            self.kwargs.update(
                {"cookies": dict(
                    auth_pubtkt=auth_cookie)})
        else:
            super(SFGerritRestAPI, self).__init__(*args, **kwargs)
        self.debug_logs = set()
        self.session = requests.session()

    def _decode_response(self, response):
        try:
            return _decode_response(response)
        except ValueError:
            return response.content.strip()

    def debug(self, msg):
        if msg in self.debug_logs:
            # ignore already logged message
            return
        self.debug_logs.add(msg)
        logger.debug(msg)

    def get(self, endpoint, **kwargs):
        kwargs.update(self.kwargs.copy())
        url = self.make_url(endpoint)
        self.debug("Send HTTP GET request %s with kwargs %s" %
                   (url, str(kwargs)))
        response = self.session.get(url, **kwargs)
        return self._decode_response(response)

    def put(self, endpoint, **kwargs):
        headers = None
        if 'headers' in kwargs:
            headers = kwargs['headers']
            del kwargs['headers']
        kwargs.update(self.kwargs.copy())
        kwargs["headers"].update(
            {"Content-Type": "application/json;charset=UTF-8"})
        if headers is not None:
            kwargs["headers"] = headers
        url = self.make_url(endpoint)
        self.debug("Send HTTP PUT request %s with kwargs %s" %
                   (url, str(kwargs)))
        response = self.session.put(url, **kwargs)
        return self._decode_response(response)

    def post(self, endpoint, **kwargs):
        headers = None
        if 'headers' in kwargs:
            headers = kwargs['headers']
            del kwargs['headers']
        kwargs.update(self.kwargs.copy())
        kwargs["headers"].update(
            {"Content-Type": "application/json;charset=UTF-8"})
        if headers is not None:
            kwargs["headers"] = headers
        url = self.make_url(endpoint)
        self.debug("Send HTTP POST request %s with kwargs %s" %
                   (url, str(kwargs)))
        response = self.session.post(url, **kwargs)
        return self._decode_response(response)

    def delete(self, endpoint, **kwargs):
        headers = None
        if 'headers' in kwargs:
            headers = kwargs['headers']
            del kwargs['headers']
        kwargs.update(self.kwargs.copy())
        if headers is not None:
            kwargs["headers"] = headers
        url = self.make_url(endpoint)
        self.debug("Send HTTP DELETE request %s with kwargs %s" %
                   (url, str(kwargs)))
        response = self.session.delete(url, **kwargs)
        return self._decode_response(response)


class GerritUtils:
    """ Utility class that eases calls on the Gerrit API
    for software-factory. Provide the args you used to pass
    to pygerrit.rest.GerritRestAPI and add auth_cookie
    to authenticate through SSO.
    """
    def __init__(self, *args, **kwargs):
        self.g = SFGerritRestAPI(*args, **kwargs)

    def _manage_errors(self, e):
        if e.response.status_code == 404:
            return False
        if e.response.status_code == 409:
            return False
        else:
            raise

    # Projects related API calls #
    def project_exists(self, name):
        try:
            name = urllib.quote_plus(name)
            self.g.get('projects/%s' % name)
            return True
        except HTTPError as e:
            return self._manage_errors(e)

    def create_project(self, name, desc, owners):
        data = json.dumps({
            "description": desc,
            "name": name,
            "create_empty_commit": True,
            "owners": owners,
        })
        try:
            name = urllib.quote_plus(name)
            self.g.put('projects/%s' % name,
                       data=data)
        except HTTPError as e:
            return self._manage_errors(e)

    def delete_project(self, name, force=False):
        try:
            name = urllib.quote_plus(name)
            if force:
                data = json.dumps({"force": True})
                self.g.delete(
                    'projects/%s' % name,
                    data=data,
                    headers={"Content-Type":
                             "application/json;charset=UTF-8"})
            else:
                self.g.delete('projects/%s' % name)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_project(self, name):
        try:
            name = urllib.quote_plus(name)
            return self.g.get('projects/%s' % name)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_projects(self):
        projects = sorted(self.g.get('projects/?').keys())
        if 'All-Users' in projects:
            projects.remove('All-Users')
        return projects

    def get_project_owner(self, name):
        try:
            name = urllib.quote_plus(name)
            ret = self.g.get('access/?project=%s' % name)
            perms = ret[name]['local']['refs/*']['permissions']
            owner = perms.get('owner')
            if owner:
                return sorted(owner['rules'].keys())[0]
        except HTTPError as e:
            return self._manage_errors(e)

    def get_project_groups_id(self, names):
        """ Return list of groups (id) for requested
        projects flag groups declared as projects owner
        """
        assert isinstance(names, list)
        # Getting access rules for all projects hosted
        # is done by one request specifiying multiple
        # project names inside the query string. To act safer
        # bulk limits the amount of projects requested in one shot
        bulk = 50

        i = 0
        project_groups = {}

        while True:
            projects = names[i:i + bulk]

            if projects:
                query_args = "?%s" % "&".join(["project=%s" % p
                                              for p in projects])

                try:
                    ret = self.g.get('access/%s' % query_args)
                except HTTPError as e:
                    return self._manage_errors(e)

                for project in projects:
                    groups_owners_ids = []
                    groups_ids = []
                    perms = ret[project]['local']['refs/*']['permissions']
                    for section, permission in perms.items():
                        if section == "owner":
                            groups_owners_ids.extend(
                                [x for x in permission['rules']])
                        if section != "owner":
                            groups_ids.extend([x for x in permission['rules']])
                    project_groups[project] = {'owners': groups_owners_ids,
                                               'others': groups_ids}
                i += bulk
            else:
                break

        return project_groups

    def get_groups(self):
        try:
            return self.g.get('groups/?')
        except HTTPError as e:
            return self._manage_errors(e)

    def get_project_groups(self, name):
        try:
            name = urllib.quote_plus(name)
            ret = self.g.get('access/?project=%s' % name)
            if 'refs/*' not in ret[name]['local']:
                return []
            perms = ret[name]['local']['refs/*']['permissions']
            groups_ids = []
            groups = []

            for section, permission in perms.items():
                groups_ids.extend([x for x in permission['rules']])
            for group_id in groups_ids:
                gdetails = self.g.get('groups/{}/detail'.format(group_id))
                groups.append(gdetails)

            return groups
        except HTTPError as e:
            return self._manage_errors(e)

    def get_groups_details(self, groups):
        """ Request the group endpoint to get details
        of multiple groups
        """
        assert isinstance(groups, list)
        # It may be require we request the API by splitting the names list
        # If the list is too long to be handled by the Gerrit server (URI)
        query_args = "?%s" % "&".join(["q=%s" % g for g in groups])
        query_args += "&o=MEMBERS" if groups else "o=MEMBERS"

        try:
            ret = self.g.get('groups/%s' % query_args)
        except HTTPError as e:
            return self._manage_errors(e)

        return ret

    # Account related API calls #
    def get_account(self, username):
        try:
            username = urllib.quote_plus(username)
            return self.g.get('accounts/%s' % username)
        except HTTPError as e:
            return self._manage_errors(e)

    def create_account(self, username, user_data):
        try:
            username = urllib.quote_plus(username)
            return self.g.put('accounts/%s' % username,
                              data=json.dumps(user_data))
        except HTTPError as e:
            return self._manage_errors(e)

    def update_account(self, id=None, username=None, **kwargs):
        """Update a gerrit account. Only 'full_name' and 'email' can
        be updated.
        Other optional arguments:
        - no_email_confirmation (default False): set to True to make new email
          the preferred one without user confirmation. Admin only"""
        if not (bool(id) != bool(username)):
            raise TypeError('account id OR username needed')
        if 'full_name' in kwargs.keys():
            try:
                self.g.put('accounts/%s/name' % id or username,
                           data=json.dumps({'name': kwargs['full_name']}))
            except HTTPError as e:
                return self._manage_errors(e)
        if 'email' in kwargs.keys():
            # Note that the user will have to confirm the email and set it
            # as preferred herself in the gerrit interface.
            try:
                url = 'accounts/%s/emails/%s' % (id or username,
                                                 kwargs['email'])
                j = {'email': kwargs['email']}
                if kwargs.get('no_email_confirmation'):
                    j['preferred'] = True
                    j['no_confirmation'] = True
                self.g.put(url,
                           data=json.dumps(j))
            except HTTPError as e:
                if e.response.status_code == 409:
                    # the email already exists, set it as preferred
                    url = url + '/preferred'
                    try:
                        self.g.put(url,
                                   data=json.dumps(j))
                    except HTTPError as ee:
                        return self._manage_errors(ee)
                else:
                    return self._manage_errors(e)
        if not ('full_name' in kwargs.keys() or 'email' in kwargs.keys()):
            raise Exception('Unknown fields')
        return True

    def get_my_groups(self):
        try:
            return self.g.get('accounts/self/groups') or []
        except HTTPError as exp:
            self._manage_errors(exp)
            return []

    def get_user_groups(self, username):
        try:
            username = urllib.quote_plus(username)
            return self.g.get('accounts/%s/groups' % username) or []
        except HTTPError as exp:
            self._manage_errors(exp)
            return []

    def get_all_users(self):
        try:
            return self.g.get('accounts') or []
        except HTTPError as exp:
            self._manage_errors(exp)
            return []

    def get_my_groups_id(self):
        try:
            grps = self.g.get('accounts/self/groups') or []
            return [g['id'] for g in grps]
        except HTTPError as e:
            return self._manage_errors(e)

    def get_user_groups_id(self, username):
        try:
            username = urllib.quote_plus(username)
            grps = self.g.get('accounts/%s/groups' % username) or []
            return [g['id'] for g in grps]
        except HTTPError as e:
            return self._manage_errors(e)

    # Groups related API calls #
    def group_exists(self, name):
        return name in self.g.get('groups/')

    def create_group(self, name, desc):
        data = json.dumps({
            "description": desc,
            "name": name,
            "visible_to_all": True
        })
        try:
            name = urllib.quote_plus(name)
            self.g.put('groups/%s' % name,
                       data=data)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_group_id(self, name):
        try:
            name = urllib.quote_plus(name)
            return self.g.get('groups/%s/detail' % name)['id']
        except HTTPError as e:
            return self._manage_errors(e)

    def get_group_members(self, group_id):
        try:
            group_id = urllib.quote_plus(group_id)
            return self.g.get('groups/%s/members/' % group_id)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_group_member_id(self, group_id, username=None, mail=None):
        resp = self.get_group_members(group_id)
        if not resp:
            # hitting the HTTPError, returning the result of _manage_errors
            return resp
        uid = [None, ]
        # poor man's XOR
        if not (bool(username) ^ bool(mail)):
            raise ValueError("Filter by username OR mail")
        if username:
            uid = [m['_account_id'] for m in resp if
                   m['username'] == username] or uid
        elif mail:
            uid = [m['_account_id'] for m in resp if
                   m['email'] == mail] or uid
        return uid[0]

    def get_group_owner(self, name):
        try:
            name = urllib.quote_plus(name)
            return self.g.get('groups/%s/owner' % name)['owner']
        except HTTPError as e:
            return self._manage_errors(e)

    def member_in_group(self, username, groupname):
        try:
            groupname = urllib.quote_plus(groupname)
            grp = self.g.get('groups/%s/members/%s' % (groupname,
                                                       username))
            return (len(grp) >= 1 and grp['username'] == username)
        except HTTPError as e:
            return self._manage_errors(e)

    def add_group_member(self, username, groupname):
        try:
            username = urllib.quote_plus(username)
            groupname = urllib.quote_plus(groupname)
            self.g.post('groups/%s/members/%s' % (groupname,
                                                  username),
                        headers={})
        except HTTPError as e:
            return self._manage_errors(e)

    def delete_group_member(self, groupname, username):
        try:
            username = urllib.quote_plus(username)
            groupname = urllib.quote_plus(groupname)
            self.g.delete('groups/%s/members/%s' % (groupname,
                                                    username),
                          headers={})
        except HTTPError as e:
            return self._manage_errors(e)

    def add_group_group_member(self, targetgroup, groupname):
        """ Add a group as a member of targetgroup
        """
        try:
            targetgroup = urllib.quote_plus(targetgroup)
            groupname = urllib.quote_plus(groupname)
            self.g.put('groups/%s/groups/%s' % (targetgroup,
                                                groupname),
                       headers={})
        except HTTPError as e:
            return self._manage_errors(e)

    def get_group_group_members(self, group_id):
        """ Get members (only groups) from a group
        """
        try:
            group_id = urllib.quote_plus(group_id)
            return self.g.get('groups/%s/groups/' % group_id)
        except HTTPError as e:
            return self._manage_errors(e)

    def delete_group_group_member(self, targetgroup, groupname):
        """ Delete a group from targetgroup
        """
        try:
            targetgroup = urllib.quote_plus(targetgroup)
            groupname = urllib.quote_plus(groupname)
            self.g.delete('groups/%s/groups/%s' % (targetgroup,
                                                   groupname),
                          headers={})
        except HTTPError as e:
            return self._manage_errors(e)

    # Keys related API calls #
    def add_pubkey(self, pubkey, user='self'):
        headers = {'content-type': 'plain/text'}
        response = self.g.post('accounts/%s/sshkeys' % user,
                               headers=headers,
                               data=pubkey)
        return response['seq']

    def del_pubkey(self, index, user='self'):
        try:
            self.g.delete('accounts/%s/sshkeys/%s' % (user, str(index)),
                          headers={})
        except HTTPError as e:
            return self._manage_errors(e)

    # Changes related API calls #
    def submit_change_note(self, change_id, revision_id, label, rate):
        # Label can be "Code-Review, Verified, Workflow"
        review_input = json.dumps({"labels": {label: int(rate)}})
        try:
            self.g.post('changes/%s/revisions/%s/review' %
                        (change_id, revision_id), data=review_input)
        except HTTPError as e:
            return self._manage_errors(e)

    def submit_patch(self, change_id, revision_id):
        submit = json.dumps({"wait_for_merge": True})
        try:
            ret = self.g.post('changes/%s/revisions/%s/submit' %
                              (change_id, revision_id), data=submit)
            if ret['status'] == 'MERGED':
                return True
            else:
                return False
        except HTTPError as e:
            return self._manage_errors(e)

    def get_reviewer_approvals(self, changeid, reviewer):
        try:
            resp = self.g.get('changes/%s/reviewers/%s' %
                              (changeid, reviewer))
            return resp[0]['approvals']
        except HTTPError as e:
            return self._manage_errors(e)

    def get_reviewers(self, changeid):
        try:
            resp = self.g.get('changes/%s/reviewers' % changeid)
            return [r['username'] for r in resp]
        except HTTPError as e:
            return self._manage_errors(e)

    def get_my_changes_for_project(self, project):
        try:
            changes = self.g.get(
                'changes/?q=owner:self+project:%s' % project)
            return [c['change_id'] for c in changes]
        except HTTPError as e:
            return self._manage_errors(e)

    def get_change(self, project, branch, change_id):
        try:
            changeid = "%s %s %s" % (project, branch, change_id)
            changeid = changeid.replace(' ', '~')
            return self.g.get('changes/%s' % changeid)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_change_last_patchset(self, change_id):
        try:
            return self.g.get('changes/%s/?o=CURRENT_REVISION' % change_id)
        except HTTPError as e:
            return self._manage_errors(e)

    def get_labels_list_for_change(self, change_id):
        try:
            ret = self.g.get('changes/%s/?o=LABELS' % change_id)
            return ret['labels']
        except HTTPError as e:
            return self._manage_errors(e)

    # Plugins related API calls #
    def list_plugins(self):
        ret = self.g.get('plugins/?all')
        return ret.keys()

    def e_d_plugin(self, plugin, mode):
        # mode can be 'enable' or 'disable'
        try:
            response = self.g.post('plugins/%s/gerrit~%s' % (plugin, mode),
                                   headers={})
            return response
        except HTTPError as e:
            return self._manage_errors(e)

    def get_open_changes(self):
        try:
            return self.g.get('changes/?q=status:open')
        except HTTPError as e:
            return self._manage_errors(e)


# Examples
if __name__ == "__main__":
    # logger.setLevel(logging.DEBUG)
    # Call with the SSO cookie
    import sfauth
    c = sfauth.get_cookie('sftests.com', 'admin', 'userpass')
    a = GerritUtils('http://sftests.com', auth_cookie=c)
    # Call with a basic auth
    # from requests.auth import HTTPBasicAuth
    # auth = HTTPBasicAuth('user1', 'userpass')
    # a = GerritUtils('http://sftests.com/api', auth=auth)
    print a.member_in_group('admin', 'config-ptl')
