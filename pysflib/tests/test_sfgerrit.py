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
from mock import patch
from mock import Mock
from requests.exceptions import HTTPError
from unittest import TestCase

from pysflib import sfgerrit


def raise_fake_exc(*args, **kwargs):
    e = HTTPError(response=Mock())
    e.response.status_code = 404
    raise e


class TestSFGerritRestAPI(TestCase):

    def test_init(self):
        ge = sfgerrit.SFGerritRestAPI('http://gerrit.tests.dom',
                                      auth_cookie='1234')
        self.assertEqual(ge.url, 'http://gerrit.tests.dom/r/a/')
        expected = {'verify': True,
                    'cookies': {'auth_pubtkt': '1234'},
                    'auth': None,
                    'headers': {'Accept-Encoding': 'gzip',
                                'Accept': 'application/json'}}
        self.assertDictEqual(ge.kwargs, expected)

    def test_verbs_calls(self):
        with patch('pygerrit.rest.requests.session'):
            with patch('pysflib.sfgerrit._decode_response'):
                ge = sfgerrit.SFGerritRestAPI('http://gerrit.tests.dom',
                                              auth_cookie='1234')
                ge.session.get = Mock()
                ge.session.put = Mock()
                ge.session.post = Mock()
                ge.session.delete = Mock()
                ge.get('projects/?')
                self.assertEqual(ge.session.get.call_count, 1)
                ge.put('projects/p1')
                self.assertEqual(ge.session.put.call_count, 1)
                ge.post('projects/p1')
                self.assertEqual(ge.session.post.call_count, 1)
                ge.delete('projects/p1')
                self.assertEqual(ge.session.delete.call_count, 1)


class TestGerritUtils(TestCase):

    @classmethod
    def setupClass(cls):
        cls.ge = sfgerrit.GerritUtils('http://gerrit.tests.dom',
                                      auth_cookie='1234')

    def test_manage_errors(self):
        fake_exc = HTTPError(response=Mock())
        fake_exc.response.status_code = 404
        self.assertFalse(self.ge._manage_errors(fake_exc))
        fake_exc.response.status_code = 409
        self.assertFalse(self.ge._manage_errors(fake_exc))

    def test_project_exists(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get'):
            self.assertTrue(self.ge.project_exists('p1'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.project_exists('p1'))

    def test_create_project(self):
        data = json.dumps({"description": "desc",
                           "create_empty_commit": True,
                           "name": "ns1/pj2",
                           "owners": "ns1/pj2-ptl"})
        with patch('pysflib.sfgerrit.SFGerritRestAPI.put') as g:
            self.assertEqual(self.ge.create_project('ns1/pj2',
                                                    'desc',
                                                    'ns1/pj2-ptl'),
                             None)
            g.assert_called_with('projects/ns1%2Fpj2', data=data)

        with patch('pysflib.sfgerrit.SFGerritRestAPI.put',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.create_project('p1', 'desc', 'p1-ptl'))

    def test_delete_project(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete'):
            self.assertEqual(self.ge.delete_project('ns1\p1'), None)
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.delete_project('p1'))

    def test_get_project(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = 'project'
            self.assertEqual(self.ge.get_project('ns2\p1'), 'project')
            g.assert_called_with('projects/ns2%5Cp1')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_project('p1'))

    def test_get_projects(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'a': None, 'b': None}
            self.assertListEqual(self.ge.get_projects(), ['a', 'b'])
            g.assert_called_with('projects/?')

    def test_get_project_owner(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'p1': {'local': {'refs/*':
                                     {'permissions': {'owner': {'rules':
                                      {'a': None, 'b': None}}}}}}}
            self.assertEqual(self.ge.get_project_owner('p1'), 'a')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_project_owner('p1'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'p1': {'local': {'refs/*':
                                     {'permissions': {'owner': None}}}}}
            self.assertEqual(self.ge.get_project_owner('p1'), None)

    def test_get_project_groups_id(self):
        r1 = json.load(open('test_data/gerrit_access.json'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=[r1]) as g:
            groups = self.ge.get_project_groups_id(['project1'])
            self.assertIn('project1', groups)
            self.assertIn('53a4f647a89ea57992571187d8025f830625192a',
                          groups['project1']['others'])
            self.assertIn('owners', groups['project1'].keys())
            g.assert_called_with('access/?project=project1')

    def test_get_groups_details(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            self.ge.get_groups_details(['p1-ptl', 'p1-core'])
            g.assert_called_with('groups/?q=p1-ptl&q=p1-core&o=MEMBERS')
            self.ge.get_groups_details([])
            g.assert_called_with('groups/?o=MEMBERS')

    def test_get_project_groups(self):
        r1 = json.load(open('test_data/gerrit_access.json'))
        r2 = 'p1-dev'
        r3 = 'p1-ptl'
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=[r1, r2, r3]):
            groups = self.ge.get_project_groups('project1')
            self.assertIn(r2, groups)
            self.assertIn(r3, groups)

        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_project_groups('p1'))

    def test_get_project_groups_without_permission(self):
        r1 = json.load(open('test_data/gerrit_access.json'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=[r1]):
            groups = self.ge.get_project_groups('MyProject')
            self.assertEqual([], groups)

    def test_get_account(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = 'account'
            self.assertEqual(self.ge.get_account('user1'), 'account')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_account('user1'))

    def test_create_account(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.put') as p:
            p.return_value = 'account'
            self.assertEqual(self.ge.create_account('user1', {}), 'account')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.put',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.create_account('user1', {}))

    def test_get_my_groups(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {
                "Administrators": {
                    "id": "6a1e70e1a88782771a91808c8af9bbb7a9871389",
                    "url": "#/admin/groups/uuid-6a1e70e1a88782771a91808c",
                    "options": {},
                    "description": "Gerrit Site Administrators",
                    "group_id": 1,
                    "owner": "Administrators",
                    "owner_id": "6a1e70e1a88782771a91808c8af9bbb7a9871389"
                },
                "Anonymous Users": {
                    "id": "global%3AAnonymous-Users",
                    "url": "#/admin/groups/uuid-global%3AAnonymous-Users",
                    "options": {},
                    "description": "Any user, signed-in or not",
                    "group_id": 2,
                    "owner": "Administrators",
                    "owner_id": "6a1e70e1a88782771a91808c8af9bbb7a9871389"
                }}
            self.assertTrue(self.ge.get_my_groups())
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_my_groups())

    def test_get_my_groups_id(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'id': 1}, {'id': 2}]
            self.assertListEqual(self.ge.get_my_groups_id(), [1, 2])
            g.assert_called_with('accounts/self/groups')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_my_groups_id())

    def test_get_user_groups(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {
                "Administrators": {
                    "id": "6a1e70e1a88782771a91808c8af9bbb7a9871389",
                    "url": "#/admin/groups/uuid-6a1e70e1a88782771a91808c",
                    "options": {},
                    "description": "Gerrit Site Administrators",
                    "group_id": 1,
                    "owner": "Administrators",
                    "owner_id": "6a1e70e1a88782771a91808c8af9bbb7a9871389"
                },
                "Anonymous Users": {
                    "id": "global%3AAnonymous-Users",
                    "url": "#/admin/groups/uuid-global%3AAnonymous-Users",
                    "options": {},
                    "description": "Any user, signed-in or not",
                    "group_id": 2,
                    "owner": "Administrators",
                    "owner_id": "6a1e70e1a88782771a91808c8af9bbb7a9871389"
                }}
            self.assertTrue(self.ge.get_user_groups('toto'))
            g.assert_called_with('accounts/%s/groups' % 'toto')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_user_groups('bobobo'))

    def test_get_user_groups_id(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'id': 1}, {'id': 2}]
            self.assertListEqual(self.ge.get_user_groups_id('toto'), [1, 2])
            g.assert_called_with('accounts/%s/groups' % 'toto')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_user_groups_id('blipblop'))

    def test_groups_exists(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = ['p1-ptl', 'p2-ptl']
            self.assertTrue(self.ge.group_exists('p2-ptl'))

        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = ['ns\p1-ptl', 'ns\p1-dev']
            self.assertTrue(self.ge.group_exists('ns\p1-dev'))
            g.assert_called_with('groups/')

    def test_create_group(self):
        data = json.dumps({"visible_to_all": True,
                           "description": "desc",
                           "name": "p1-ptl"})
        with patch('pysflib.sfgerrit.SFGerritRestAPI.put') as g:
            self.assertEqual(self.ge.create_group('p1-ptl', 'desc'), None)
            g.assert_called_with('groups/p1-ptl', data=data)

        data = json.dumps({"visible_to_all": True,
                           "description": "desc",
                           "name": "ns1\\prj1-dev"})
        with patch('pysflib.sfgerrit.SFGerritRestAPI.put') as g:
            self.assertEqual(self.ge.create_group('ns1\\prj1-dev', 'desc'),
                             None)
            g.assert_called_with('groups/ns1%5Cprj1-dev', data=data)

        with patch('pysflib.sfgerrit.SFGerritRestAPI.put',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.create_group('p1-ptl', 'desc'))

    def test_get_group_id(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'id': 1}
            self.assertEqual(self.ge.get_group_id('p1-ptl'), 1)
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_group_id('p1-ptl'))

    def test_get_group_member_id(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'_account_id': 1, 'username': 'user1'}]
            self.assertEqual(self.ge.get_group_member_id('p1-ptl', 'user1'), 1)
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_group_member_id('p1-ptl', 'user1'))

    def test_get_group_members(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            members = [{'_account_id': 1, 'username': 'user1'}]
            g.return_value = members
            self.assertEqual(self.ge.get_group_members('p1-ptl'),
                             members)

    def test_get_group_owner(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'owner': 'user1'}
            self.assertEqual(self.ge.get_group_owner('p1-ptl'), 'user1')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_group_owner('p1-ptl'))

    def test_member_in_group(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'username': 'user1'}
            self.assertTrue(self.ge.member_in_group('user1', 'p1-ptl'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.member_in_group('user1', 'p1-ptl'))

    def test_add_group_member(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post') as g:
            self.assertEqual(self.ge.add_group_member('user1', 'p1-ptl'), None)
            g.assert_called_with('groups/p1-ptl/members/user1', headers={})

        with patch('pysflib.sfgerrit.SFGerritRestAPI.post') as g:
            self.assertEqual(self.ge.add_group_member('u1', 'n3/p2-ptl'),
                             None)
            g.assert_called_with('groups/n3%2Fp2-ptl/members/u1',
                                 headers={})
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.add_group_member('user1', 'p1-ptl'))

    def test_delete_group_member(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete'):
            self.assertEqual(self.ge.delete_group_member('p1-ptl', 'user1'),
                             None)
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.delete_group_member('p1-ptl', 'user1'))

    def test_add_pubkey(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post') as p:
            p.return_value = {'seq': 1}
            self.assertEqual(self.ge.add_pubkey('rsa ...'), 1)
            p.assert_called_with('accounts/self/sshkeys',
                                 headers={'content-type': 'plain/text'},
                                 data='rsa ...')
            self.assertEqual(self.ge.add_pubkey('rsa ...', user='joe'), 1)
            p.assert_called_with('accounts/joe/sshkeys',
                                 headers={'content-type': 'plain/text'},
                                 data='rsa ...')

    def test_del_pubkey(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete') as d:
            self.assertEqual(self.ge.del_pubkey(1), None)
            d.assert_called_with('accounts/self/sshkeys/1',
                                 headers={})
            self.assertEqual(self.ge.del_pubkey(1, user='bob'), None)
            d.assert_called_with('accounts/bob/sshkeys/1',
                                 headers={})
        with patch('pysflib.sfgerrit.SFGerritRestAPI.delete',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.del_pubkey(1))

    def test_submit_change_note(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post'):
            self.assertEqual(
                self.ge.submit_change_note('1', '1', 'Verified', 2), None)
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post',
                   side_effect=raise_fake_exc):
            self.assertFalse(
                self.ge.submit_change_note('1', '1', 'Verified', 2))

    def test_submit_patch(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post') as p:
            p.return_value = {'status': 'MERGED'}
            self.assertEqual(self.ge.submit_patch('1', '1'), True)
            p.return_value = {'status': 'OPEN'}
            self.assertFalse(self.ge.submit_patch('1', '1'))
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.submit_patch('1', '1'))

    def test_get_reviewer_approvals(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'approvals': 'app'}]
            self.assertEqual(
                self.ge.get_reviewer_approvals('1', 'jenkins'), 'app')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_reviewer_approvals('1', 'jenkins'))

    def test_get_reviewers(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'username': 'user1'}]
            self.assertListEqual(self.ge.get_reviewers('1'), ['user1'])
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_reviewers('1'))

    def test_get_my_changes_for_project(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = [{'change_id': '123'}]
            self.assertListEqual(
                self.ge.get_my_changes_for_project('p1'), ['123'])
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_my_changes_for_project('p1'))

    def test_get_change(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = '123'
            self.assertEqual(self.ge.get_change('p1', 'master', '123'), '123')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_change('p1', 'master', '123'))

    def test_get_change_last_patchset(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = 'b'
            self.assertEqual(self.ge.get_change_last_patchset('123'), 'b')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_change_last_patchset('123'))

    def test_get_labels_list_for_change(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'labels': 'b'}
            self.assertEqual(self.ge.get_labels_list_for_change('123'), 'b')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.get_labels_list_for_change('123'))

    def test_list_plugins(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.get') as g:
            g.return_value = {'delete-project': '', 'gravatar': ''}
            self.assertListEqual(
                sorted(self.ge.list_plugins()), ['delete-project', 'gravatar'])

    def test_e_d_plugin(self):
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post') as p:
            p.return_value = 'plugin'
            self.assertEqual(
                self.ge.e_d_plugin('gravatar', 'enable'), 'plugin')
        with patch('pysflib.sfgerrit.SFGerritRestAPI.post',
                   side_effect=raise_fake_exc):
            self.assertFalse(self.ge.e_d_plugin('gravatar', 'enable'))
