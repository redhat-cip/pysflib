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

from unittest import TestCase
from mock import patch

from redmine.exceptions import ResourceNotFoundError
from pysflib import sfredmine


def raisenotfound(*args, **kwargs):
    raise ResourceNotFoundError()


class FakeRes:
    status = 'Open'
    id = 1
    name = 'Open'
    firstname = 'user1'
    lastname = 'TotoMan'
    login = 'user1'
    mail = 'toto@example.com'

    def __getitem__(self, n):
        return getattr(self, n)


def fake_resource(*args, **kwargs):
    return FakeRes()


class TestSFRedmine(TestCase):
    @classmethod
    def setupClass(cls):
        cls.rm = sfredmine.RedmineUtils('http://fake.fake', key='1234')

    def test_project_exists(self):
        with patch('redmine.managers.ResourceManager.get'):
            self.assertTrue(self.rm.project_exists('p1'))
        with patch('redmine.managers.ResourceManager.get') as g:
            self.assertTrue(self.rm.project_exists('ns1/p1'))
            g.assert_called_with('ns1_p1')
        with patch('redmine.managers.ResourceManager.get',
                   side_effect=raisenotfound):
            self.assertFalse(self.rm.project_exists('p1'))

    def test_get_issue_status(self):
        with patch('redmine.managers.ResourceManager.get',
                   new_callable=lambda: fake_resource):
            self.assertEqual('Open', self.rm.get_issue_status(12))
        with patch('redmine.managers.ResourceManager.get',
                   side_effect=raisenotfound):
            self.assertEqual(None, self.rm.get_issue_status(12))

    def test_get_issues_by_project(self):
        def my_fake_resource(*args, **kwargs):
            class Fake:
                issues = [FakeRes(), FakeRes()]
            return Fake()
        with patch('redmine.managers.ResourceManager.get',
                   new_callable=lambda: my_fake_resource):
            self.assertListEqual([1, 1], self.rm.get_issues_by_project('p1'))
        with patch('redmine.managers.ResourceManager.get') as g:
            self.rm.get_issues_by_project('ns2/p2')
            g.assert_called_with('ns2_p2')
        with patch('redmine.managers.ResourceManager.get',
                   side_effect=raisenotfound):
            self.assertEqual(None, self.rm.get_issues_by_project('p1'))

    def test_set_issue_status(self):
        with patch('redmine.managers.ResourceManager.update') as u:
            u.return_value = True
            self.rm.set_issue_status(1, 2, message='new note')
        with patch('redmine.managers.ResourceManager.update',
                   side_effect=raisenotfound):
            self.assertEqual(None,
                             self.rm.set_issue_status(1, 2,
                                                      message='new note'))

    def test_test_issue_status(self):
        with patch('pysflib.sfredmine.RedmineUtils.get_issue_status',
                   new_callable=lambda: fake_resource):
            self.assertTrue(self.rm.test_issue_status(12, 'Open'))
            self.assertFalse(self.rm.test_issue_status(12, 'Closed'))

    def test_create_issue(self):
        with patch('redmine.managers.ResourceManager.create',
                   new_callable=lambda: fake_resource):
            self.assertEqual(1, self.rm.create_issue('myissue'))

    def test_delete_issue(self):
        with patch('redmine.managers.ResourceManager.delete') as d:
            d.return_value = True
            self.assertTrue(self.rm.delete_issue(1))
        with patch('redmine.managers.ResourceManager.delete',
                   side_effect=raisenotfound):
            self.assertFalse(self.rm.delete_issue(1))

    def test_create_user(self):
        with patch('redmine.managers.ResourceManager.create') as c:
            self.rm.create_project('john', 'john@tests.dom', 'John Doe')
            self.assertTrue(c.called)

    def test_create_project(self):
        with patch('redmine.managers.ResourceManager.create') as c:
            self.rm.create_project('myissue', '', False)
            self.assertTrue(c.called)

    def test_create_project_with_different_name(self):
        with patch('redmine.managers.ResourceManager.create') as cc:
            self.rm.create_project('SF test project', '', False)
            self.assertTrue(cc.called)
            cc.assert_called_with(description='',
                                  identifier='sf-test-project',
                                  is_public='true',
                                  name='SF test project')

    def test_create_project_with_antislash(self):
        with patch('redmine.managers.ResourceManager.create') as cc:
            self.rm.create_project('SF/project', '', False)
            self.assertTrue(cc.called)
            cc.assert_called_with(description='',
                                  identifier='sf_project',
                                  is_public='true',
                                  name='SF/project')

    def test_check_user_role(self):
        def my_fake_resource(*args, **kwargs):
            class Fake:
                user = FakeRes()
                roles = [FakeRes(), FakeRes()]
            return [Fake()]
        with patch('redmine.managers.ResourceManager.filter',
                   new_callable=lambda: my_fake_resource):
            with patch('redmine.managers.ResourceManager.get',
                       new_callable=lambda: fake_resource):
                self.assertTrue(self.rm.check_user_role('p1', 'user1', 'Open'))
                self.assertFalse(self.rm.check_user_role('p1', 'user1', 'A'))

    def test_get_user_id(self):
        def my_fake_resource(*args, **kwargs):
            return [FakeRes(), FakeRes()]
        with patch('redmine.managers.ResourceManager.filter',
                   new_callable=lambda: my_fake_resource):
            self.assertEqual(1, self.rm.get_user_id('toto@example.com'))
            self.assertEqual(None, self.rm.get_user_id('toto2@example.com'))

    def test_get_role_id(self):
        def my_fake_resource(*args, **kwargs):
            return [FakeRes(), FakeRes()]
        with patch('redmine.managers.ResourceManager.all',
                   new_callable=lambda: my_fake_resource):
            self.assertEqual(1, self.rm.get_role_id('Open'))
            self.assertEqual(None, self.rm.get_role_id('A'))

    def test_get_project_membership_for_user(self):
        def my_fake_resource(*args, **kwargs):
            class Fake:
                user = FakeRes()
                id = 1
            return [Fake(), Fake()]
        with patch('redmine.managers.ResourceManager.filter',
                   new_callable=lambda: my_fake_resource):
            self.assertEqual(
                1,
                self.rm.get_project_membership_for_user('p1', 1))
            self.assertEqual(
                None,
                self.rm.get_project_membership_for_user('p1', 2))

    def test_get_project_roles_for_user(self):
        def my_fake_resource(*args, **kwargs):
            class Fake:
                roles = [FakeRes(), FakeRes()]
            return Fake()
        with patch(
                'pysflib.sfredmine.RedmineUtils.'
                'get_project_membership_for_user'):
            with patch('redmine.managers.ResourceManager.get',
                       new_callable=lambda: my_fake_resource):
                self.assertListEqual(
                    ['Open', 'Open'],
                    self.rm.get_project_roles_for_user('p1', 1))
            with patch('redmine.managers.ResourceManager.get',
                       side_effect=raisenotfound):
                self.assertListEqual(
                    [],
                    self.rm.get_project_roles_for_user('p1', 1))

    def test_update_membership(self):
        with patch('redmine.managers.ResourceManager.update') as u:
            u.return_value = True
            self.assertTrue(self.rm.update_membership('p1', {}))
        with patch('redmine.managers.ResourceManager.update',
                   side_effect=raisenotfound):
            self.assertEqual(None, self.rm.update_membership('p1', {}))

    def test_update_project_membership(self):
        with patch('redmine.managers.ResourceManager.create') as c:
            self.rm.update_project_membership('p1',
                                              [{'user_id': '', 'role_ids': ''},
                                               {'user_id': '', 'role_ids': ''}
                                               ])
            self.assertEqual(2, len(c.mock_calls))

    def test_delete_membership(self):
        with patch('redmine.managers.ResourceManager.delete') as d:
            d.return_value = True
            self.assertTrue(self.rm.delete_membership(1))
        with patch('redmine.managers.ResourceManager.delete',
                   side_effect=raisenotfound):
            self.assertFalse(self.rm.delete_membership(1))

    def test_delete_project(self):
        with patch('redmine.managers.ResourceManager.delete') as d:
            d.return_value = True
            self.assertTrue(self.rm.delete_project('p1'))
        with patch('redmine.managers.ResourceManager.delete',
                   side_effect=raisenotfound):
            self.assertFalse(self.rm.delete_project('p1'))

    def test_get_active_users(self):
        def my_fake_resource(*args, **kwargs):
            return [FakeRes()]
        with patch('redmine.managers.ResourceManager.filter',
                   new_callable=lambda: my_fake_resource):
            self.assertEqual([('user1', 'toto@example.com', 'user1 TotoMan')],
                             self.rm.active_users())

    def test_create_group(self):
        with patch('redmine.managers.ResourceManager.create') as c:
            self.rm.create_group('mygroup')
            self.assertTrue(c.called)

    def test_list_group(self):
        with patch('redmine.managers.ResourceManager.get') as c:
            self.rm.list_group('mygroup')
            self.assertTrue(c.called)

    def test_delete_group(self):
        with patch('redmine.managers.ResourceManager.delete') as c:
            self.rm.delete_group('12')
            self.assertTrue(c.called)

    def test_get_group_id(self):
        def my_fake_resource(*args, **kwargs):
            return [FakeRes()]
        with patch('redmine.managers.ResourceManager.all',
                   new_callable=lambda: my_fake_resource):
            self.assertEqual(1, self.rm.get_group_id('Open'))
            self.assertEqual(None, self.rm.get_group_id('Test'))

    def test_set_group_members(self):
        with patch('redmine.managers.ResourceManager.update') as c:
            self.rm.set_group_members(1, [3, 4, 5])
            self.assertTrue(c.called)
