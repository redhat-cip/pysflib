# Copyright (C) 2016 Red Hat <licensing@enovance.com>
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


class IssueTrackerUtils:
    """ Generic interface for utilities classes related to issue trackers
    used in Software Factory.
    """
    def __init__(self, *args, **kwargs):
        """used mainly to initialize a client to the tracker."""
        raise NotImplementedError

    def project_exists(self, name):
        """checks whether a project exists or not, returns a boolean"""
        raise NotImplementedError

    def get_issue_status(self, issueid):
        """gets issue status, returns a status (redmine-like) or None"""
        raise NotImplementedError

    def get_open_issues(self):
        """gets open issues"""
        raise NotImplementedError

    def get_issues_by_project(self, name):
        """gets issue status, returns a list of issues ids or None"""
        raise NotImplementedError

    def test_issue_status(self, issueid, status):
        """gets issue status, returns a status (redmine-like) or None"""
        raise NotImplementedError

    def set_issue_status(self, iid, status_id, message=None):
        """gets issue status, returns a status (redmine-like) or None"""
        raise NotImplementedError

    def create_issue(self, name, subject=''):
        """creates issue, returns a issue id or None"""
        raise NotImplementedError

    def delete_issue(self, issueid):
        """gets issue status, returns None in case of """
        raise NotImplementedError

    def check_user_role(self, name, username, role):
        """checks that user has given role, returns boolean"""
        raise NotImplementedError

    def create_project(self, name, description, private):
        """creates a project, returns nothing"""
        raise NotImplementedError

    def create_user(self, username, email, lastname):
        """creates user, returns user id"""
        raise NotImplementedError

    def get_user_id(self, mail):
        """gets user id by email, returns id or None"""
        raise NotImplementedError

    def get_user_id_by_username(self, username):
        """gets user id by username, returns id or None"""
        raise NotImplementedError

    def get_role_id(self, name):
        """gets role id by name, returns id or None"""
        raise NotImplementedError

    def get_role(self, id):
        """gets role by id, returns id or None"""
        raise NotImplementedError

    def get_projects(self):
        """gets list of projects"""
        raise NotImplementedError

    def get_project_membership_for_user(self, pname, uid):
        """gets membership id or None"""
        raise NotImplementedError

    def get_project_roles_for_user(self, pname, uid):
        """returns a list of roles"""
        raise NotImplementedError

    def update_membership(self, mid, role_ids):
        """returns id or None"""
        raise NotImplementedError

    def update_project_membership(self, pname, memberships):
        """returns Nothing"""
        raise NotImplementedError

    def delete_membership(self, id):
        """returns Nothing or None"""
        raise NotImplementedError

    def delete_project(self, pname):
        """returns Nothing or None"""
        raise NotImplementedError

    def active_users(self):
        """returns a list of (login, mail, full name) or None"""
        raise NotImplementedError

    def get_sf_projects_url(self):
        """return the tracker's projects homepage url"""
        raise NotImplementedError

    def get_root_url(self):
        """return the tracker's root url"""
        raise NotImplementedError

    def test_static_file(self):
        raise NotImplementedError
