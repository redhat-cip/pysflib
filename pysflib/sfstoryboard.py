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


from storyboardclient.v1.client import Client as StoryboardClient
import urllib


class SFStoryboard(StoryboardClient):
    def __init__(self, api_url, auth_cookie):
        uid = filter(lambda x: x.startswith('uid='),
                     urllib.unquote(auth_cookie).split(';'))[0].split('=')[1]
        super(SFStoryboard, self).__init__(api_url=api_url, access_token=uid)
        self.http_client.http.cookies['auth_pubtkt'] = auth_cookie


if __name__ == "__main__":
    import sfauth
    c = sfauth.get_cookie('sftests.com', 'admin', 'userpass')
    s = SFStoryboard("https://sftests.com/storyboard_api", c)
    s.stories.list()
