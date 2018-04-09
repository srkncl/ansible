from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError

try:
    import thycotic
except ImportError:
    raise AnsibleError("The lookup ss requires thycotic wrapper.")

from ansible.plugins import AnsiblePlugin
from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text
import os

def _get_user(ss, secretid):
    data = ss.getsecretslug(secretid, s_slug='username').encode('utf8')
    return data 

def _get_password(ss, secretid):
    data = ss.getsecretslug(secretid, s_slug='password').encode('utf8')
    return data

class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        
        ret = []
        lookup_type = kwargs.get('type', False)
        match_user = kwargs.get('user', False)

        username = os.getenv('SS_USERNAME', '')
        password = os.getenv('SS_PASSWORD', '')
        host = os.getenv('SS_HOST', '')
        ss = thycotic.ThycoticWrapper(host=host, username=username, password=password)
        try:
            ss.login()
            secrets = ss.getsecretbysearch(query=terms[0])
            if match_user:
                for secret in secrets['records']:
                    record_user = _get_user(ss, str(secret['id']))
                    if match_user == record_user:
                        if lookup_type == 'username':
                            record = record_user
                        if lookup_type == 'password':
                            record = _get_password(ss, str(secret['id'])) 
                    else:
                        raise AnsibleError("Username not found in password safe")
            else:
                if lookup_type == 'username':
                    record = _get_user(ss, secretid=str(secrets['records'][0]['id']))
                if lookup_type == 'password':
                    record = _get_password(ss, secretid=str(secrets['records'][0]['id']))
        except Exception as e:
             raise AnsibleError(e)
        ret.append(record)
        return ret
