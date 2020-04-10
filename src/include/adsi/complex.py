from __future__ import absolute_import, division, print_function, unicode_literals
import os.path, sys
import uuid
import re
from subprocess import Popen, PIPE
from syslog import syslog, LOG_INFO, LOG_ERR, LOG_DEBUG, LOG_EMERG, LOG_ALERT
import traceback
from yast import ycpbuiltins
from adcommon.yldap import Ldap, LdapException, stringify_ldap, SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, addlist, modlist

import six

class Connection(Ldap):
    def __init__(self, lp, creds, ldap_url):
        super().__init__(lp, creds, ldap_url=ldap_url)
        self.naming_contexts = self.__naming_contexts()
        self.rootdse = False
        if self.ldap_url.dn == 'Default naming context':
            naming_context = 'defaultNamingContext'
        elif self.ldap_url.dn == 'Configuration':
            naming_context = 'configurationNamingContext'
        elif self.ldap_url.dn == 'Schema':
            naming_context = 'schemaNamingContext'
        elif self.ldap_url.dn == 'RootDSE':
            self.rootdse = True
        else:
            naming_context = self.ldap_url.dn
        if not self.rootdse:
            self.naming_context_name = self.ldap_url.dn
            self.naming_context = self.naming_contexts[naming_context][-1].decode() if naming_context in self.naming_contexts else naming_context

    def __naming_contexts(self):
        attrs = ['configurationNamingContext', 'defaultNamingContext', 'namingContexts', 'rootDomainNamingContext', 'schemaNamingContext']
        res = self.ldap_search_s('', SCOPE_BASE, '(objectclass=*)', attrs)
        if res and len(res) > 0 and len(res[0]) > 1:
            return res[-1][-1]

    def __well_known_container(self, container):
        if strcmp(container, 'system'):
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'computers'):
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'dcs'):
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif strcmp(container, 'users'):
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = self.ldap_search_s('<WKGUID=%s,%s>' % (wkguiduc, self.realm_dn), SCOPE_SUBTREE, '(objectClass=container)', stringify_ldap(['distinguishedName']))
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            return result[0][1]['distinguishedName'][-1]

    def container_inferiors(self, container):
        objectClass = self.obj(container, ['objectClass'])[-1]['objectClass'][-1]
        return self.schema_request_inferior_classes(objectClass)

    def containers(self, container=None):
        if not container:
            container = self.naming_context
        search = '(objectClass=*)'
        ret = self.ldap_search(container, SCOPE_ONELEVEL, search, ['name', 'objectClass'])
        results = []
        for e in ret:
            try:
                if len(self.schema_request_inferior_classes(e[1]['objectClass'][-1])) > 0:
                    results.append((e[0], e[1]['name'][-1]))
            except KeyError:
                pass
        return results

    def objs(self, container=None):
        if not container:
            container = self.naming_context
        search = '(objectClass=*)'
        ret = self.ldap_search(container, SCOPE_ONELEVEL, search, ['name', 'objectClass'])
        return [(e[1]['name'][-1], e[1]['objectClass'][-1], e[0]) for e in ret]

    def obj(self, dn, attrs=[]):
        if six.PY3 and type(dn) is bytes:
            dn = dn.decode('utf-8')
        return self.ldap_search(dn, SCOPE_BASE, '(objectClass=*)', attrs)[-1]

    def objects_list(self, container):
        return self.ldap_search_s(container, SCOPE_ONELEVEL, '(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))', [])

    def add_obj(self, container, attrs):
        dn = 'CN=%s,%s' % (attrs['cn'], container)
        try:
            self.ldap_add(dn, addlist(stringify_ldap(attrs)))
        except LdapException as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.add_s: %s\n' % self.__ldap_exc_msg(e))
        return dn

    def mod_obj(self, dn, old, attrs):
        try:
            self.ldap_modify(dn, modlist(stringify_ldap(old), stringify_ldap(attrs)))
        except LdapException as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.add_s: %s\n' % self.__ldap_exc_msg(e))

