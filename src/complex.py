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
        self.realm_dn = self.realm_to_dn(self.realm)
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
        self.schema = {}
        self.__load_schema()

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

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

    def __find_inferior_classes(self, name):
        dn = 'CN=Schema,CN=Configuration,%s' % self.realm_dn
        search = '(|(possSuperiors=%s)(systemPossSuperiors=%s))' % (name, name)
        return [item[-1]['lDAPDisplayName'][-1] for item in self.ldap_search_s(dn, SCOPE_SUBTREE, search, ['lDAPDisplayName'])]

    def __load_schema(self):
        dn = self.l.search_subschemasubentry_s()
        results = self.l.read_subschemasubentry_s(dn)

        self.schema['attributeTypes'] = {}
        self.schema['constructedAttributes'] = self.__constructed_attributes()
        for attributeType in results['attributeTypes']:
            m = re.match(b'\(\s+(?P<id>[0-9\.]+)\s+NAME\s+\'(?P<name>[\-\w]+)\'\s+(SYNTAX\s+\'(?P<syntax>[0-9\.]+)\'\s+)?(?P<info>.*)\)', attributeType)
            if m:
                name = m.group('name')
                self.schema['attributeTypes'][name] = {}
                self.schema['attributeTypes'][name]['id'] = m.group('id')
                self.schema['attributeTypes'][name]['syntax'] = m.group('syntax')
                self.schema['attributeTypes'][name]['multi-valued'] = b'SINGLE-VALUE' not in m.group('info')
                self.schema['attributeTypes'][name]['collective'] = b'COLLECTIVE' in m.group('info')
                self.schema['attributeTypes'][name]['user-modifiable'] = b'NO-USER-MODIFICATION' not in m.group('info')
                if b'USAGE' in m.group('info'):
                    usage = re.findall(b'.*\s+USAGE\s+(\w+)', m.group('info'))
                    self.schema['attributeTypes'][name]['usage'] = usage[-1] if usage else 'userApplications'
                else:
                    self.schema['attributeTypes'][name]['usage'] = 'userApplications'
            else:
                raise ldap.LDAPError('Failed to parse attributeType: %s' % attributeType.decode())

        self.schema['objectClasses'] = {}
        for objectClass in results['objectClasses']:
            m = re.match(b'\(\s+(?P<id>[0-9\.]+)\s+NAME\s+\'(?P<name>[\-\w]+)\'\s+(SUP\s+(?P<superior>[\-\w]+)\s+)?(?P<type>\w+)\s+(MUST\s+\((?P<must>[^\)]*)\)\s+)?(MAY\s+\((?P<may>[^\)]*)\)\s+)?\)', objectClass)
            if m:
                name = m.group('name')
                self.schema['objectClasses'][name] = {}
                self.schema['objectClasses'][name]['id'] = m.group('id')
                self.schema['objectClasses'][name]['superior'] = m.group('superior')
                self.schema['objectClasses'][name]['inferior'] = self.__find_inferior_classes(name.decode())
                self.schema['objectClasses'][name]['type'] = m.group('type')
                self.schema['objectClasses'][name]['must'] = m.group('must').strip().split(b' $ ') if m.group('must') else []
                self.schema['objectClasses'][name]['may'] = m.group('may').strip().split(b' $ ') if m.group('may') else []
            else:
                raise ldap.LDAPError('Failed to parse objectClass: %s' % objectClass.decode())

        self.schema['dITContentRules'] = {}
        for dITContentRule in results['dITContentRules']:
            m = re.match(b'\(\s+(?P<id>[0-9\.]+)\s+NAME\s+\'(?P<name>[\-\w]+)\'\s*(AUX\s+\((?P<aux>[^\)]*)\))?\s*(MUST\s+\((?P<must>[^\)]*)\)\s+)?\s*(MAY\s+\((?P<may>[^\)]*)\))?\s*(NOT\s+\((?P<not>[^\)]*)\))?\s*\)', dITContentRule)
            if m:
                name = m.group('name')
                self.schema['dITContentRules'][name] = {}
                self.schema['dITContentRules'][name]['id'] = m.group('id')
                self.schema['dITContentRules'][name]['must'] = m.group('must').strip().split(b' $ ') if m.group('must') else []
                self.schema['dITContentRules'][name]['may'] = m.group('may').strip().split(b' $ ') if m.group('may') else []
                self.schema['dITContentRules'][name]['aux'] = m.group('aux').strip().split(b' $ ') if m.group('aux') else []
                self.schema['dITContentRules'][name]['not'] = m.group('not').strip().split(b' $ ') if m.group('not') else []
            else:
                raise ldap.LDAPError('Failed to parse dITContentRule: %s' % dITContentRule.decode())

    def __constructed_attributes(self):
        # ADSI Hides constructed attributes, since they can't be modified.
        search = '(&(systemFlags:1.2.840.113556.1.4.803:=4)(ObjectClass=attributeSchema))'
        container = 'CN=Schema,CN=Configuration,%s' % self.realm_dn
        ret = self.ldap_search(container, SCOPE_ONELEVEL, search, ['lDAPDisplayName'])
        return [a[-1]['lDAPDisplayName'][-1] for a in ret]

    def container_inferiors(self, container):
        objectClass = self.obj(container, ['objectClass'])[-1]['objectClass'][-1]
        return self.schema['objectClasses'][objectClass]['inferior']

    def containers(self, container=None):
        if not container:
            container = self.naming_context
        search = '(objectClass=*)'
        ret = self.ldap_search(container, SCOPE_ONELEVEL, search, ['name', 'objectClass'])
        results = []
        for e in ret:
            try:
                if len(self.schema['objectClasses'][e[1]['objectClass'][-1]]['inferior']) > 0:
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

