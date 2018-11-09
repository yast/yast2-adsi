#!/usr/bin/env python

from __future__ import absolute_import, division, print_function, unicode_literals
import ldap, ldap.modlist, ldap.sasl
import os.path, sys
from samba.net import Net
from samba.dcerpc import nbt
import uuid
import re
from subprocess import Popen, PIPE
from syslog import syslog, LOG_INFO, LOG_ERR, LOG_DEBUG, LOG_EMERG, LOG_ALERT
from ldap.modlist import addModlist as addlist
from ldap.modlist import modifyModlist as modlist
import traceback
from yast import ycpbuiltins
from samba.credentials import Credentials, MUST_USE_KERBEROS

import six

def y2error_dialog(msg):
    from yast import UI, Opt, HBox, HSpacing, VBox, VSpacing, Label, Right, PushButton, Id
    if six.PY3 and type(msg) is bytes:
        msg = msg.decode('utf-8')
    ans = False
    UI.SetApplicationTitle('Error')
    UI.OpenDialog(Opt('warncolor'), HBox(HSpacing(1), VBox(
        VSpacing(.3),
        Label(msg),
        Right(HBox(
            PushButton(Id('ok'), 'OK')
        )),
        VSpacing(.3),
    ), HSpacing(1)))
    ret = UI.UserInput()
    if str(ret) == 'ok' or str(ret) == 'abort' or str(ret) == 'cancel':
        UI.CloseDialog()

def strcmp(first, second):
    if six.PY3:
        if isinstance(first, six.string_types):
            first = six.binary_type(first, 'utf8')
        if isinstance(second, six.string_types):
            second = six.binary_type(second, 'utf8')
    return first == second

def strcasecmp(first, second):
    if six.PY3:
        if isinstance(first, six.string_types):
            first = six.binary_type(first, 'utf8')
        if isinstance(second, six.string_types):
            second = six.binary_type(second, 'utf8')
    return first.lower() == second.lower()

class LdapException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        if len(self.args) > 0:
            self.msg = self.args[0]
        else:
            self.msg = None
        if len(self.args) > 1:
            self.info = self.args[1]
        else:
            self.info = None

def stringify_ldap(data):
    if type(data) == dict:
        for key, value in data.items():
            data[key] = stringify_ldap(value)
        return data
    elif type(data) == list:
        new_list = []
        for item in data:
            new_list.append(stringify_ldap(item))
        return new_list
    elif type(data) == tuple:
        new_tuple = []
        for item in data:
            new_tuple.append(stringify_ldap(item))
        return tuple(new_tuple)
    elif six.PY2 and type(data) == unicode:
        return str(data)
    elif six.PY3 and isinstance(data, six.string_types):
        return data.encode('utf-8') # python3-ldap requires a bytes type
    else:
        return data

# 09/21/2018 03:48:36  09/21/2018 13:48:36  ldap/win-dw0ohw3xqb9.froggy.suse.de@
def validate_kinit(creds):
    out, _ = Popen(['klist'], stdout=PIPE, stderr=PIPE).communicate()
    m = re.findall(six.b('Default principal:\s*(\w+)@([\w\.]+)'), out)
    if len(m) == 0:
        return None
    user, realm = m[0]
    if not strcasecmp(user, creds.get_username()):
        return None
    if Popen(['klist', '-s'], stdout=PIPE, stderr=PIPE).wait() != 0:
        return None
    creds.set_kerberos_state(MUST_USE_KERBEROS)

    return creds

class Connection:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        self.realm = lp.get('realm')
        self.realm_dn = self.realm_to_dn(self.realm)
        self.__ldap_connect()
        self.schema = {}
        self.__load_schema()

    def __kinit_for_gssapi(self):
        p = Popen(['kinit', '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()], stdin=PIPE, stdout=PIPE)
        p.stdin.write(('%s\n' % self.creds.get_password()).encode())
        p.stdin.flush()
        return p.wait() == 0

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        if strcmp(container, 'system'):
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'computers'):
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'dcs'):
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif strcmp(container, 'users'):
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = self.ldap_search_s('<WKGUID=%s,%s>' % (wkguiduc, self.realm_dn), ldap.SCOPE_SUBTREE, '(objectClass=container)', stringify_ldap(['distinguishedName']))
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            return result[0][1]['distinguishedName'][-1]

    def __find_inferior_classes(self, name):
        dn = 'CN=Schema,CN=Configuration,%s' % self.realm_dn
        search = '(|(possSuperiors=%s)(systemPossSuperiors=%s))' % (name, name)
        return [item[-1]['lDAPDisplayName'][-1] for item in self.ldap_search_s(dn, ldap.SCOPE_SUBTREE, search, ['lDAPDisplayName'])]

    def __load_schema(self):
        dn = self.l.search_subschemasubentry_s()
        results = self.l.read_subschemasubentry_s(dn)

        self.schema['attributeTypes'] = {}
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

    def containers(self, container=None):
        if not container:
            container = self.realm_dn
        search = '(objectClass=*)'
        ret = self.ldap_search(container, ldap.SCOPE_ONELEVEL, search, ['name', 'objectClass'])
        results = []
        for e in ret:
            if len(self.schema['objectClasses'][e[1]['objectClass'][-1]]['inferior']) > 0:
                results.append((e[0], e[1]['name'][-1]))
        return results

    def objs(self, container=None):
        if not container:
            container = self.realm_dn
        search = '(objectClass=*)'
        ret = self.ldap_search(container, ldap.SCOPE_ONELEVEL, search, ['name', 'objectClass'])
        return [(e[1]['name'][-1], e[1]['objectClass'][-1], e[0]) for e in ret]

    def obj(self, dn, attrs=[]):
        if six.PY3 and type(dn) is bytes:
            dn = dn.decode('utf-8')
        return self.ldap_search(dn, ldap.SCOPE_BASE, '(objectClass=*)', attrs)[-1]

    def objects_list(self, container):
        return self.ldap_search_s(container, ldap.SCOPE_ONELEVEL, '(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))', [])

    def __ldap_exc_msg(self, e):
        if len(e.args) > 0 and \
          type(e.args[-1]) is dict and \
          'desc' in e.args[-1]:
            return e.args[-1]['desc']
        else:
            return str(e)

    def __ldap_exc_info(self, e):
        if len(e.args) > 0 and \
          type(e.args[-1]) is dict and \
          'info' in e.args[-1]:
            return e.args[-1]['info']
        else:
            return ''

    def __ldap_connect(self):
        self.net = Net(creds=self.creds, lp=self.lp)
        cldap_ret = self.net.finddc(domain=self.realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        self.l = ldap.initialize('ldap://%s' % cldap_ret.pdc_dns_name)
        if self.creds.get_kerberos_state() == MUST_USE_KERBEROS or self.__kinit_for_gssapi():
            auth_tokens = ldap.sasl.gssapi('')
            self.l.sasl_interactive_bind_s('', auth_tokens)
        else:
            ycpbuiltins.y2error('Failed to initialize ldap connection')

    def ldap_search_s(self, *args):
        try:
            try:
                return self.l.search_s(*args)
            except ldap.SERVER_DOWN:
                self.__ldap_connect()
                return self.l.search_s(*args)
        except ldap.LDAPError as e:
            y2error_dialog(self.__ldap_exc_msg(e))
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.search_s: %s\n' % self.__ldap_exc_msg(e))

    def ldap_search(self, *args):
        result = []
        try:
            try:
                res_id = self.l.search(*args)
            except ldap.SERVER_DOWN:
                self.__ldap_connect()
                res_id = self.l.search(*args)
            while 1:
                t, d = self.l.result(res_id, 0)
                if d == []:
                    break
                else:
                    if t == ldap.RES_SEARCH_ENTRY:
                        result.append(d[0])
        except ldap.LDAPError as e:
            pass
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.search: %s\n' % self.__ldap_exc_msg(e))
        return result

    def ldap_add(self, *args):
        try:
            try:
                return self.l.add_s(*args)
            except ldap.SERVER_DOWN:
                self.__ldap_connect()
                return self.l.add_s(*args)
        except Exception as e:
            raise LdapException(self.__ldap_exc_msg(e), self.__ldap_exc_info(e))

    def ldap_modify(self, *args):
        try:
            try:
                return self.l.modify(*args)
            except ldap.SERVER_DOWN:
                self.__ldap_connect()
                return self.l.modify(*args)
        except ldap.LDAPError as e:
            y2error_dialog(self.__ldap_exc_msg(e))
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.modify: %s\n' % self.__ldap_exc_msg(e))

    def ldap_delete(self, *args):
        try:
            try:
                return self.l.delete_s(*args)
            except ldap.SERVER_DOWN:
                self.__ldap_connect()
                return self.l.delete_s(*args)
        except ldap.LDAPError as e:
            y2error_dialog(self.__ldap_exc_msg(e))
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.delete_s: %s\n' % self.__ldap_exc_msg(e))

