import ldap, ldap.modlist, ldap.sasl
from ldap.modlist import addModlist as addlist
from ldap.modlist import modifyModlist as modlist
from ldap import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
import traceback
from yast import ycpbuiltins, import_module
import_module('UI')
from yast import UI
from samba.credentials import MUST_USE_KERBEROS
from creds import kinit_for_gssapi
from strings import strcmp
from samba.net import Net
from samba.dcerpc import nbt

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

class Ldap:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        self.realm = lp.get('realm')
        self.__ldap_connect()

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
        if self.creds.get_kerberos_state() == MUST_USE_KERBEROS or kinit_for_gssapi(self.creds, self.realm):
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

