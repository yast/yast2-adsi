from yast import import_module
import_module('UI')
from yast import *
from subprocess import Popen, PIPE
from samba.credentials import Credentials, MUST_USE_KERBEROS
import re, six
from strings import strcasecmp

def kinit_for_gssapi(creds, realm):
    p = Popen(['kinit', '%s@%s' % (creds.get_username(), realm) if not realm in creds.get_username() else creds.get_username()], stdin=PIPE, stdout=PIPE)
    p.stdin.write(('%s\n' % creds.get_password()).encode())
    p.stdin.flush()
    return p.wait() == 0

class YCreds:
    def __init__(self, creds):
        self.creds = creds
        self.retry = False

    def get_creds(self):
        if self.retry:
            self.creds.set_password('')
        self.retry = True
        if not self.creds.get_password():
            if self.creds.get_username():
                self.__validate_kinit()
                if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                    return True
            UI.SetApplicationTitle('Authenticate')
            UI.OpenDialog(self.__password_prompt(self.creds.get_username()))
            while True:
                subret = UI.UserInput()
                if str(subret) == 'creds_ok':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    password = UI.QueryWidget('password_prompt', 'Value')
                    UI.CloseDialog()
                    if not password:
                        return False
                    self.creds.set_username(user)
                    self.creds.set_password(password)
                    return True
                if str(subret) == 'krb_select':
                    user = UI.QueryWidget('krb_select', 'Label')[1:]
                    self.creds.set_username(user)
                    self.__validate_kinit()
                    if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                        UI.CloseDialog()
                        return True
                if str(subret) == 'creds_cancel':
                    UI.CloseDialog()
                    return False
                if str(subret) == 'username_prompt':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    self.creds.set_username(user)
                    self.__validate_kinit()
                    if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                        UI.CloseDialog()
                        return True
        return True

    def __validate_kinit(self):
        out, _ = Popen(['klist'], stdout=PIPE, stderr=PIPE).communicate()
        m = re.findall(six.b('Default principal:\s*(\w+)@([\w\.]+)'), out)
        if len(m) == 0:
            return None
        user, realm = m[0]
        if not strcasecmp(user, self.creds.get_username()):
            return None
        if Popen(['klist', '-s'], stdout=PIPE, stderr=PIPE).wait() != 0:
            return None
        self.creds.set_kerberos_state(MUST_USE_KERBEROS)

    def __recommend_user(self):
        expired = False
        if Popen(['klist', '-s'], stdout=PIPE, stderr=PIPE).wait() != 0:
            expired = True
        out, _ = Popen(['klist'], stdout=PIPE, stderr=PIPE).communicate()
        m = re.findall(six.b('Default principal:\s*(\w+)@([\w\.]+)'), out)
        if len(m) == 0:
            return None, None, None
        user, realm = m[0]
        return user, realm, expired

    def __password_prompt(self, user):
        krb_user, krb_realm, krb_expired = self.__recommend_user()
        if krb_user and not krb_expired:
            krb_selection = Frame('', VBox(
                VSpacing(.5),
                Left(PushButton(Id('krb_select'), Opt('hstretch', 'vstretch'), krb_user)),
                Left(Label(b'Realm: %s' % krb_realm))
            ))
        elif krb_user and krb_expired:
            user = krb_user
            krb_selection = Empty()
        else:
            krb_selection = Empty()
        return MinWidth(30, HBox(HSpacing(1), VBox(
            VSpacing(.5),
            Left(Label('To continue, type an administrator password')),
            Frame('', VBox(
                Left(TextEntry(Id('username_prompt'), Opt('hstretch', 'notify'), 'Username', user)),
                Left(Password(Id('password_prompt'), Opt('hstretch'), 'Password')),
            )),
            krb_selection,
            Right(HBox(
                PushButton(Id('creds_ok'), 'OK'),
                PushButton(Id('creds_cancel'), 'Cancel'),
            )),
            VSpacing(.5)
        ), HSpacing(1)))

