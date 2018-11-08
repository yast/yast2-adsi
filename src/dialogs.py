#!/usr/bin/env python

from __future__ import absolute_import, division, print_function, unicode_literals
import copy
from complex import Connection, strcmp, validate_kinit
from random import randint
from yast import import_module
import_module('Wizard')
import_module('UI')
from yast import *
import six
from ldap.filter import filter_format
from ldap import SCOPE_SUBTREE as SUBTREE
from samba.credentials import MUST_USE_KERBEROS

def have_x():
    from subprocess import Popen, PIPE
    p = Popen(['xset', '-q'], stdout=PIPE, stderr=PIPE)
    return p.wait() == 0
have_advanced_gui = have_x()

class ADSI:
    def __init__(self, lp, creds):
        self.realm = lp.get('realm')
        self.lp = lp
        self.creds = creds
        self.got_creds = self.__get_creds(creds)
        while self.got_creds:
            try:
                self.conn = Connection(lp, creds)
                break
            except Exception as e:
                ycpbuiltins.y2error(str(e))
                creds.set_password('')
                self.got_creds = self.__get_creds(creds)

    def __get_creds(self, creds):
        if not creds.get_password():
            if creds.get_username():
                validate_kinit(self.creds)
                if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                    return True
            UI.SetApplicationTitle('Authenticate')
            UI.OpenDialog(self.__password_prompt(creds.get_username()))
            while True:
                subret = UI.UserInput()
                if str(subret) == 'creds_ok':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    password = UI.QueryWidget('password_prompt', 'Value')
                    UI.CloseDialog()
                    if not password:
                        return False
                    creds.set_username(user)
                    creds.set_password(password)
                    return True
                if str(subret) == 'creds_cancel':
                    UI.CloseDialog()
                    return False
                if str(subret) == 'username_prompt':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    creds.set_username(user)
                    validate_kinit(self.creds)
                    if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                        UI.CloseDialog()
                        return True
        return True

    def __password_prompt(self, user):
        return MinWidth(30, HBox(HSpacing(1), VBox(
            VSpacing(.5),
            Left(Label('To continue, type an administrator password')),
            Left(TextEntry(Id('username_prompt'), Opt('hstretch', 'notify'), 'Username', user)),
            Left(Password(Id('password_prompt'), Opt('hstretch'), 'Password')),
            Right(HBox(
                PushButton(Id('creds_ok'), 'OK'),
                PushButton(Id('creds_cancel'), 'Cancel'),
            )),
            VSpacing(.5)
        ), HSpacing(1)))

    def Show(self):
        if not self.got_creds:
            return Symbol('abort')
        UI.SetApplicationTitle('ADSI Edit')
        Wizard.SetContentsButtons('', self.__ldap_tree(), '', 'Back', 'Close')

        Wizard.HideBackButton()
        Wizard.HideAbortButton()
        while True:
            event = UI.WaitForEvent()
            if 'WidgetID' in event:
                ret = event['WidgetID']
            elif 'ID' in event:
                ret = event['ID']
            else:
                raise Exception('ID not found in response %s' % str(event))
            if str(ret) == 'next':
                break
        return ret

