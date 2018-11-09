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

    def __delete_selected_obj(self, current_object):
        if self.__warn_delete(current_object):
            self.conn.ldap_delete(current_object)

    def Show(self):
        if not self.got_creds:
            return Symbol('abort')
        UI.SetApplicationTitle('ADSI Edit')
        Wizard.SetContentsButtons('', self.__adsi_page(), '', 'Back', 'Close')

        Wizard.HideBackButton()
        Wizard.HideAbortButton()
        UI.SetFocus('adsi_tree')
        current_container = None
        current_object = None
        while True:
            event = UI.WaitForEvent()
            if 'WidgetID' in event:
                ret = event['WidgetID']
            elif 'ID' in event:
                ret = event['ID']
            else:
                raise Exception('ID not found in response %s' % str(event))
            if ret == 'adsi_tree':
                choice = UI.QueryWidget('adsi_tree', 'Value')
                if 'DC=' in choice:
                    current_container = choice
                    current_object = choice
                    self.__refresh(choice)
                    if not have_advanced_gui:
                        UI.ChangeWidget(Id('delete'), "Enabled", True)
                        UI.ChangeWidget(Id('refresh'), 'Enabled', True)
                else:
                    current_container = None
                    current_object = None
                    UI.ReplaceWidget('rightPane', Empty())
                    if not have_advanced_gui:
                        UI.ChangeWidget(Id('delete'), "Enabled", False)
                        UI.ChangeWidget(Id('refresh'), 'Enabled', False)
            elif ret == 'items':
                current_object = UI.QueryWidget('items', 'Value')
            elif ret == 'next':
                break
            elif ret == 'refresh':
                self.__refresh(current_container)
            elif str(ret) == 'delete':
                self.__delete_selected_obj(current_object)
                self.__refresh(current_container)
        return ret

    def __warn_delete(self, name):
        if six.PY3 and type(name) is bytes:
            name = name.decode('utf-8')
        ans = False
        UI.SetApplicationTitle('Delete')
        UI.OpenDialog(Opt('warncolor'), HBox(HSpacing(1), VBox(
            VSpacing(.3),
            Label('Are you sure you want to delete \'%s\'?' % name),
            Right(HBox(
                PushButton(Id('yes'), 'Yes'),
                PushButton(Id('no'), 'No')
            )),
            VSpacing(.3),
        ), HSpacing(1)))
        ret = UI.UserInput()
        if str(ret) == 'yes':
            ans = True
        elif str(ret) == 'no' or str(ret) == 'abort' or str(ret) == 'cancel':
            ans = False
        UI.CloseDialog()
        return ans

    def __refresh(self, current_container, obj_id=None):
        if current_container:
            UI.ReplaceWidget('rightPane', self.__objects_tab(current_container))
            if obj_id:
                UI.ChangeWidget('items', 'CurrentItem', obj_id)
        else:
            UI.ReplaceWidget('rightPane', Empty())

    def __objects_tab(self, container):
        header = Header('Name', 'Class', 'Distinguished Name')
        items = [Item(Id(obj[2]), obj[0], obj[1], obj[2]) for obj in self.conn.objs(container)]
        return Table(Id('items'), Opt('notify', 'notifyContextMenu'), header, items)

    def __fetch_children(self, parent):
        return [Item(Id(e[0]), e[0].split(',')[0], False, self.__fetch_children(e[0])) for e in self.conn.containers(parent)]

    def __ldap_tree(self):
        top = self.conn.realm_to_dn(self.conn.realm)
        items = self.__fetch_children(top)

        if not have_advanced_gui:
            menu = HBox(
                PushButton(Id('delete'), Opt('disabled'), "Delete"),
                PushButton(Id('refresh'), Opt('disabled'), 'Refresh')
            )
        else:
            menu = Empty()

        return VBox(
            Tree(Id('adsi_tree'), Opt('notify', 'immediate', 'notifyContextMenu'), 'ADSI Edit', [
                Item('Default naming context', False, [
                    Item(Id(top), top, False, items)
                ])
            ]),
            menu
        )

    def __adsi_page(self):
        return HBox(
            HWeight(1, self.__ldap_tree()),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty()))
        )

