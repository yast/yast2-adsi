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
import copy
from datetime import datetime
import binascii, struct

def have_x():
    from subprocess import Popen, PIPE
    p = Popen(['xset', '-q'], stdout=PIPE, stderr=PIPE)
    return p.wait() == 0
have_advanced_gui = have_x()

def octet_string_to_hex(data):
    return binascii.hexlify(data)

def octet_string_to_objectGUID(data):
    return '%s-%s-%s-%s-%s' % ('%02x' % struct.unpack('<L', data[0:4])[0],
                               '%02x' % struct.unpack('<H', data[4:6])[0],
                               '%02x' % struct.unpack('<H', data[6:8])[0],
                               '%02x' % struct.unpack('>H', data[8:10])[0],
                               '%02x%02x' % struct.unpack('>HL', data[10:]))

def octet_string_to_objectSid(data):
    if struct.unpack('B', chr(data[0]).encode())[0] == 1:
        length = struct.unpack('B', chr(data[1]).encode())[0]-1
        security_nt_authority = struct.unpack('>xxL', data[2:8])[0]
        security_nt_non_unique = struct.unpack('<L', data[8:12])[0]
        ret = 'S-1-%d-%d' % (security_nt_authority, security_nt_non_unique)
        for i in range(length):
            pos = 12+(i*4)
            ret += '-%d' % struct.unpack('<L', data[pos:pos+4])
        return ret
    else:
        return octet_string_to_hex(data)

class AttrEdit:
    def __init__(self, conn, attr, val):
        self.conn = conn
        self.attribute = attr
        self.value = val
        self.attr_type = self.conn.schema['attributeTypes'][self.attribute.encode()]

    def __dialog(self):
        opts = tuple()
        if not self.attr_type['user-modifiable']:
            opts = tuple(['disabled'])
        input_box = InputField(Id('value'), Opt('hstretch', *opts), 'Value:', self.value)
        return MinSize(60, 8, HBox(HSpacing(3), VBox(
            VSpacing(1),
            Left(Label('Attribute:\t%s' % self.attribute)),
            VSpacing(1),
            Left(input_box),
            Bottom(
                HBox(
                    Left(PushButton(Id('clear'), Opt(*opts), 'Clear')),
                    Right(PushButton(Id('ok'), 'OK')),
                    Right(PushButton(Id('cancel'), 'Cancel')),
                )
            ),
            VSpacing(1),
        ), HSpacing(3)))

    def Show(self):
        UI.SetApplicationTitle('String Attribute Editor')
        if not self.attr_type['multi-valued']:
            UI.OpenDialog(self.__dialog())
        else:
            return None
        while True:
            ret = UI.UserInput()
            if ret == 'abort' or ret == 'cancel':
                ret = None
                break
            elif ret == 'ok':
                ret = UI.QueryWidget(Id('value'), 'Value')
                if not self.attr_type['multi-valued']:
                    ret = [ret]
                break
            elif ret == 'clear':
                pass # Clear the dialog
        UI.CloseDialog()
        return ret

class ObjAttrs:
    def __init__(self, conn, obj):
        self.conn = conn
        self.obj = obj
        attrs = []
        for objectClass in self.obj['objectClass']:
            data = self.conn.schema['objectClasses'][objectClass]
            attrs.extend(data['must'])
            attrs.extend(data['may'])
        for attr in attrs:
            if not attr.decode() in self.obj.keys():
                self.obj[attr.decode()] = None

    def __timestamp(self, val):
        return str(datetime.strptime(val.decode(), '%Y%m%d%H%M%S.%fZ'))

    def __display_value(self, key, val):
        attr_type = self.conn.schema['attributeTypes'][key.encode()]
        if val == None:
            return '<not set>'
        if not attr_type['multi-valued']:
            if attr_type['syntax'] == b'1.3.6.1.4.1.1466.115.121.1.24':
                return self.__timestamp(val[-1])
            if attr_type['syntax'] == b'1.3.6.1.4.1.1466.115.121.1.40':
                if key == 'objectGUID':
                    return octet_string_to_objectGUID(val[-1])
                elif key == 'objectSid':
                    return octet_string_to_objectSid(val[-1])
                else:
                    return octet_string_to_hex(val[-1])
            return self.obj[key][-1]
        else:
            return b'; '.join(self.obj[key])

    def __new(self):
        items = [
            Item(
                Id(key),
                key,
                self.__display_value(key, self.obj[key])
            )
            for key in sorted(self.obj.keys())
        ]
        return MinSize(70, 40, HBox(HSpacing(3), VBox(
            VSpacing(1),
            VWeight(20, Table(Id('attrs'), Opt('vstretch', 'notify'), Header('Attribute', 'Value'), items)),
            VWeight(1, Bottom(Right(HBox(
                PushButton(Id('ok'), 'OK'),
                PushButton(Id('cancel'), 'Cancel'),
                PushButton(Id('apply'), 'Apply')
            )))),
            VSpacing(1),
        ), HSpacing(3)))

    def Show(self):
        UI.SetApplicationTitle(b'CN=%s Properties' % self.obj['cn'][-1])
        UI.OpenDialog(self.__new())
        while True:
            ret = UI.UserInput()
            if ret == 'abort' or ret == 'cancel':
                ret = None
                break
            elif ret == 'ok':
                ret = self.obj
                break
            elif ret == 'apply':
                ret = self.obj
            elif ret == 'attrs':
                attr = UI.QueryWidget('attrs', 'Value')
                val = '' if self.obj[attr] == None else self.obj[attr][-1] if len(self.obj[attr]) == 1 else self.obj[attr]
                new_val = AttrEdit(self.conn, attr, val).Show()
                if self.obj[attr] != new_val:
                    self.obj[attr] = new_val
        UI.CloseDialog()
        return ret

class NewObjDialog:
    def __init__(self, conn, container):
        self.conn = conn
        self.container = container
        self.obj = {}
        self.dialog_seq = 0
        self.dialog = None

    def __fetch_pane(self):
        if not self.dialog:
            self.dialog = self.__object_dialog()
        return self.dialog[self.dialog_seq][0]

    def __new(self):
        pane = self.__fetch_pane()
        return MinSize(56, 22, HBox(HSpacing(3), VBox(
                VSpacing(1),
                ReplacePoint(Id('new_pane'), pane),
                VSpacing(1),
            ), HSpacing(3)))

    def __object_dialog(self):
        inferiors = sorted(self.conn.container_inferiors(self.container))
        items = [Item(name) for name in inferiors]
        return [
            [VBox(
                Left(Label(Id('objectClass_label'), 'Select a class:')),
                Table(Id('objectClass'), Header(''), items),
                Bottom(Right(HBox(
                    PushButton(Id('back'), Opt('disabled'), '< Back'),
                    PushButton(Id('next'), 'Next >'),
                    PushButton(Id('cancel'), 'Cancel'),
                ))),
            ),
            ['objectClass'], # known keys
            ['objectClass'], # required keys
            None, # dialog hook
            ],
            [VBox(
                Left(Label('Attribute:\tcn')),
                Left(Label('Syntax:\tUnicode String')),
                Left(Label('Description:\tCommon-Name')),
                Left(InputField(Id('cn'), Opt('hstretch'), 'Value:')),
                Bottom(Right(HBox(
                    PushButton(Id('back'), '< Back'),
                    PushButton(Id('finish'), 'Finish'),
                    PushButton(Id('cancel'), 'Cancel'),
                ))),
            ),
            ['cn'], # known keys
            ['cn'], # required keys
            None, # dialog hook
            ],
        ]

    def __warn_label(self, key):
        label = UI.QueryWidget('%s_label' % key, 'Value')
        if not label:
            label = UI.QueryWidget(key, 'Label')
        if label[-2:] != ' *':
            if not UI.ChangeWidget('%s_label' % key, 'Value', '%s *' % label):
                UI.ChangeWidget(key, 'Label', '%s *' % label)

    def __fetch_values(self, back=False):
        ret = True
        known_value_keys = self.dialog[self.dialog_seq][1]
        for key in known_value_keys:
            value = UI.QueryWidget(key, 'Value')
            if value or type(value) == bool:
                self.obj[key] = value
        required_value_keys = self.dialog[self.dialog_seq][2]
        for key in required_value_keys:
            if not key in self.obj or not self.obj[key]:
                self.__warn_label(key)
                ycpbuiltins.y2error('Missing value for %s' % key)
                ret = False
        return ret

    def __set_values(self):
        for key in self.obj:
            UI.ChangeWidget(key, 'Value', self.obj[key])

    def __dialog_hook(self):
        hook = self.dialog[self.dialog_seq][3]
        if hook:
            hook()

    def Show(self):
        UI.SetApplicationTitle('Create Object')
        UI.OpenDialog(self.__new())
        while True:
            self.__dialog_hook()
            ret = UI.UserInput()
            if str(ret) == 'abort' or str(ret) == 'cancel':
                ret = None
                break
            elif str(ret) == 'next':
                if self.__fetch_values():
                    self.dialog_seq += 1
                    UI.ReplaceWidget('new_pane', self.__fetch_pane())
                    self.__set_values()
            elif str(ret) == 'back':
                self.__fetch_values(True)
                self.dialog_seq -= 1;
                UI.ReplaceWidget('new_pane', self.__fetch_pane())
                self.__set_values()
            elif str(ret) == 'finish':
                if self.__fetch_values():
                    ret = self.obj
                    break
        UI.CloseDialog()
        return ret

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
                    self.__load_right_pane(current_container)
                    if not have_advanced_gui:
                        UI.ReplaceWidget('new_but',  MenuButton(Id('new'), "New", [
                            Item(Id('context_add_object'), 'Object...')
                        ]))
                        UI.ChangeWidget(Id('delete'), "Enabled", True)
                        UI.ChangeWidget(Id('refresh'), 'Enabled', True)
                else:
                    current_container = None
                    current_object = None
                    UI.ReplaceWidget('rightPane', Empty())
                    if not have_advanced_gui:
                        UI.ReplaceWidget('new_but',  MenuButton(Id('new'), Opt('disabled'), "New", []))
                        UI.ChangeWidget(Id('delete'), "Enabled", False)
                        UI.ChangeWidget(Id('refresh'), 'Enabled', False)
            elif ret == 'context_add_object':
                obj = NewObjDialog(self.conn, current_container).Show()
                if obj:
                    dn = self.conn.add_obj(current_container, obj)
                    self.__refresh(current_container, dn)
            elif ret == 'items':
                current_object = UI.QueryWidget('items', 'Value')
                obj = self.conn.obj(current_object)[-1]
                old_obj = copy.deepcopy(obj)
                obj = ObjAttrs(self.conn, obj).Show()
                if obj:
                    obj = {key: obj[key] for key in obj.keys() if obj[key] != None}
                    self.conn.mod_obj(current_object, old_obj, obj)
                    self.__refresh(current_container, current_object)
            elif ret == 'next':
                break
            elif ret == 'refresh':
                self.__refresh(current_container)
            elif str(ret) == 'delete':
                self.__delete_selected_obj(current_object)
                self.__refresh(current_container)
            UI.SetApplicationTitle('ADSI Edit')
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
            UI.ReplaceWidget('ldap_tree', self.__ldap_tree(current_container))
            UI.ChangeWidget('adsi_tree', 'CurrentItem', Id(current_container))
        self.__load_right_pane(current_container, obj_id)

    def __load_right_pane(self, current_container, obj_id=None):
        if current_container:
            UI.ReplaceWidget('rightPane', self.__objects_tab(current_container))
            if obj_id:
                UI.ChangeWidget('items', 'CurrentItem', Id(obj_id))
        else:
            UI.ReplaceWidget('rightPane', Empty())

    def __objects_tab(self, container):
        header = Header('Name', 'Class', 'Distinguished Name')
        items = [Item(Id(obj[2]), obj[0], obj[1], obj[2]) for obj in self.conn.objs(container)]
        return Table(Id('items'), Opt('notify', 'notifyContextMenu'), header, items)

    def __fetch_children(self, parent, expand):
        return [Item(Id(e[0]), e[0].split(',')[0], e[0].lower() in expand.lower(), self.__fetch_children(e[0], expand)) for e in self.conn.containers(parent)]

    def __ldap_tree(self, expand=''):
        top = self.conn.realm_to_dn(self.conn.realm)
        items = self.__fetch_children(top, expand)

        return Tree(Id('adsi_tree'), Opt('notify', 'immediate', 'notifyContextMenu'), 'ADSI Edit', [
                Item('Default naming context', True, [
                    Item(Id(top), top, True, items)
                ])
            ]
        )

    def __adsi_page(self):
        if not have_advanced_gui:
            menu = HBox(
                ReplacePoint(Id('new_but'),
                    MenuButton(Id('new'), Opt('disabled'), "New", [])
                ),
                PushButton(Id('delete'), Opt('disabled'), "Delete"),
                PushButton(Id('refresh'), Opt('disabled'), 'Refresh')
            )
        else:
            menu = Empty()

        return HBox(
            HWeight(1, VBox(
                ReplacePoint(Id('ldap_tree'), self.__ldap_tree()),
                menu
            )),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty()))
        )

