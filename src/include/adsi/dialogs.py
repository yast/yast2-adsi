from __future__ import absolute_import, division, print_function, unicode_literals
import copy
from complex import Connection
from adcommon.strings import strcmp
from random import randint
from yast import import_module
import_module('Wizard')
import_module('UI')
from yast import *
import six
from ldap.filter import filter_format
import copy
from datetime import datetime
import binascii, struct
from adcommon.yldap import SCOPE_SUBTREE as SUBTREE
from adcommon.creds import YCreds, MUST_USE_KERBEROS
from adcommon.ui import CreateMenu, DeleteButtonBox
from samba.net import Net
from samba.dcerpc import nbt
from samba.credentials import Credentials

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
        if self.attribute.encode() in self.conn.schema['attributeTypes']:
            self.attr_type = self.conn.schema['attributeTypes'][self.attribute.encode()]
        else:
            self.attr_type = None

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
        if self.attr_type and (not self.attr_type['multi-valued'] or not self.attr_type['user-modifiable']):
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
                UI.ChangeWidget(Id('value'), 'Value', '')
        UI.CloseDialog()
        return ret

class ObjAttrs:
    def __init__(self, conn, obj):
        self.conn = conn
        self.obj = obj
        attrs = []
        if 'objectClass' in self.obj: # RootDSE doesn't have an objectClass
            for objectClass in self.obj['objectClass']:
                attrs.extend(self.__extend_attrs(objectClass))
        attrs = list(set(attrs))
        for attr in attrs:
            if not attr.decode() in self.obj.keys():
                self.obj[attr.decode()] = None

    def __extend_attrs(self, objectClass):
        attrs = []
        data = self.conn.schema['objectClasses'][objectClass]
        attrs.extend(data['must'])
        attrs.extend(data['may'])
        rules = self.conn.schema['dITContentRules'][objectClass]
        attrs.extend(rules['must'])
        attrs.extend(rules['may'])
        for aux_class in rules['aux']:
            attrs.extend(self.__extend_attrs(aux_class))
        attrs = [a for a in attrs if not a in self.conn.schema['constructedAttributes']]
        return attrs

    def __timestamp(self, val):
        return str(datetime.strptime(val.decode(), '%Y%m%d%H%M%S.%fZ'))

    def __display_value_each(self, syntax, key, val):
        if syntax == b'1.3.6.1.4.1.1466.115.121.1.24':
            return self.__timestamp(val)
        if syntax == b'1.3.6.1.4.1.1466.115.121.1.40':
            if key == 'objectGUID':
                return octet_string_to_objectGUID(val)
            elif key == 'objectSid':
                return octet_string_to_objectSid(val)
            else:
                return octet_string_to_hex(val)
        return val

    def __display_value(self, key, val):
        if key.encode() in self.conn.schema['attributeTypes']:
            attr_type = self.conn.schema['attributeTypes'][key.encode()]
        else:
            # RootDSE attributes don't show up in the schema, so we have to guess
            if len(val) > 1: # multi-valued
                return '; '.join([v.decode() for v in val])
            return val[-1]
        if val == None:
            return '<not set>'
        else:
            if not attr_type['multi-valued']:
                return self.__display_value_each(attr_type['syntax'], key, val[-1])
            ret = []
            for sval in val:
                nval = self.__display_value_each(attr_type['syntax'], key, sval)
                if isinstance(nval, six.binary_type):
                    nval = nval.decode()
                ret.append(nval)
            return '; '.join(ret)

    def __new(self):
        items = [
            Item(
                Id(key),
                key,
                self.__display_value(key, self.obj[key])
            )
            for key in sorted(self.obj.keys(), key=str.lower)
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
        if 'cn' in self.obj:
            title = b'CN=%s Properties' % self.obj['cn'][-1]
        else:
            title = b''
        UI.SetApplicationTitle(title)
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
                val = self.__display_value(attr, self.obj[attr])
                new_val = AttrEdit(self.conn, attr, val).Show()
                if new_val is not None and self.obj[attr] != new_val:
                    self.obj[attr] = new_val
                UI.SetApplicationTitle(title)
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

class ConnectionSettings:
    def __init__(self, creds, lp):
        self.creds = creds
        self.lp = lp
        self.conn = None
        self.server = None
        realm = self.lp.get('realm')
        if realm:
            self.server = self.__fetch_server(realm)

    def __fetch_server(self, realm):
        net = Net(Credentials())
        cldap_ret = net.finddc(domain=realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        return cldap_ret.pdc_dns_name if cldap_ret else None

    def __fetch_domain(self):
        net = Net(Credentials())
        cldap_ret = net.finddc(address=self.server, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        return cldap_ret.dns_domain if cldap_ret else None

    def __new(self):
        self.contexts = ['Default naming context', 'Configuration', 'RootDSE', 'Schema']
        context = self.contexts[0]
        if self.server:
            path = 'ldap://%s/%s' % (self.server, context)
        else:
            path = ''
        return MinSize(56, 22, HBox(HSpacing(3), VBox(
                VSpacing(1),
                HBox(
                    HWeight(1, Left(Label('Name:'))),
                    HWeight(6, InputField(Id('context'), Opt('hstretch'), '', context)),
                ),
                HBox(
                    HWeight(1, Left(Label('Path:'))),
                    HWeight(6, InputField(Id('path'), Opt('hstretch', 'disabled'), '', path)),
                ),
                Frame('Connection Point', VBox(
                    RadioButtonGroup(VBox(
                        Left(RadioButton(Id('select_dn'), Opt('hstretch', 'editable'), 'Select or type a Distinguished Name or Naming Context:', False)),
                        Left(ComboBox(Id('context_type'), Opt('hstretch', 'editable', 'notify', 'immediate'), '', [])),
                        Left(RadioButton(Id('select_nc'), Opt('hstretch'), 'Select a well known Naming Context:', True)),
                        Left(ComboBox(Id('context_combo'), Opt('hstretch', 'notify'), '', [Item(c) for c in self.contexts])),
                    )),
                )),
                Frame('Computer', VBox(
                    RadioButtonGroup(VBox(
                        Left(RadioButton(Id('server_select'), Opt('hstretch'), 'Select or type a domain or server: (Server | Domain [:port])', self.server is None)),
                        Left(ComboBox(Id('server'), Opt('hstretch', 'editable', 'notify', 'immediate'), '', [])),
                        Left(RadioButton(Opt('hstretch', 'disabled' if self.server is None else ''), 'Default (Domain or server that you logged in to)', self.server is not None)),
                    )),
                    Left(CheckBox(Opt('hstretch', 'disabled'), 'Use SSL-based Encryption', True)),
                )),
                Bottom(Right(HBox(
                    PushButton(Id('ok'), 'OK'),
                    PushButton(Id('cancel'), 'Cancel'),
                ))),
                VSpacing(1),
            ), HSpacing(3)))

    def Show(self):
        UI.SetApplicationTitle('Connection Settings')
        UI.OpenDialog(self.__new())
        while True:
            ret = UI.UserInput()
            if str(ret) == 'abort' or str(ret) == 'cancel':
                break
            elif ret == 'context_combo':
                UI.ChangeWidget('select_nc', 'Value', True)
                context = UI.QueryWidget('context_combo', 'Value')
                UI.ChangeWidget('context', 'Value', context)
                path = 'ldap://%s/%s' % (self.server, context) if self.server else None
                if path:
                    UI.ChangeWidget('path', 'Value', path)
            elif ret == 'context_type':
                UI.ChangeWidget('select_dn', 'Value', True)
                context = UI.QueryWidget('context_type', 'Value')
                UI.ChangeWidget('context', 'Value', context)
                path = 'ldap://%s/%s' % (self.server, context) if self.server else None
                if path:
                    UI.ChangeWidget('path', 'Value', path)
            elif ret == 'server':
                UI.ChangeWidget('server_select', 'Value', True)
                self.server = UI.QueryWidget('server', 'Value')
                context = UI.QueryWidget('context_combo', 'Value')
                UI.ChangeWidget('path', 'Value', 'ldap://%s/%s' % (self.server, context))
            elif ret == 'ok':
                realm = self.__fetch_domain().upper()
                if realm:
                    self.lp.set('realm', realm)
                path = UI.QueryWidget('path', 'Value')
                ycred = YCreds(self.creds)
                def cred_valid():
                    try:
                        self.conn = Connection(self.lp, self.creds, path)
                        return True
                    except Exception as e:
                        ycpbuiltins.y2error(str(e))
                    return False
                ycred.Show(cred_valid)
                if self.conn:
                    break
        UI.CloseDialog()
        return self.conn

class ADSI:
    def __init__(self, lp, creds):
        self.realm = lp.get('realm')
        self.lp = lp
        self.creds = creds
        self.__setup_menus()
        self.conn = None

    def __setup_menus(self, obj=False):
        menus = [{'title': '&File', 'id': 'file', 'type': 'Menu'},
                 {'title': 'Exit', 'id': 'abort', 'type': 'MenuEntry', 'parent': 'file'}]
        if obj:
            menus.append({'title': 'Action', 'id': 'action', 'type': 'Menu'})
            menus.append({'title': 'New', 'id': 'new_but', 'type': 'SubMenu', 'parent': 'action'})
            menus.append({'title': 'Object...', 'id': 'context_add_object', 'type': 'MenuEntry', 'parent': 'new_but'})
            menus.append({'title': 'Delete', 'id': 'delete', 'type': 'MenuEntry', 'parent': 'action'})
            menus.append({'title': 'Refresh', 'id': 'refresh', 'type': 'MenuEntry', 'parent': 'action'})
            menus.append({'title': 'Properties', 'id': 'properties', 'type': 'MenuEntry', 'parent': 'action'})
        else:
            menus.append({'title': 'Action', 'id': 'action', 'type': 'Menu'})
            menus.append({'title': 'Connect to...', 'id': 'connect', 'type': 'MenuEntry', 'parent': 'action'})
        CreateMenu(menus)

    def __delete_selected_obj(self, current_object):
        if self.__warn_delete(current_object):
            self.conn.ldap_delete(current_object)

    def Show(self):
        UI.SetApplicationTitle('ADSI Edit')
        Wizard.SetContentsButtons('', self.__adsi_page(), '', 'Back', 'Close')
        DeleteButtonBox()
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
            if str(ret) == 'abort' or (str(ret) == 'cancel' and not menu_open):
                break
            menu_open = False
            if ret == 'adsi_tree':
                choice = UI.QueryWidget('adsi_tree', 'Value')
                if 'DC=' in choice:
                    current_container = choice
                    current_object = choice
                    self.__load_right_pane(current_container)
                    self.__setup_menus(obj=True)
                elif choice == 'rootdse':
                    current_container = ''
                    current_object = None
                    self.__load_right_pane(current_container)
                    self.__setup_menus(obj=True)
                else:
                    current_container = None
                    current_object = None
                    UI.ReplaceWidget('rightPane', Empty())
                    self.__setup_menus()
                if event['EventReason'] == 'ContextMenuActivated':
                    if current_container:
                        menu_open = True
                        UI.OpenContextMenu(self.__objs_context_menu())
                    else:
                        menu_open = True
                        UI.OpenContextMenu(self.__connect_context_menu())
            elif ret == 'context_add_object':
                obj = NewObjDialog(self.conn, current_container).Show()
                if obj:
                    dn = self.conn.add_obj(current_container, obj)
                    self.__refresh(current_container, dn)
            elif ret == 'items':
                if event['EventReason'] == 'ContextMenuActivated':
                    current_object = UI.QueryWidget('items', 'Value')
                    UI.OpenContextMenu(self.__objs_context_menu())
                elif event['EventReason'] == 'SelectionChanged':
                    current_object = UI.QueryWidget('items', 'Value')
                    self.__setup_menus(obj=True)
                else:
                    self.__obj_properties(current_container, current_object)
            elif ret == 'properties':
                self.__obj_properties(current_container, current_object)
            elif ret == 'next':
                break
            elif ret == 'refresh':
                self.__refresh(current_container)
            elif str(ret) == 'delete':
                self.__delete_selected_obj(current_object)
                self.__refresh(current_container)
            elif ret == 'connect':
                self.conn = ConnectionSettings(self.creds, self.lp).Show()
                if self.conn:
                    UI.ReplaceWidget('ldap_tree', self.__ldap_tree())
            UI.SetApplicationTitle('ADSI Edit')
        return ret

    def __obj_properties(self, current_container, current_object):
        if not current_object:
            current_object = current_container
        obj = self.conn.obj(current_object)[-1]
        old_obj = copy.deepcopy(obj)
        obj = ObjAttrs(self.conn, obj).Show()
        if obj:
            obj = {key: obj[key] for key in obj.keys() if obj[key] != None}
            self.conn.mod_obj(current_object, old_obj, obj)
            self.__refresh(current_container, current_object if current_object != current_container else None)

    def __objs_context_menu(self):
        return Term('menu', [
            Term('menu', 'New', [
                    Item(Id('context_add_object'), 'Object...'),
                ]),
            Item(Id('delete'), 'Delete'),
            Item(Id('refresh'), 'Refresh'),
            Item(Id('properties'), 'Properties'),
            ])

    def __connect_context_menu(self):
        return Term('menu', [
            Item(Id('connect'), 'Connect to...'),
            Item(Id('refresh'), 'Refresh'),
        ])

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
        return Table(Id('items'), Opt('notify', 'immediate', 'notifyContextMenu'), header, items)

    def __fetch_children(self, parent, expand):
        return [Item(Id(e[0]), e[0].split(',')[0], e[0].lower() in expand.lower(), self.__fetch_children(e[0], expand)) for e in self.conn.containers(parent)]

    def __ldap_tree(self, expand=''):
        if self.conn and not self.conn.rootdse:
            top = self.conn.naming_context
            context = '%s [%s]' % (self.conn.naming_context_name, self.conn.dc_hostname)
            items = self.__fetch_children(top, expand)
            tree = [Item(context, True, [Item(Id(top), top, True, items)])]
        elif self.conn and self.conn.rootdse:
            context = 'RootDSE [%s]' % self.conn.dc_hostname
            tree = [Item(context, True, [Item(Id('rootdse'), 'RootDSE', False, [])])]
        else:
            tree = []

        return Tree(Id('adsi_tree'), Opt('notify', 'immediate', 'notifyContextMenu'), '', [
            Item(Id('adsi_edit'), 'ADSI Edit', True, tree)
        ])

    def __adsi_page(self):
        return HBox(
            HWeight(1, VBox(
                ReplacePoint(Id('ldap_tree'), self.__ldap_tree()),
            )),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty()))
        )

