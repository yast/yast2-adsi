#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
from dialogs import ADSI
from yast import import_module
import_module('Wizard')
import_module('UI')
import_module('Sequencer')
from yast import Wizard, UI, Sequencer, Code, Symbol

def ADSISequence(lp, creds):
    aliases = {
        'adsi' : [(lambda lp, creds: ADSI(lp, creds).Show()), lp, creds],
    }

    sequence = {
        'ws_start' : 'adsi',
        'adsi' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : Symbol('next'),
        },
    }

    Wizard.CreateDialog()
    Wizard.SetTitleIcon('yast-adsi')

    ret = Sequencer.Run(aliases, sequence)

    UI.CloseDialog()
    return ret

