##
# Copyright (c) 2015, Valentin Lorentz
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
###

import os
import os.path
import functools
import collections
from . import conf, log

upgrades_path = conf.supybot.directories.migrations.dirize('upgrades.txt')
if not os.path.isfile(upgrades_path):
    with open(upgrades_path, 'a', encoding='utf8') as fd:
        pass
with open(upgrades_path, encoding='utf8') as fd:
    done_upgrades = set([x.strip() for x in fd.readlines()])

registered_upgrades = set()

def register(name, upgrade_function):
    global done_upgrades
    registered_upgrades.add(name)
    if name in done_upgrades:
        # This migration was already done and its downgrade script was
        # installed.
        return False
    log.critical('Upgrading feature %s' % name)
    downgrade_script = upgrade_function()
    done_upgrades.add(name)
    if downgrade_script is None:
        return True # No downgrade script
    filename = '%s.py' % name
    path = conf.supybot.directories.migrations.dirize(filename)
    with open(path, 'a', encoding='utf8') as fd:
        fd.write(downgrade_script)


def do_downgrades():
    global done_upgrades
    assert registered_upgrades.issubset(done_upgrades)
    for name in sorted(done_upgrades - registered_upgrades):
        log.critical('Downgrading feature %s' % name)
        filename = '%s.py' % name
        path = conf.supybot.directories.migrations.dirize(filename)
        if not os.path.isfile(path):
            # No downgrade script
            continue
        else:
            with open(path) as fd:
                script = fd.read()
            exec(script)
            os.unlink(path)
    done_upgrades = registered_upgrades
    os.unlink(upgrades_path)

def update_upgrades_txt():
    with open(upgrades_path, 'a', encoding='utf8') as fd:
        fd.write('\n'.join(done_upgrades))



def add_authentication_plugin_to_list():
    conf.registerPlugin('Authentication')
    return None # No downgrade script.
register('2015-12-20_add_authentication_plugin',
        add_authentication_plugin_to_list)
