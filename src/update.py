###
# Copyright (c) 2013, Valentin Lorentz
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

"""
Allows updating Supybot without restarting it.
"""

import os
import sys
import tempfile
import threading
import pickle as pickle


SAVED_OBJECTS = {
        'supybot.drivers': ('_drivers', '_deadDrivers', '_newDrivers'),
        }

def synchronous(f):
    def newf(self, *args, **kwargs):
        with self._lock:
            return f(self, *args, **kwargs)
    return newf

def import_object(module_name):
    """Really imports an object/module, instead of importing the parent module.
    """
    module = __import__(module_name)
    for submodule in module_name.split('.')[1:]:
        module = getattr(module, submodule)
    return module

class State(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._objects = {}

    @property
    @synchronous
    def serialized(self):
        return pickle.dumps(self._objects)

    @synchronous
    def write(self, fd):
        pickle.dump(fd)
    @synchronous
    def read(cls, fd):
        pickle.load(fd)

    @synchronous
    def backup(self):
        """Saves all Supybot objects to an internal attribute."""
        for module_name, object_names in SAVED_OBJECTS.items():
            module = import_object(module_name)
            objects = {}
            for object_name in object_names:
                objects[object_name] = getattr(module, object_name)
            self._objects = {module_name: objects}

        from supybot import conf, registry
        fd = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self._objects['conf.supybot'] = fd.name
        registry.close(conf.supybot, fd.name)
        fd = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self._objects['conf.users'] = fd.name
        registry.close(conf.users, fd.name)

    @synchronous
    def restore_misc(self):
        """Restore generic Supybot objects from an internal attribute."""
        for module_name, objects in self._objects.items():
            if module_name in ('supybot.registry', 'supybot.world'):
                continue
            module = __import__(module_name)
            for object_name, object_ in objects.items():
                setattr(module, object_name, object_)

    @synchronous
    def restore_registry(self):
        """Restore Supybot registry from an internal attribute."""
        from supybot import registry
        for filename in map(lambda x:self._objects['conf.'+x],
                ('supybot', 'users')):
            registry.open_registry(filename)
            os.unlink(filename)


def save():
    """Save the state to a file and return the path to the file."""
    import supybot.conf as conf
    path = conf.supybot.directories.data.tmp.dirize('saved_state')
    if os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        os.rmdir(path)
    state = State()
    state.backup()
    with open(path, 'w') as fd:
        fd.write(state.serialized)
    return path

def restart():
    """Perform a restart with preserved state."""
    path = save()
    os.execl(sys.executable, '--restore', path)

def on_restart(path):
    """Called by the __main__ script after restart to restore a state."""
    state = update.State()
    with open(path, 'r') as fd:
        state.read(fd)
    state.restore_registry()
    state.restore_misc()
