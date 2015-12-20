###
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

from supybot.test import *


class AdminTestCase(PluginTestCase):
    plugins = ('Authentication',)

    def startCapNegociation(self, caps='sasl'):
        m = self.irc.takeMsg()
        self.failUnless(m.command == 'CAP', 'Expected CAP, got %r.' % m)
        self.failUnless(m.args == ('LS', '302'), 'Expected CAP LS 302, got %r.' % m)

        m = self.irc.takeMsg()
        self.failUnless(m.command == 'NICK', 'Expected NICK, got %r.' % m)

        m = self.irc.takeMsg()
        self.failUnless(m.command == 'USER', 'Expected USER, got %r.' % m)

        self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
            args=('*', 'LS', caps)))

        if caps:
            m = self.irc.takeMsg()
            self.failUnless(m.command == 'CAP', 'Expected CAP, got %r.' % m)
            self.assertEqual(m.args[0], 'REQ', m)
            self.assertEqual(m.args[1], 'sasl')

            self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
                args=('*', 'ACK', 'sasl')))

    def endCapNegociation(self):
        m = self.irc.takeMsg()
        self.failUnless(m.command == 'CAP', 'Expected CAP, got %r.' % m)
        self.assertEqual(m.args, ('END',), m)

    def testPlain(self):
        try:
            conf.supybot.networks.test.sasl.username.setValue('jilles')
            conf.supybot.networks.test.sasl.password.setValue('sesame')
            self.irc = irclib.Irc('test')
        finally:
            conf.supybot.networks.test.sasl.username.setValue('')
            conf.supybot.networks.test.sasl.password.setValue('')
        state = self.irc.getCallback('Authentication') \
                ._sasl_states[self.irc.network]
        self.assertEqual(state.sasl_current_mechanism, None)
        self.assertEqual(state.sasl_next_mechanisms, ['plain'])

        self.startCapNegociation()

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('PLAIN',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='AUTHENTICATE', args=('+',)))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('amlsbGVzAGppbGxlcwBzZXNhbWU=',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='900',
            args=(self.nick, self.prefix, 'jilles')))
        self.irc.feedMsg(ircmsgs.IrcMsg(command='903', args=(self.nick,)))

        self.endCapNegociation()

    def testExternalFallbackToPlain(self):
        try:
            conf.supybot.networks.test.sasl.username.setValue('jilles')
            conf.supybot.networks.test.sasl.password.setValue('sesame')
            conf.supybot.networks.test.certfile.setValue('foo')
            self.irc = irclib.Irc('test')
        finally:
            conf.supybot.networks.test.sasl.username.setValue('')
            conf.supybot.networks.test.sasl.password.setValue('')
            conf.supybot.networks.test.certfile.setValue('')
        state = self.irc.getCallback('Authentication') \
                ._sasl_states[self.irc.network]
        self.assertEqual(state.sasl_current_mechanism, None)
        self.assertEqual(state.sasl_next_mechanisms, ['external', 'plain'])

        self.startCapNegociation()

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('EXTERNAL',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='904',
            args=('mechanism not available',)))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('PLAIN',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='AUTHENTICATE', args=('+',)))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('amlsbGVzAGppbGxlcwBzZXNhbWU=',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='900',
            args=(self.nick, self.prefix, 'jilles')))
        self.irc.feedMsg(ircmsgs.IrcMsg(command='903', args=(self.nick,)))

        self.endCapNegociation()

    def testFilter(self):
        try:
            conf.supybot.networks.test.sasl.username.setValue('jilles')
            conf.supybot.networks.test.sasl.password.setValue('sesame')
            conf.supybot.networks.test.certfile.setValue('foo')
            self.irc = irclib.Irc('test')
        finally:
            conf.supybot.networks.test.sasl.username.setValue('')
            conf.supybot.networks.test.sasl.password.setValue('')
            conf.supybot.networks.test.certfile.setValue('')
        state = self.irc.getCallback('Authentication') \
                ._sasl_states[self.irc.network]
        self.assertEqual(state.sasl_current_mechanism,  None)
        self.assertEqual(state.sasl_next_mechanisms, ['external', 'plain'])

        self.startCapNegociation(caps='sasl=foo,plain,bar')

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('PLAIN',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='AUTHENTICATE', args=('+',)))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('amlsbGVzAGppbGxlcwBzZXNhbWU=',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='900',
            args=(self.nick, self.prefix, 'jilles')))
        self.irc.feedMsg(ircmsgs.IrcMsg(command='903', args=(self.nick,)))

        self.endCapNegociation()

    def testReauthenticate(self):
        try:
            conf.supybot.networks.test.sasl.username.setValue('jilles')
            conf.supybot.networks.test.sasl.password.setValue('sesame')
            self.irc = irclib.Irc('test')
        finally:
            conf.supybot.networks.test.sasl.username.setValue('')
            conf.supybot.networks.test.sasl.password.setValue('')
        state = self.irc.getCallback('Authentication') \
                ._sasl_states[self.irc.network]
        self.assertEqual(state.sasl_current_mechanism, None)
        self.assertEqual(state.sasl_next_mechanisms, ['plain'])

        self.startCapNegociation(caps='')

        self.endCapNegociation()

        while self.irc.takeMsg():
            pass

        self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
                args=('*', 'NEW', 'sasl=EXTERNAL')))

        self.irc.takeMsg() # None. But even if it was CAP REQ sasl, it would be ok
        self.assertEqual(self.irc.takeMsg(), None)

        try:
            conf.supybot.networks.test.sasl.username.setValue('jilles')
            conf.supybot.networks.test.sasl.password.setValue('sesame')
            self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
                    args=('*', 'DEL', 'sasl')))
            self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
                    args=('*', 'NEW', 'sasl=PLAIN')))
        finally:
            conf.supybot.networks.test.sasl.username.setValue('')
            conf.supybot.networks.test.sasl.password.setValue('')

        m = self.irc.takeMsg()
        self.failUnless(m.command == 'CAP', 'Expected CAP, got %r.' % m)
        self.assertEqual(m.args[0], 'REQ', m)
        self.assertEqual(m.args[1], 'sasl')
        self.irc.feedMsg(ircmsgs.IrcMsg(command='CAP',
            args=('*', 'ACK', 'sasl')))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('PLAIN',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='AUTHENTICATE', args=('+',)))

        m = self.irc.takeMsg()
        self.assertEqual(m, ircmsgs.IrcMsg(command='AUTHENTICATE',
            args=('amlsbGVzAGppbGxlcwBzZXNhbWU=',)))

        self.irc.feedMsg(ircmsgs.IrcMsg(command='900',
            args=(self.nick, self.prefix, 'jilles')))
        self.irc.feedMsg(ircmsgs.IrcMsg(command='903', args=(self.nick,)))


# vim:set shiftwidth=4 tabstop=4 expandtab textwidth=79:
