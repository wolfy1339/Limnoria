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

import functools

from supybot.test import *
import supybot.sasl as sasl
import supybot.irclib as irclib

def set_variables(L):
    def decorator(f):
        @functools.wraps(f)
        def newf(self):
            try:
                for (var, value) in L:
                    var.setValue(value)
                return f(self)
            finally:
                for (var, _) in L:
                    var.setValue('')
        return newf
    return decorator


class AuthenticationTestCase(SupyTestCase):
    def setUp(self):
        self.nick = 'tester'
        self.prefix = 'tester!foo@bar'
        self.irc = irclib.Irc('test')

    def startCapNegotiation(self, caps='sasl'):
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

    def endCapNegotiation(self):
        m = self.irc.takeMsg()
        self.failUnless(m.command == 'CAP', 'Expected CAP, got %r.' % m)
        self.assertEqual(m.args, ('END',), m)

    @set_variables([
        (conf.supybot.networks.test.sasl.username, 'jilles'),
        (conf.supybot.networks.test.sasl.password, 'sesame'),
        ])
    def testPlain(self):
        self.irc = irclib.Irc('test')
        state = sasl.SaslState(self.irc.network)

        self.startCapNegotiation()

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

        self.endCapNegotiation()

    @set_variables([
        (conf.supybot.networks.test.sasl.username, 'jilles'),
        (conf.supybot.networks.test.sasl.password, 'sesame'),
        (conf.supybot.networks.test.certfile, 'foo'),
        ])
    def testExternalFallbackToPlain(self):
        self.irc = irclib.Irc('test')
        state = sasl.SaslState(self.irc.network)
        self.assertEqual(state.sasl_current_mechanism, None)
        self.assertEqual(state.sasl_next_mechanisms, ['external', 'plain'])

        self.startCapNegotiation()

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

        self.endCapNegotiation()

    @set_variables([
        (conf.supybot.networks.test.sasl.username, 'jilles'),
        (conf.supybot.networks.test.sasl.password, 'sesame'),
        (conf.supybot.networks.test.certfile, 'foo'),
        ])
    def testFilter(self):
        self.irc = irclib.Irc('test')
        state = sasl.SaslState(self.irc.network)
        self.assertEqual(state.sasl_current_mechanism,  None)
        self.assertEqual(state.sasl_next_mechanisms, ['external', 'plain'])

        self.startCapNegotiation(caps='sasl=foo,plain,bar')

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

        self.endCapNegotiation()

    @set_variables([
        (conf.supybot.networks.test.sasl.username, 'jilles'),
        (conf.supybot.networks.test.sasl.password, 'sesame'),
        ])
    def testReauthenticate(self):
        self.irc = irclib.Irc('test')
        state = sasl.SaslState(self.irc.network)
        self.assertEqual(state.sasl_current_mechanism, None)
        self.assertEqual(state.sasl_next_mechanisms, ['plain'])

        self.startCapNegotiation(caps='')

        self.endCapNegotiation()

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

