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

import base64
try:
    from ecdsa import SigningKey, BadDigestError
    ecdsa = True
except ImportError:
    ecdsa = False

import supybot.conf as conf
import supybot.world as world
import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircmsgs as ircmsgs
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization('Authentication')
except ImportError:
    # Placeholder that allows to run the plugin on a bot
    # without the i18n module
    _ = lambda x: x

class SaslState:
    """Container."""
    def __init__(self, network):
        self.reset(network)
    def reset(self, network):
        network_config = conf.supybot.networks.get(network)
        self.sasl_authenticated = False
        self.sasl_username = network_config.sasl.username()
        self.sasl_password = network_config.sasl.password()
        self.sasl_ecdsa_key = network_config.sasl.ecdsa_key()
        self.sasl_next_mechanisms = []
        self.sasl_current_mechanism = None

        for mechanism in network_config.sasl.mechanisms():
            if mechanism == 'ecdsa-nist256p-challenge' and \
                    ecdsa and self.sasl_username and self.sasl_ecdsa_key:
                self.sasl_next_mechanisms.append(mechanism)
            elif mechanism == 'external' and (
                    network_config.certfile() or
                    conf.supybot.protocols.irc.certfile()):
                self.sasl_next_mechanisms.append(mechanism)
            elif mechanism == 'plain' and \
                    self.sasl_username and self.sasl_password:
                self.sasl_next_mechanisms.append(mechanism)

class Authentication(callbacks.Plugin):
    """Authenticates the bot to networks."""
    def __init__(self, irc):
        super(Authentication, self).__init__(irc)
        self._sasl_states = {}
        self.authenticate_decoder = None
        for irc in world.ircs:
            if not irc.capNegociationEnded:
                self.onNewIrc(irc)

    def hold_capability_negociation(self, irc):
        return irc.network in self._sasl_states

    def onNewIrc(self, irc):
        self._sasl_states[irc.network] = SaslState(irc.network)

    def resetSasl(self, irc):
        self._sasl_states[irc.network] = SaslState(irc.network)

    def sendSaslString(self, irc, string):
        for chunk in ircutils.authenticate_generator(string):
            irc.sendMsg(ircmsgs.IrcMsg(command='AUTHENTICATE',
                args=(chunk,)))

    def tryNextSaslMechanism(self, irc):
        state = self._sasl_states[irc.network]
        if state.sasl_next_mechanisms:
            state.sasl_current_mechanism = state.sasl_next_mechanisms.pop(0)
            irc.sendMsg(ircmsgs.IrcMsg(command='AUTHENTICATE',
                args=(state.sasl_current_mechanism.upper(),)))
        else:
            state.sasl_current_mechanism = None
            del self._sasl_states[irc.network]
            irc.endCapabilityNegociation()

    def filterSaslMechanisms(self, irc, available):
        available = set(map(str.lower, available))
        state = self._sasl_states[irc.network]
        state.sasl_next_mechanisms = [
                x for x in state.sasl_next_mechanisms
                if x.lower() in available]

    def doAuthenticate(self, irc, msg):
        if not self.authenticate_decoder:
            self.authenticate_decoder = ircutils.AuthenticateDecoder()
        self.authenticate_decoder.feed(msg)
        if not self.authenticate_decoder.ready:
            return # Waiting for other messages
        string = self.authenticate_decoder.get()
        self.authenticate_decoder = None

        state = self._sasl_states[irc.network]

        mechanism = state.sasl_current_mechanism
        if mechanism == 'ecdsa-nist256p-challenge':
            if string == b'':
                self.sendSaslString(irc, state.sasl_username.encode('utf-8'))
                return
            try:
                with open(state.sasl_ecdsa_key) as fd:
                    private_key = SigningKey.from_pem(fd.read())
                authstring = private_key.sign(base64.b64decode(msg.args[0].encode()))
                self.sendSaslString(irc, authstring)
            except (BadDigestError, OSError, ValueError):
                self.sendMsg(ircmsgs.IrcMsg(command='AUTHENTICATE',
                    args=('*',)))
                self.tryNextSaslMechanism(irc)
        elif mechanism == 'external':
            self.sendSaslString(b'')
        elif mechanism == 'plain':
            authstring = b'\0'.join([
                state.sasl_username.encode('utf-8'),
                state.sasl_username.encode('utf-8'),
                state.sasl_password.encode('utf-8'),
            ])
            self.sendSaslString(irc, authstring)

    def do900(self, irc, msg):
        account = msg.args[2]
        self.log.info('%s: SASL authenticated as %s', irc.network, account)
        irc.state.authentication = account

    def do903(self, irc, msg):
        self.log.info('%s: SASL authentication successful', irc.network)
        del self._sasl_states[irc.network]
        irc.endCapabilityNegociation()

    def do904(self, irc, msg):
        self.log.warning('%s: SASL authentication failed', irc.network)
        self.tryNextSaslMechanism(irc)

    def do905(self, irc, msg):
        self.log.warning('%s: SASL authentication failed because the '
                    'username or password is too long.', irc.network)
        self.tryNextSaslMechanism(irc)

    def do906(self, irc, msg):
        self.log.warning('%s: SASL authentication aborted', irc.network)
        self.tryNextSaslMechanism(irc)

    def do907(self, irc, msg):
        self.log.warning('%s: Attempted SASL authentication when we were already '
                    'authenticated.', irc.network)
        self.tryNextSaslMechanism(irc)

    def do908(self, irc, msg):
        self.log.info('%s: Supported SASL mechanisms: %s',
                 irc.network, msg.args[1])
        self.filterSaslMechanisms(irc, set(msg.args[1].split(',')))

    def doCap(self, irc, msg):
        subcommand = msg.args[1]
        if subcommand == 'ACK':
            self.doCapAck(irc, msg)
        elif subcommand == 'NAK':
            self.doCapNak(irc, msg)
        elif subcommand == 'LS':
            self.doCapLs(irc, msg)
        elif subcommand == 'NEW':
            self.doCapNew(irc, msg)

    def doCapAck(self, irc, msg):
        if len(msg.args) != 3:
            self.log.warning('Bad CAP ACK from server: %r', msg)
            return
        caps = msg.args[2].split()

        if 'sasl' in caps:
            if irc.network not in self._sasl_states:
                self._sasl_states[irc.network] = SaslState(irc.network)
            s = irc.state.capabilities_ls['sasl']
            if s is not None:
                self.filterSaslMechanisms(irc, set(s.split(',')))
            self.tryNextSaslMechanism(irc)

    def doCapLs(self, irc, msg):
        if msg.args[0] == '*':
            # Last message
            if 'sasl' not in irc.state.capabilities_ls:
                if irc.network in self._sasl_states:
                    del self._sasl_states[irc.network]
                irc.endCapabilityNegociation()

    def doCapNew(self, irc, msg):
        if not irc.state.authentication and 'sasl' in irc.state.capabilities_ls:
            self.resetSasl(irc)
            s = irc.state.capabilities_ls['sasl']
            if s is not None:
                self.filterSaslMechanisms(irc, set(s.split(',')))


Class = Authentication


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
