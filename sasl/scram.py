"""SCRAM-* SASL mechanisms per RFC 5802

Salted Challenge-Response Authentication Mechanism

Copyright (C) 2012, Wim Lewis <wiml@hhhh.org>.
"""

from __future__ import absolute_import
import random, hashlib, hmac, logging
from base64 import b64encode, b64decode
from sasl.mechanism import Mechanism, AuthState
import sasl.stringprep

__author__ = 'Wim Lewis <wiml@hhhh.org>'

ALPHA = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

class error(Exception):
    pass

def _saslname_decode(b):
    # Vaguely-QP-like escape mechanism.
    ( lhs, s, rhs ) = b.partition(b'=')
    while s:
        if rhs.startswith(b'2C'):
            lhs += b','
        elif rhs.startswith(b'3D'):
            lhs += b'='
        else: 
            # Don't allow other sequences from QP.
            raise error('invalid-username-encoding',
                        'Incorrectly encoded "saslname"')
        (l, s, rhs) = rhs[2:].partition(b'=')
        lhs += l
    return lhs
def _saslname_encode(b):
    b = b.replace(b'=', b'=3D').replace(b',', b'=2C')
    if b'\x00' in b:
        raise ValueError('Forbidden character in saslname')
    return b

def _splitmessage(msg):
    assert isinstance(msg, bytes)
    if msg == b'':
        return []
    parts = msg.split(b',')
    attributes = []
    for part in parts:
        if part == b'':
            attributes.append( None )
            continue
        elif part[1] != b'=':
            raise ValueError('attr-val syntax (rfc5802 7)')
        name = part[0]
        value = part[2:]
        if name in b'an':
            value = _saslname_decode(value)
        elif name in b'cspv':
            value = b64decode(value)
        elif name == b'i':
            value = int(value)
        elif name not in ALPHA:
            raise ValueError('attr-name not ALPHA (rfc5802 7)')
        attributes.append( (name, value) )
    return attributes

def _checkmessage(unchecked, items):
    # Mandatory extensions. We don't support any.
    if unchecked and unchecked[0] and unchecked[0][0] == 'm':
        raise error('extensions-not-supported',
                    'Unsupported extension %r' % (unchecked[0][1],))

    attributes = []
    for i in items:
        if not unchecked:
            raise ValueError('Missing field, expecting %r' % (i,))
        u = unchecked.pop(0)
        if u is None:
            raise ValueError('Empty field, expecting %r' % (i,))
        (k, v) = u
        if k != i:
            raise ValueError('Unexpected field %r, expecting %r' % (k, i))
        attributes.append(v)
    # Anything left in "unchecked" is an optional extension.
    return ( attributes, unchecked )

def PBKDF2_mini(password, salt, iterations, hashfunc):
    """Computes PBKDF2 per RFC2898 / PKCS#5, with the PRF
    set to HMAC(H), and lengths fixed by the hash function
    as described in RFC5802 2.2."""
    
    prf = hmac.HMAC(password, digestmod = hashfunc)
    h = prf.copy()
    h.update(salt + b"\x00\x00\x00\x01")
    U = h.digest()
    H = [ ord(c) for c in U ]
    while iterations > 1:
        h = prf.copy()
        h.update(U)
        U = h.digest()
        for i in range(len(H)):
            H[i] ^= ord(U[i])
        iterations -= 1
    return b''.join(chr(c) for c in H)

def _xorstr(s1, s2):
    assert len(s1) == len(s2)
    return b''.join(map(lambda a, b: chr(ord(a)^ord(b)), s1, s2))

class Scram(sasl.mechanism.Mechanism):
    SECURE = True
    _logger = None
    
    # Algorithm parameters
    nonce_length = 8   # Our nonces will be this long
    hashfunc = None    # Specified by concrete subclasses

    # Ranges of parameters we will accept from the other end
    minimum_nonce = 4
    minimum_salt = 8
    minimum_iterations = 1024
    maximum_iterations = 65536 # ?

    # Pre-authentication setup
    cbinding_types    = None  # or sequence of available types
    cbinding_data     = None  # data, or callable that type -> data
    cbinding_required = None  # True if auth must fail unless bound
    auth = None
    server_can_bind   = False

    # Derived from the above
    authz_prepped = None
    authn_prepped = None

    def __init__(self, auth):
        self.auth = auth
    def bind_channel(self, kinds, description, required=True):
        if not kinds or not len(kinds):
            kinds = None
            description = None
            required = None
        self.cbinding_types = kinds
        self.cbinding_data = description
        self.cbinding_required = required

    def generate_nonce(self,
                       length = None,
                       alphabet = ALPHA + b'1234567890!@#$%^&*()[]{}<>/|'):
        if length is None:
            length = self.nonce_length
        nonce = b''.join( (random.choice(alphabet) for i in range(length) ) )
        return nonce

    def prepare_names(self):
        authn = self.auth.username()
        authz = self.auth.authorization_id()
        if authz == authn or authz == u'':
            authz = None
        
        prep = sasl.stringprep.saslprep
        self.authn_prepped = _saslname_encode(prep(authn).encode('utf-8'))
        if authz is not None:
            self.authz_prepped = _saslname_encode(prep(authz).encode('utf-8'))
        else:
            self.authz_prepped = None

    def salt_key(self, password, salt, iterations):
        normpass = sasl.stringprep.saslprep(password).encode('utf-8')
        return PBKDF2_mini(normpass, salt, iterations, self.hashfunc)
    def derive_client_keys(self, saltedpassword,
                           clientkey=None, serverkey=None,
                           storedkey=None):
        
        if clientkey is None:
            clientkey = self.hmac(saltedpassword, b'Client Key')
        if serverkey is None:
            serverkey = self.hmac(saltedpassword, b'Server Key')
        if storedkey is None:
            storedkey = self.hashfunc(clientkey).digest()
        return ( clientkey, serverkey, storedkey )
    
    def hmac(self, key, message):
        h = hmac.HMAC(key, digestmod = self.hashfunc)
        h.update(message)
        return h.digest()

    def logger(self):
        if self._logger is None:
            self._logger = logging.getLogger(__name__)
        return self._logger
    def reportexc(self, ctxt, exc):
        self.logger().error('%s: %r' % (ctxt, exc), exc_info=True)
        if isinstance(exc, error):
            errstr = exc.args[0].encode('ascii')
        else:
            errstr = b'other-error'
        return AuthState(False, None, b'e='+errstr)            

    ## Client:
    ## 1. Issue IR with username and cbinding flag.
    ## 2. Compute response to server's challenge.
    ## 3. Verify server's final response.
    
    def respond(self, msg):
        if msg:
            self.logger().error('Protocol violation (initial challenge)')
            return AuthState(False, None, None)
        cnonce = self.generate_nonce()
        self.prepare_names()

        # Decide what kind of channel binding to ask for
        if self.cbinding_types is None:
            # We can't do channel binding.
            bindinfo = b'n'
            bindingdata = b''
        elif not self.server_can_bind and not self.cbinding_required:
            # We can but don't require it, and the server can't.
            bindinfo = b'y'
            bindingdata = b''
        else:
            binding_type = self.cbinding_types[0]
            bindinfo = b'p=' + binding_type
            bindingdata = self.cbinding_data
            if callable(bindingdata):
                bindingdata = bindingdata(binding_type)

        if self.authz_prepped is None:
            bindinfo = bindinfo + b',,'
        else:
            bindinfo = bindinfo + b',a=' + self.authz_prepped + b','

        first_message_bare = b'n=' + self.authn_prepped + b',r=' + cnonce
        state = ( cnonce, bindinfo + bindingdata )
        message = bindinfo + first_message_bare
        return AuthState(self.client_fr, state, message)
    def client_fr(self, state, msg):
        ( cnonce, cbind_input ) = state
        info = _checkmessage(_splitmessage(msg), b'rsi')
        if info is None:
            return AuthState(False, None, None)
        ( nonce, salt, iterations ) = info[0]
        if len(nonce) < ( len(cnonce) + self.minimum_nonce ):
            self.logger().error('Server nonce is too short')
            return AuthState(False, None, None)
        if not nonce.startswith(cnonce):
            self.logger().error('Incorrect nonce')
            return AuthState(False, None, None)
        if len(salt) < self.minimum_salt:
            self.logger().error('Needs more salt')
            return AuthState(False, None, None)
        if ( iterations < self.minimum_iterations or
             iterations > self.maximum_iterations ):
            self.logger().error('Bad iteration count %r', iterations)
            return AuthState(False, None, None)
        
        # Compute "client-final-message-without-proof"
        fmwp = b'c=' + b64encode( cbind_input ) + b',r=' + nonce

        # Compute "AuthMessage"
        first_message_bare = b'n=' + self.authn_prepped + b',r=' + cnonce
        authmessage = first_message_bare + b',' + msg + b',' + fmwp
        
        # TODO: Extend auth's client-side interface to allow caching the
        # salted password (or possibly the three derived keys)
        salted = self.salt_key(self.auth.password(), salt, iterations)
        (clientkey, serverkey, storedkey) = self.derive_client_keys(salted)
        
        # Compute "ClientSignature" and "ClientProof"
        proof = _xorstr(clientkey, self.hmac(storedkey, authmessage))
        expected_response = self.hmac(serverkey, authmessage)

        return AuthState(self.client_finish,
                         expected_response,
                         fmwp + b',p=' + b64encode(proof))
    def client_finish(self, expected_response, msg):
        info = _splitmessage(msg)
        ( k, v ) = info[0]
        if k == b'e':
            # Server error indication.
            self.logger().error('Server reports failure: %r', v)
            return AuthState(False, None, None)
        if k != b'v':
            # Protocol violation
            self.logger().error('Invalid server-final-response')
            return AuthState(False, None, None)
        
        # Validate the server-verifier.
        if v != expected_response:
            self.logger().error('ServerSignature does not verify')
            return AuthState(False, None, None)
        
        # Success.
        return AuthState(True, None, None)

    ## Server
    
    def challenge(self):
        # The exchange is initiated by the client.
        return AuthState(self.server_ir, None, b'')
    def server_ir(self, state, message):
        # The client's initial message violates format slightly.
        try:
            ( cbinding_req, authzid, first_message_bare ) = message.split(b',', 2)
            info = _checkmessage(_splitmessage(first_message_bare), b'nr')
            ( authnid, cnonce ) = info[0]
        except Exception, e:
            return self.reportexc('parsing initial client message', e)

        # Make sure the client is using the expected nonce.
        if len(cnonce) < self.minimum_nonce:
            self.logger().error('client nonce too short')
            return AuthState(False, None, b'e=other-error')
        
        # Check that we have the same ideas about channel binding.
        if cbinding_req == b'y':
            if self.cbinding_types is not None:
                self.logger().error('server DOES support channel binding')
                return AuthState(False, None, b'e=server-does-support-channel-binding')
            binding_type = None # we don't support it, that's OK.
        elif cbinding_req == b'n':
            if self.cbinding_required:
                self.logger().error('channel binding is required')
                return AuthState(False, None, b'e=channel-bindings-dont-match')
            binding_type = None # nobody wants it.
        elif cbinding_req.startswith(b'p='):
            binding_type = cbinding_req[2:]
            if self.cbinding_types is None:
                return AuthState(False, None, b'e=channel-binding-not-supported')
            elif binding_type not in self.cbinding_types:
                self.logger().error('unsupported channel binding type')
                return AuthState(False,None, b'e=unsupported-channel-binding-type')
        else:
            self.logger().error('unexpected GS2 header')
            return AuthState(False,None, b'e=unsupported-channel-binding-type')
        
        # Check that the usernames are valid.
        try:
            username = sasl.stringprep.saslprep(authnid.decode('utf-8'))
            if authzid is not None:
                authzname = sasl.stringprep.saslprep(authzid.decode('utf-8'))
            else:
                authzname = None
            
            uinfo = self.lookup_user(username)
            # This allows clients to cheaply probe for user names.
            # Should we optionally force them to go through the
            # auth procedure before telling them unknown-user ?
            if uinfo is None:
                return AuthState(False, None, b'e=unknown-user')
            ( storedkey, serverkey, salt, its ) = uinfo
        except UnicodeError, e:
            self.logger().error('client invalid-username-encoding: %r' % (e,))
            return AuthState(False, None, b'e=invalid-username-encoding')
        except Exception, e:
            return self.reportexc('retrieving user', e)


        nonce = cnonce + self.generate_nonce()
        response = b'r=%s,s=%s,i=%d' % ( nonce, b64encode(salt), its )

        state = (
            cbinding_req + b',' + ( authzid or b'' ) + b',',
            first_message_bare + b',' + response,
            username, authzname,
            storedkey, serverkey, binding_type, nonce
            )
        return AuthState(self.server_verify, state, response)
    def server_verify(self, state, msg):
        try:
            ( gs2_header, authmessage_prefix,
              username, authzname,
              storedkey, serverkey, binding_type, nonce ) = state
            ( without_proof, proof_part ) = msg.rsplit(b',', 1)
            if proof_part[:2] != b'p=':
                self.logger().error('client sent no proof')
                return AuthState(False, None, b'e=other-error')
            proof = b64decode(proof_part[2:])
            ( ( cbinding_again, nonce_again ), extensions ) = \
                _checkmessage(_splitmessage(without_proof), b'cr')
        except Exception, e:
            return self.reportexc('parsing client response', e)

        if nonce_again != nonce:
            self.logger().error('client nonce mismatch')
            return AuthState(False, None, b'e=invalid-proof')
        
        if binding_type is not None:
            if not cbinding_again.startswith(gs2_header):
                self.logger().error('client gs2-header mismatch')
                return AuthState(False, None, b'e=other-error')
            supplied_binding = cbinding_again[ len(gs2_header): ]
            actual_binding = self.cbinding_data
            if callable(actual_binding):
                actual_binding = actual_binding(binding_type)
            if supplied_binding != actual_binding:
                self.logger().error('channel binding mismatch')
                return AuthState(False, None, b'e=channel-bindings-dont-match')
        else:
            if cbinding_again != gs2_header:
                self.logger().error('client cbind-input mismatch')
                return AuthState(False, None, b'e=other-error')

        authmessage = authmessage_prefix + b',' + without_proof
        clientsignature = self.hmac(storedkey, authmessage)
        derived_clientkey = _xorstr(clientsignature, proof)
        derived_storedkey = self.hashfunc(derived_clientkey).digest()
        if storedkey != derived_storedkey:
            self.logger().info('client proof failed')
            return AuthState(False, None, b'e=invalid-proof')

        # TODO: Extend auth to support authorization checks w/o
        # simultaneous presence of plaintext password
        
        serversignature = self.hmac(serverkey, authmessage)
        return AuthState(True, None,
                         b'v=' + b64encode(serversignature))

    def lookup_user(self, username):
        # TODO: Write a version of auth that stores salted passwords.
        if username == u'user':
            # This is the example entry from RFC 5802.
            salt = b64decode('QSXCR+Q6sek8bf92')
            iterations = 4096
            ( _, serverkey, storedkey ) = self.derive_client_keys(self.salt_key(u'pencil', salt, iterations))
            return ( storedkey, serverkey, salt, iterations )
        raise error('unknown-user')
        
class ScramSHA1(Scram):
    hashfunc = hashlib.sha1
class ScramSHA1_Plus(ScramSHA1):
    server_can_bind = True

class ScramSHA256(Scram):
    hashfunc = hashlib.sha256
class ScramSHA256_Plus(ScramSHA256):
    server_can_bind = True

class ScramSHA512(Scram):
    hashfunc = hashlib.sha512
class ScramSHA512_Plus(ScramSHA512):
    server_can_bind = True
