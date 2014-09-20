#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#    This program is free software: you can redistribute it and/or modify it
#    under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of
#    the License, or (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Affero General Public License for more details.

#    You should have received a copy of the GNU Affero General Public
#    License along with this program. If not, see
#    <http://www.gnu.org/licenses/>.

# for example usage see test() at the end of the file.

# (C) 2014 by Stefan Marsiske, <s@ctrlc.hu>

import struct
import pysodium as nacl
from SecureString import clearmem
import scrypt

KEY_SIZE = nacl.crypto_secretbox_KEYBYTES

class AxolotlCTX(object):
    """State
    ------
    Each party stores the following values per conversation in persistent storage:

    RK           : 32-byte root key which gets updated by DH ratchet
    HKs, HKr     : 32-byte header keys (send and recv versions)
    NHKs, NHKr   : 32-byte next header keys (")
    CKs, CKr     : 32-byte chain keys (used for forward-secrecy updating)
    DHIs, DHIr   : ECDH Identity keys
    DHRs, DHRr   : ECDH Ratchet keys
    Ns, Nr       : Message numbers (reset to 0 with each new ratchet)
    PNs          : Previous message numbers (# of msgs sent under prev ratchet)
wtf:ratchet_flag : True if the party will send a new ratchet key in next msg
    skipped_HK_MK : A list of stored message keys and their associated header keys
                    for "skipped" messages, i.e. messages that have not been
                    received despite the reception of more recent messages.
                    Entries may be stored with a timestamp, and deleted after a
                    certain age.
    """

    def __init__(self, me):
        self.me            = me
        self.peer          = None
        self.isalice       = None
        self.RK            = None
        self.HKs           = None
        self.HKr           = None
        self.NHKs          = None
        self.NHKr          = None
        self.CKs           = None
        self.CKr           = None
        self.DHIs          = me.identitykey
        self.DHIr          = None
        self.ephemeralkey  = Key().new()
        self.DHRs          = Key().new()
        self.DHRr          = None
        self.Ns            = 0
        self.Nr            = 0
        self.PNs           = 0
        self.bobs1stmsg    = False
        self.skipped_HK_MK = {}
        self.staged_HK_MK  = {}

    def aspeer(self):
        """ returns a dict containing the public components of the
        - identitykey
        - ephemeralkey
        - DHRs
        This dict needs to be transfered to the other peer for
        initializing the ratchet.
        """
        return {'identitykey': self.me.identitykey.pk,
                'ephemeralkey': self.ephemeralkey.pk,
                'DHRs': self.DHRs.pk }

    def init(self, peer):
        """
        as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

        Key Agreement
        --------------
        - Parties exchange identity keys (A,B) and handshake keys (Ah,Ai) and (Bh,Bi)
        - Parties assign themselves "Alice" or "Bob" roles by comparing public keys
        - Parties perform triple-DH with (A,B,Ah,Bh) and derive initial keys:
        Alice:
        KDF from triple-DH: RK, HKs, HKr, NHKs, NHKr, CKs, CKr
        DHIs, DHIr = A, B
        DHRs, DHRr = <none>, Bi
        Ns, Nr = 0, 0
        PNs = 0
        bobs_first_message = False
        Bob:
        KDF from triple-DH: RK, HKr, HKs, NHKr, NHKs, CKr, CKs
        DHIs, DHIr = B, A
        DHRs, DHRr = Bi, <none>
        Ns, Nr = 0, 0
        PNs = 0
        bobs_first_message = True
        """

        self.peer          = peer
        self.DHIr          = peer['identitykey']
        self.isalice       = self.me.identitykey.pk <= peer['identitykey']
        mk = self.tripledh()
        self.RK            = scrypt.hash(mk, "RK")[:KEY_SIZE]
        if self.isalice:
            self.DHRr      = peer['DHRs']
            self.DHRs      = None
            self.HKs           = scrypt.hash(mk, "HKs")[:KEY_SIZE]
            self.HKr           = scrypt.hash(mk, "HKr")[:KEY_SIZE]
            self.NHKs          = scrypt.hash(mk, "NHKs")[:KEY_SIZE]
            self.NHKr          = scrypt.hash(mk, "NHKr")[:KEY_SIZE]
            self.CKs           = scrypt.hash(mk, "CKs")[:KEY_SIZE]
            self.CKr           = scrypt.hash(mk, "CKr")[:KEY_SIZE]
            self.bobs1stmsg    = False
        else:
            self.HKs           = scrypt.hash(mk, "HKr")[:KEY_SIZE]
            self.HKr           = scrypt.hash(mk, "HKs")[:KEY_SIZE]
            self.NHKs          = scrypt.hash(mk, "NHKr")[:KEY_SIZE]
            self.NHKr          = scrypt.hash(mk, "NHKs")[:KEY_SIZE]
            self.CKs           = scrypt.hash(mk, "CKr")[:KEY_SIZE]
            self.CKr           = scrypt.hash(mk, "CKs")[:KEY_SIZE]
            self.bobs1stmsg    = True

        clearmem(mk)
        mk = None

    #def __repr__(self):
    #    return "<AxolotlCtx %s:%s>" % (self.me, self.peer)

    def tripledh(self):
        """Triple DH performs cross DH between two peers having two keys
        each:

        - an identity key (Ai,Bi), and
        - an ephemeral key (Ae, Be).

        the cross DH is then performed on these pairs:
        (Ai,Be)+(Bi,Ae)+(Ae,Be) The order of the parameters to these
        operations depends on the order in which the peers are acting.
        """
        if self.isalice:
            p1 = nacl.crypto_scalarmult_curve25519(self.me.identitykey.sk, self.peer['ephemeralkey'])
            p2 = nacl.crypto_scalarmult_curve25519(self.ephemeralkey.sk, self.peer['identitykey'])
            p3 = nacl.crypto_scalarmult_curve25519(self.ephemeralkey.sk, self.peer['ephemeralkey'])
            sec = p1+p2+p3
            clearmem(p1)
            clearmem(p2)
            clearmem(p3)
            res = nacl.crypto_generichash(sec, '', nacl.crypto_secretbox_KEYBYTES)
            clearmem(sec)
            return res
        p1 = nacl.crypto_scalarmult_curve25519(self.ephemeralkey.sk, self.peer['identitykey'])
        p2 = nacl.crypto_scalarmult_curve25519(self.me.identitykey.sk, self.peer['ephemeralkey'])
        p3 = nacl.crypto_scalarmult_curve25519(self.ephemeralkey.sk, self.peer['ephemeralkey'])
        sec = p1+p2+p3
        clearmem(p1)
        clearmem(p2)
        clearmem(p3)
        res = nacl.crypto_generichash(sec, '', nacl.crypto_secretbox_KEYBYTES)
        clearmem(sec)
        return res

    def send(self, msg):
        """
        as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

        Sending messages
        -----------------
        Local variables:
          MK  : message key

        if DHRs == <none>:
          DHRs = generateECDH()
        MK = HASH(CKs || "0")
        msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
        Ns = Ns + 1
        CKs = HASH(CKs || "1")
        return msg
        """
        if self.DHRs == None:
            self.DHRs = Key().new()
            self.PNs = self.Ns # wtf: not in spec, but seems needed
            self.Ns = 0 # wtf: not in spec, but seems needed
        mk = scrypt.hash(self.CKs, 'MK')[:nacl.crypto_secretbox_KEYBYTES]
        hnonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)
        mnonce = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES)

        msg = ''.join((hnonce,
                       mnonce,
                       nacl.crypto_secretbox(
                           ''.join((struct.pack('>I',self.Ns),
                                    struct.pack('>I',self.PNs),
                                    self.DHRs.pk)),
                           hnonce, self.HKs),
                       nacl.crypto_secretbox(msg, mnonce, mk)))
        clearmem(mk)
        mk = None
        self.Ns += 1
        self.CKs = scrypt.hash(self.CKs, "CK")[:nacl.crypto_secretbox_KEYBYTES]
        return msg

    def stage_skipped_keys(self, HK, Nr, Np, CK):
        """
        stage_skipped_header_and_message_keys() : Given a current header key, a current message number,
        a future message number, and a chain key, calculates and stores all skipped-over message keys
        (if any) in a staging area where they can later be committed, along with their associated
        header key.  Returns the chain key and message key corresponding to the future message number.
        """
        for _ in xrange(Np - Nr):
            mk = scrypt.hash(CK, 'MK')[:nacl.crypto_secretbox_KEYBYTES]
            self.staged_HK_MK[mk] = HK
            CK = scrypt.hash(CK, 'CK')[:nacl.crypto_secretbox_KEYBYTES]
        mk = scrypt.hash(CK, 'MK')[:nacl.crypto_secretbox_KEYBYTES]
        CK = scrypt.hash(CK, 'CK')[:nacl.crypto_secretbox_KEYBYTES]
        return CK, mk

    def try_skipped_keys(self, hcrypt, hnonce, mcrypt, mnonce):
        for mk, hkr in self.skipped_HK_MK.items():
            try: nacl.crypto_secretbox_open(hcrypt, hnonce, hkr)
            except: continue
            try: msg = nacl.crypto_secretbox_open(mcrypt, mnonce, mk)
            except: continue
            del self.skipped_HK_MK[mk]
            return msg

    def recv(self, msg):
        """
        as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

        Receiving messages
        -------------------
        Local variables:
          MK  : message key
          Np  : Purported message number
          PNp : Purported previous message number
          CKp : Purported new chain key
          DHp : Purported new DHr
          RKp : Purported new root key
          NHKp, HKp : Purported new header keys

        if (plaintext = try_skipped_header_and_message_keys()):
          return plaintext

        if Dec(HKr, header):
          Np = read()
          CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
          if not Dec(MK, ciphertext):
            raise undecryptable
          if bobs_first_message:
            DHRr = read()
            RK = HASH(RK || ECDH(DHRs, DHRr))
            HKs = NHKs
            NHKs, CKs = KDF(RK)
            erase(DHRs)
            bobs_first_message = False
        else:
          if not Dec(NHKr, header):
            raise undecryptable()
          Np, PNp, DHRp = read()
          stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
          RKp = HASH(RK || ECDH(DHRs, DHRr))
          HKp = NHKr
          NHKp, CKp = KDF(RKp)
          CKp, MK = stage_skipped_header_and_message_keys(HKp, 0, Np, CKp)
          if not Dec(MK, ciphertext):
            raise undecryptable()
          RK = RKp
          HKr = HKp
          NHKr = NHKp
          DHRr = DHRp
          RK = HASH(RK || ECDH(DHRs, DHRr))
          HKs = NHKs
          NHKs, CKs = KDF(RK)
          erase(DHRs)
        commit_skipped_header_and_message_keys()
        Nr = Np + 1
        CKr = CKp
        return read()
        """

        hnonce = msg[:nacl.crypto_secretbox_NONCEBYTES]
        i = nacl.crypto_secretbox_NONCEBYTES
        mnonce = msg[i:i+nacl.crypto_secretbox_NONCEBYTES]
        i += nacl.crypto_secretbox_NONCEBYTES
        hcrypt = msg[i:i + nacl.crypto_secretbox_MACBYTES + 4 + 4 + nacl.crypto_scalarmult_curve25519_BYTES]
        i += nacl.crypto_secretbox_MACBYTES + 4 + 4 + nacl.crypto_scalarmult_curve25519_BYTES
        mcrypt = msg[i:]

        ret = self.try_skipped_keys(hcrypt, hnonce, mcrypt, mnonce)
        if ret:
            return ret

        headers = None
        try: headers = nacl.crypto_secretbox_open(hcrypt, hnonce, self.HKr)
        except: pass
        if headers:
            Np = struct.unpack('>I',headers[:4])[0]
            CKp, MK = self.stage_skipped_keys(self.HKr, self.Nr, Np, self.CKr)
            msg = nacl.crypto_secretbox_open(mcrypt, mnonce, MK)
            if self.bobs1stmsg:
                self.DHRr = headers[8:]
                self.RK = scrypt.hash(self.RK, nacl.crypto_scalarmult_curve25519(self.DHRs.sk,self.DHRr))[:KEY_SIZE]
                self.HKs = self.NHKs
                if self.isalice:
                    self.NHKs = scrypt.hash(self.RK, "NHKs")[:KEY_SIZE]
                    self.CKs = scrypt.hash(self.RK, "CKs")[:KEY_SIZE]
                else:
                    self.NHKs = scrypt.hash(self.RK, "NHKr")[:KEY_SIZE]
                    self.CKs = scrypt.hash(self.RK, "CKr")[:KEY_SIZE]
                self.DHRs.clear()
                self.DHRs = None
                self.bobs1stmsg = False
        else:
            headers = nacl.crypto_secretbox_open(hcrypt, hnonce, self.NHKr)
            #unpack header fields
            Np = struct.unpack('>I',headers[:4])[0]
            PNp = struct.unpack('>I',headers[4:8])[0]
            DHRp = headers[8:]
            self.stage_skipped_keys(self.HKr, self.Nr, PNp, self.CKr)
            RKp = scrypt.hash(self.RK, nacl.crypto_scalarmult_curve25519(self.DHRs.sk,self.DHRr))[:KEY_SIZE]
            HKp = self.NHKr
            if self.isalice:
                NHKp = scrypt.hash(RKp, "NHKr")[:KEY_SIZE]
                CKp = scrypt.hash(RKp, "CKr")[:KEY_SIZE]
            else:
                NHKp = scrypt.hash(RKp, "NHKs")[:KEY_SIZE]
                CKp = scrypt.hash(RKp, "CKs")[:KEY_SIZE]
            CKp, MK = self.stage_skipped_keys(HKp, 0, Np, CKp)
            msg = nacl.crypto_secretbox_open(mcrypt, mnonce, MK)
            self.RK = RKp
            self.HKr = HKp
            self.NHKr = NHKp
            self.DHRr = DHRp
            self.RK = scrypt.hash(self.RK, nacl.crypto_scalarmult_curve25519(self.DHRs.sk,self.DHRr))[:KEY_SIZE]
            self.HKs = self.NHKs
            if self.isalice:
                self.NHKs = scrypt.hash(self.RK, "NHKs")[:KEY_SIZE]
                self.CKs = scrypt.hash(self.RK, "CKs")[:KEY_SIZE]
            else:
                self.NHKs = scrypt.hash(self.RK, "NHKr")[:KEY_SIZE]
                self.CKs = scrypt.hash(self.RK, "CKr")[:KEY_SIZE]
            self.DHRs.clear()
            self.DHRs = None

        # commit_skipped_header_and_message_keys() : Commits any skipped-over message keys from the
        # staging area to persistent storage (along with their associated header keys).
        self.skipped_HK_MK.update(self.staged_HK_MK)
        self.staged_HK_MK = {}

        self.Nr = Np + 1
        self.CKr = CKp
        return msg

class Key(object):
    def __init__(self):
        self.pk = None
        self.sk = None

    def new(self):
        self.sk = nacl.randombytes(nacl.crypto_scalarmult_curve25519_BYTES)
        self.pk = nacl.crypto_scalarmult_curve25519_base(self.sk)
        return self

    def clear(self):
        clearmem(self.sk)
        self.sk = None
        self.pk = None

class Peer(object):
    def __init__(self, name):
        self.name = name
        self.identitykey = Key().new() # or rather load it.

def context(ctx1, ctx2):
    for k in ctx1.__dict__.keys():
        if repr(ctx1.__dict__[k]) == repr(ctx2.__dict__[k]):
            print "= %-20s %s" % (k, repr(ctx1.__dict__[k]))
        else:
            print " %-20s %s" % (k, repr(ctx1.__dict__[k]))
            print " " * 21, repr(ctx2.__dict__[k])

def test():
    peer1 = Peer('peer1')
    peer2 = Peer('peer2')

    ctx1 = AxolotlCTX(peer1)
    ctx2 = AxolotlCTX(peer2)

    ctx1.init(ctx2.aspeer())
    ctx2.init(ctx1.aspeer())

    assert(ctx1.RK == ctx2.RK)
    assert(ctx2.recv(ctx1.send("howdy")) == 'howdy')
    assert(ctx2.recv(ctx1.send("2nd howdy")) == '2nd howdy')
    assert(ctx1.recv(ctx2.send("re")) == 're')
    assert(ctx2.recv(ctx1.send("rere")) == 'rere')
    assert(ctx2.recv(ctx1.send("2nd rere")) == '2nd rere')
    assert(ctx1.recv(ctx2.send("rerere")) == 'rerere')
    # some out of order sending
    msgx1 = ctx2.send("aaaaa")
    msg1 = ctx1.send("000000")
    msg2 = ctx1.send("111111")
    msgx2 = ctx2.send("bbbbb")
    msgx3 = ctx2.send("ccccc")
    msg3 = ctx1.send("222222")
    msg4 = ctx1.send("333333")
    msgx4 = ctx2.send("ddddd")
    assert(ctx2.recv(msg2) == '111111')
    msg5 = ctx1.send("444444")
    assert(ctx2.recv(msg5) == '444444')
    msgx5 = ctx2.send("eeeee")
    assert(ctx1.recv(msgx1) == 'aaaaa')
    assert(ctx1.recv(msgx3) == 'ccccc')
    assert(ctx1.recv(msgx5) == 'eeeee')
    assert(ctx2.recv(msg4) == '333333')
    assert(ctx1.recv(msgx4) == 'ddddd')
    assert(ctx2.recv(msg3) == '222222')
    assert(ctx1.recv(msgx2) == 'bbbbb')
    assert(ctx2.recv(msg1) == '000000')

    # back to normal exchanges
    assert(ctx2.recv(ctx1.send("re howdy")) == 're howdy')
    assert(ctx1.recv(ctx2.send("howdy re")) == 'howdy re')

if __name__ == '__main__':
    test()
