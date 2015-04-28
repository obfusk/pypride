# --                                                            ; {{{1
#
# File        : pypride.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-04-28
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.1
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""

Python PRIDE implementation

Examples
--------

>>> from pypride import Pride

>>> key1      = "00000000000000000000000000000000".decode("hex")
>>> plain1    = "0000000000000000".decode("hex")
>>> cipher1   = Pride(key1)
>>> encrypted1 = cipher1.encrypt(plain1)
>>> encrypted1.encode("hex")
"82b4109fcc70bd1f"
>>> decrypted1 = cipher1.decrypt(encrypted1)
>>> decrypted1.encode("hex")
"0000000000000000"

>>> key2      = "00000000000000000000000000000000".decode("hex")
>>> plain2    = "ffffffffffffffff".decode("hex")
>>> cipher2   = Pride(key2)
>>> encrypted2 = cipher2.encrypt(plain2)
>>> encrypted2.encode("hex")
"d70e60680a17b956"
>>> decrypted2 = cipher2.decrypt(encrypted2)
>>> decrypted2.encode("hex")
"ffffffffffffffff"

>>> key3      = "ffffffffffffffff0000000000000000".decode("hex")
>>> plain3    = "0000000000000000".decode("hex")
>>> cipher3   = Pride(key3)
>>> encrypted3 = cipher3.encrypt(plain3)
>>> encrypted3.encode("hex")
"28f19f97f5e846a9"
>>> decrypted3 = cipher3.decrypt(encrypted3)
>>> decrypted3.encode("hex")
"0000000000000000"

>>> key4      = "0000000000000000ffffffffffffffff".decode("hex")
>>> plain4    = "0000000000000000".decode("hex")
>>> cipher4   = Pride(key4)
>>> encrypted4 = cipher4.encrypt(plain4)
>>> encrypted4.encode("hex")
"d123ebaf368fce62"
>>> decrypted4 = cipher4.decrypt(encrypted4)
>>> decrypted4.encode("hex")
"0000000000000000"

>>> key5      = "0000000000000000fedcba9876543210".decode("hex")
>>> plain5    = "0123456789abcdef".decode("hex")
>>> cipher5   = Pride(key5)
>>> encrypted5 = cipher5.encrypt(plain5)
>>> encrypted5.encode("hex")
"d1372929712d336e"
>>> decrypted5 = cipher5.decrypt(encrypted5)
>>> decrypted5.encode("hex")
"0123456789abcdef"

Links
-----

https://eprint.iacr.org/2014/453.pdf (specification)
https://www.gnu.org/licenses/lgpl-3.0.html (license)

"""
                                                                # }}}1

import numpy

class Pride(object):                                            # {{{1

  """PRIDE cipher"""

  def __init__(self, key, rounds = 20):
    """
    Create a PRIDE cipher object

    key:      the key as a 128-bit rawstring
    rounds:   the number of rounds as an integer (32 by default)
    """

    if len(key) != 16:
      raise ValueError, "Key must be a 128-bit rawstring"

    self.k0, k1     = str2int(key[:8]), key[8:]
    self.rounds     = rounds
    self.roundkeys  = [ f(i, k1) for i in xrange(rounds) ]

  def encrypt(self, block):
    """
    Encrypt 1 block (8 bytes)

    block:    plaintext block as rawstring
    returns:  ciphertext block as rawstring
    """

    state = str2int(block)
    state = p_layer_inv(state)
    state = whiten(state, self.k0)
    for i in xrange(self.rounds):
      state = add_roundkey(state, p_layer_inv(self.roundkeys[i]))
      state = s_layer(state)
      if i != self.rounds -1:
        state = p_layer(state)
        state = l_layer(state)
        state = p_layer_inv(state)
    state = whiten(state, self.k0)  # k2 = k0
    state = p_layer(state)
    return int2str(state, 8)

  # TODO
  def decrypt(self, block):
    """
    Decrypt 1 block (8 bytes)

    block:    plaintext block as rawstring
    returns:  ciphertext block as rawstring
    """

    return ""

  def get_block_size(self):
    return 8
                                                                # }}}1

def xor_key(state, key):
  """
  XOR key

  state:    state as integer
  key:      key as integer
  returns:  state as integer
  """

  return state ^ key

whiten        = xor_key   # key whitening
add_roundkey  = xor_key   # add round key

def p_layer(state, inv = False):
  """
  apply permutation matrix P

  state:    state as integer
  returns:  new state as integer
  """

  p = P if not inv else P_inv
  state_ = 0
  for i in xrange(64):
    state_ |= ((state >> i) & 0b1) << p[i]
  return state_

def p_layer_inv(state):
  """apply permutation matrix P_inv"""
  return p_layer(state, True)

def s_layer(state, inv = False):
  """
  apply S-box S

  state:    state as integer
  returns:  new state as integer
  """

  s = S if not inv else S_inv
  state_ = 0
  for i in xrange(16):
    state_ |= s[(state >> (i*4)) & 0xF] << (i*4)
  return state_

def s_layer_inv(state):
  """apply S-box S_inv"""
  return s_layer(state, True)

# TODO
def l_layer(state, inv = False):
  """
  apply linear mappings L[0-3]

  state:    state as integer
  returns:  new state as integer
  """

  l = [L3,L2,L1,L0] if not inv else [L3_inv,L2_inv,L1_inv,L0_inv]
  state_ = 0
  for i in xrange(4):
    x = (state >> (i*16)) & 0xFFFF
    y = bits2int((int2bits(x, 16) * l[i] % 2).tolist()[0])
    state_ |= y << (i*16)
  return state_

def l_layer_inv(state):
  """apply linear mappings L[0-3]_inv"""
  return l_layer(state, True)

def f(i, k1):
  """
  round key (see specification)

  i:        round number (1 <= i <= rounds)
  k1:       round key basis as rawstring
  returns:  round key as integer
  """
  return str2int("".join(
    int2str(g(str2int(k1[j]), i, j // 2)) if j%2 else k1[j]
      for j in xrange(8)
  ))

def g(x, i, j):
  """
  dynamic part of round key (see specification)

  x:        key part (1 byte) as integer
  i:        round number
  j:        part number (0 <= j <= 3)
  returns:  new key part (1 byte) integer
  """
  m = { 0: 193, 1: 165, 2: 81, 3: 197 }
  return (x + m[j]*i) % 256

def p():
  """
  permutation matrix (see specification)

  returns: array of indices as interers
  """
  m = [None]*64
  for i in xrange(4):
    for j in xrange(16):
      m[63-(j*4+i)] = (3-i)*16+(15-j)
  return m

P     = p()
S     = [ 0x0, 0x4, 0x8, 0xF, 0x1, 0x5, 0xE, 0x9,
          0x2, 0x7, 0xA, 0xC, 0xB, 0xD, 0x6, 0x3 ]

P_inv = [ P.index(i) for i in xrange(64) ]
S_inv = [ S.index(i) for i in xrange(16) ]
del i # leaky scope

# L[0-3]{,_inv}                                                 # {{{1

L0 = numpy.matrix([
  [ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0 ],
])

L0_inv = L0

L1 = numpy.matrix([
  [ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 ],
  [ 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1 ],
  [ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0 ],
])

L1_inv = numpy.matrix([
  [ 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 ],
])

L2 = numpy.matrix([
  [ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 ],
  [ 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1 ],
])

L2_inv = numpy.matrix([
  [ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1 ],
])

L3 = numpy.matrix([
  [ 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0 ],
  [ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1 ],
  [ 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 ],
  [ 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 ],
  [ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0 ],
  [ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1 ],
])

L3_inv = L3
                                                                # }}}1


def str2int(x):
  """convert rawstring to integer"""
  return int(x.encode("hex"), 16)

def int2str(x, n = 1):
  """convert integer to rawstring of length (at least) n"""
  return ("%0*x" % (n*2,x)).decode("hex")

def int2bits(x, n = 1):
  """convert integer to bit vector of length (at least n)"""
  f = "{:0"+str(int(n))+"b}"
  return list(reversed(map(int, list(f.format(x)))))

def bits2int(v):
  """convert bit vector to integer"""
  x = 0
  for i in xrange(len(v)): x |= v[i] << i
  return x


if __name__ == "__main__":
  import doctest
  doctest.testmod()

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
