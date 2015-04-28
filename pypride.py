# --                                                            ; {{{1
#
# File        : pypride.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-04-28
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.1.0
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""
Python PRIDE cipher implementation

Examples
--------

>>> from pypride import Pride

>>> key1      = "00000000000000000000000000000000".decode("hex")
>>> plain1    = "0000000000000000".decode("hex")
>>> cipher1   = Pride(key1)
>>> encrypted1 = cipher1.encrypt(plain1)
>>> encrypted1.encode("hex")
'82b4109fcc70bd1f'
>>> decrypted1 = cipher1.decrypt(encrypted1)
>>> decrypted1.encode("hex")
'0000000000000000'

>>> key2      = "00000000000000000000000000000000".decode("hex")
>>> plain2    = "ffffffffffffffff".decode("hex")
>>> cipher2   = Pride(key2)
>>> encrypted2 = cipher2.encrypt(plain2)
>>> encrypted2.encode("hex")
'd70e60680a17b956'
>>> decrypted2 = cipher2.decrypt(encrypted2)
>>> decrypted2.encode("hex")
'ffffffffffffffff'

>>> key3      = "ffffffffffffffff0000000000000000".decode("hex")
>>> plain3    = "0000000000000000".decode("hex")
>>> cipher3   = Pride(key3)
>>> encrypted3 = cipher3.encrypt(plain3)
>>> encrypted3.encode("hex")
'28f19f97f5e846a9'
>>> decrypted3 = cipher3.decrypt(encrypted3)
>>> decrypted3.encode("hex")
'0000000000000000'

>>> key4      = "0000000000000000ffffffffffffffff".decode("hex")
>>> plain4    = "0000000000000000".decode("hex")
>>> cipher4   = Pride(key4)
>>> encrypted4 = cipher4.encrypt(plain4)
>>> encrypted4.encode("hex")
'd123ebaf368fce62'
>>> decrypted4 = cipher4.decrypt(encrypted4)
>>> decrypted4.encode("hex")
'0000000000000000'

>>> key5      = "0000000000000000fedcba9876543210".decode("hex")
>>> plain5    = "0123456789abcdef".decode("hex")
>>> cipher5   = Pride(key5)
>>> encrypted5 = cipher5.encrypt(plain5)
>>> encrypted5.encode("hex")
'd1372929712d336e'
>>> decrypted5 = cipher5.decrypt(encrypted5)
>>> decrypted5.encode("hex")
'0123456789abcdef'

Links
-----

https://eprint.iacr.org/2014/453.pdf (specification)
https://www.gnu.org/licenses/lgpl-3.0.html (license)
"""
                                                                # }}}1

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
    self.roundkeys  = [ f(i+1, k1) for i in xrange(rounds) ]

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
      if i != self.rounds - 1:
        state = p_layer(state)
        state = l_layer(state)
        state = p_layer_inv(state)
    state = whiten(state, self.k0)  # k2 = k0
    state = p_layer(state)
    return int2str(state, 8)

  def decrypt(self, block):
    """
    Decrypt 1 block (8 bytes)

    block:    ciphertext block as rawstring
    returns:  plaintext block as rawstring
    """

    state = str2int(block)
    state = p_layer_inv(state)
    state = whiten(state, self.k0)  # k2 = k0
    for i in xrange(self.rounds):
      state = s_layer_inv(state)
      state = add_roundkey(state, p_layer_inv(self.roundkeys[-i-1]))
      if i != self.rounds - 1:
        state = p_layer(state)
        state = l_layer_inv(state)
        state = p_layer_inv(state)
    state = whiten(state, self.k0)
    state = p_layer(state)
    return int2str(state, 8)

  def get_block_size(self):
    return 8
                                                                # }}}1

def xor_key(state, key):
  """
  XOR key

  state:    state as integer
  key:      key as integer
  returns:  new state as integer
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

def l_layer(state, inv = False):
  """
  apply linear mappings L[0-3]

  state:    state as integer
  returns:  new state as integer
  """

  l = [L3,L2,L1,L0] if not inv else [L3_inv,L2_inv,L1_inv,L0_inv]
  state_ = 0
  for i in xrange(4):
    state_ |= matrix_mult(l[i], (state >> (i*16)) & 0xFFFF) << (i*16)
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
  returns:  new key part (1 byte) as integer
  """
  m = { 0: 193, 1: 165, 2: 81, 3: 197 }
  return (x + m[j]*i) % 256

def p():
  """
  permutation matrix (see specification)

  returns: array of indices as integers
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

L0 = [
  0b0000100010001000, 0b0000010001000100, 0b0000001000100010,
  0b0000000100010001, 0b1000000010001000, 0b0100000001000100,
  0b0010000000100010, 0b0001000000010001, 0b1000100000001000,
  0b0100010000000100, 0b0010001000000010, 0b0001000100000001,
  0b1000100010000000, 0b0100010001000000, 0b0010001000100000,
  0b0001000100010000,
]

L0_inv = L0

L1 = [
  0b1100000000010000, 0b0110000000001000, 0b0011000000000100,
  0b0001100000000010, 0b0000110000000001, 0b0000011010000000,
  0b0000001101000000, 0b1000000100100000, 0b1000000000011000,
  0b0100000000001100, 0b0010000000000110, 0b0001000000000011,
  0b0000100010000001, 0b0000010011000000, 0b0000001001100000,
  0b0000000100110000,
]

L1_inv = [
  0b0000001100000010, 0b1000000100000001, 0b1100000010000000,
  0b0110000001000000, 0b0011000000100000, 0b0001100000010000,
  0b0000110000001000, 0b0000011000000100, 0b0001000000011000,
  0b0000100000001100, 0b0000010000000110, 0b0000001000000011,
  0b0000000110000001, 0b1000000011000000, 0b0100000001100000,
  0b0010000000110000,
]

L2 = [
  0b0000110000000001, 0b0000011010000000, 0b0000001101000000,
  0b1000000100100000, 0b1100000000010000, 0b0110000000001000,
  0b0011000000000100, 0b0001100000000010, 0b0000100010000001,
  0b0000010011000000, 0b0000001001100000, 0b0000000100110000,
  0b1000000000011000, 0b0100000000001100, 0b0010000000000110,
  0b0001000000000011,
]

L2_inv = [
  0b0011000000100000, 0b0001100000010000, 0b0000110000001000,
  0b0000011000000100, 0b0000001100000010, 0b1000000100000001,
  0b1100000010000000, 0b0110000001000000, 0b0000000110000001,
  0b1000000011000000, 0b0100000001100000, 0b0010000000110000,
  0b0001000000011000, 0b0000100000001100, 0b0000010000000110,
  0b0000001000000011,
]

L3 = [
  0b1000100000001000, 0b0100010000000100, 0b0010001000000010,
  0b0001000100000001, 0b1000100010000000, 0b0100010001000000,
  0b0010001000100000, 0b0001000100010000, 0b0000100010001000,
  0b0000010001000100, 0b0000001000100010, 0b0000000100010001,
  0b1000000010001000, 0b0100000001000100, 0b0010000000100010,
  0b0001000000010001,
]

L3_inv = L3
                                                                # }}}1

def matrix_mult(m, v):
  """binary multiplication of 16x16 matrix w/ vector"""
  y = 0
  for i,r in enumerate(m):
    y |= (bin(r & v)[2:].count('1') % 2) << (15 - i)
  return y

def str2int(x):
  """convert rawstring to integer"""
  return int(x.encode("hex"), 16)

def int2str(x, n = 1):
  """convert integer to rawstring of length (at least) n"""
  return ("%0*x" % (n*2,x)).decode("hex")


if __name__ == "__main__":
  import doctest
  doctest.testmod()

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
