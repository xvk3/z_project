#!/usr/bin/env python3
import sys

class Util:
  def utilHash(self, s):
    rax = 5381
    for c in s:
      rdx = rax
      rax = rax << 5
      rax = rax + rdx
      al = (rax & 0xff) ^ ord(c) 
      rax = (rax & 0xffffffffffffff00) | al
    return rax

  def utilHashPretty(self, s):
    return format(self.utilHash(s), "x").zfill(16) + " : " + s

if __name__ == "__main__":
  if len(sys.argv) > 1:
    util = Util()
    for s in range(1, len(sys.argv)):
      print(format(util.utilHash(sys.argv[s]), "x").zfill(16) + " : " + sys.argv[s])

