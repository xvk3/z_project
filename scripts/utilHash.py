#!/usr/bin/env python3
import sys

def utilHash(s):
  rax = 5381
  for c in s:
    rdx = rax
    rax = rax << 5
    rax = rax + rdx
    al = (rax & 0xff) ^ ord(c) 
    rax = (rax & 0xffffffffffffff00) | al
  return rax

if __name__ == "__main__":
  if len(sys.argv) > 1:
    for s in range(1, len(sys.argv)):
      print(format(utilHash(sys.argv[s]), "x").zfill(16) + " : " + sys.argv[s])

