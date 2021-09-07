#!/usr/bin/env python3
import sys
import re

class Util:

  def replace(self, filename):
    doc = []
    with open(filename, "r", encoding="utf-8") as f:
      for line in f:
        doc.append(line)
    print(doc)
    for index in range(0, len(doc)):
      if re.search(r"utilHash\([^\n]+\)", doc[index]):
        string = re.search(r"(?<=utilHash\()[^\)]+", doc[index])
        doc[index] = re.sub(r"utilHash\([^\)]+\)", self.utilHashMasm(string.group(0)), doc[index])
    with open(filename + ".util", "w", encoding="utf-8") as f:
      for index in range(0, len(doc)):
        f.write(doc[index])


  def replaceTabs(self, filename):
    doc = []
    with open(filename, "r", encoding="utf-8") as f:
      for line in f:
        doc.append(line)
    for index in range(0, len(doc)):
      doc[index].replace("\t", 2)
    with open(filename + ".replaceTabs", "w", encodinv="utf-8") as f:
      for index in range(0, len(doc)):
        f.write(doc[index])

  def utilHash(self, s):
    rax = 5381
    for c in s:
      rdx = rax
      rax = rax << 5
      rax = rax + rdx
      al = (rax & 0xff) ^ ord(c) 
      rax = (rax & 0xffffffffffffff00) | al
    return rax

  def utilHashMasm(self, s):
    hashed = format(self.utilHash(s), "x").zfill(16) + "h"
    return "0" + hashed if hashed[0].isalpha() else hashed

  def utilHashPretty(self, s):
    return format(self.utilHash(s), "x").zfill(16) + " : " + s

if __name__ == "__main__":
  if len(sys.argv) > 1:
    util = Util()
    for s in range(1, len(sys.argv)):
      print(format(util.utilHash(sys.argv[s]), "x").zfill(16) + " : " + sys.argv[s])

