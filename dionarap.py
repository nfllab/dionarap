#!/usr/bin/env python3

# Copyright 2021 Nagy Ferenc László
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import re

class LameRandom:
    def __init__(self, seed):
        x = seed & 0xffffffffffffffff
        x = ((x ^ (x >> 33)) * 0x62a9d9ed799705f5) & 0xffffffffffffffff
        x = ((x ^ (x >> 28)) * 0xcb24d0a5c88c35b3) & 0xffffffffffffffff
        self.state = x >> 32

    def __brotl(self, x, k):
        x &= 0xffff
        result = x << k
        if x >= 0x8000:
            result |= 0xffffffff >> (32 - k)
        return result & 0xffff

    def next(self):
        s0 = self.state & 0xffff
        s1 = (self.state >> 16) & 0xffff
        s2 = s1 ^ s0
        r0 = (self.__brotl(s0, 13) ^ (s2 << 5) ^ s2) & 0xffff
        r1 = self.__brotl(s2, 10) & 0xffff
        r2 = (self.__brotl(s0 + s1, 9) + s0) & 0xffff
        if r0 >= 0x8000:
            r1 = 0xffff
        if r1 >= 0x8000:
            r2 = 0xffff
        self.state = r1 << 16 | r0
        return r2

decoder_regex = re.compile(
        rb"\.class public (?P<classname>L[\w$/]+;)\s+"
        rb"\.super Ljava/lang/Object;.*"
        rb"\.method (?:public )?static constructor <clinit>\(\)V\s+"
        rb"\.registers 3\s+"
        rb"const/4 v0, 0x\d+\s+"
        rb"new\-array v0, v0, \[Ljava/lang/String;\s+"
        rb"sput\-object v0, (?P=classname)\->\w+:\[Ljava/lang/String;\s+"
        rb"const/4 v1, 0x0\s+"
        rb"const\-string v2, (?P<chunks>\".*\")\s+" # matches multiple chunks
        rb"aput\-object v2, v0, v1\s+"
        rb"return\-void\s+"
        rb"\.end method.*"
        rb"\.method public static (?P<methodname>\w+)\(J\)Ljava/lang/String;\s+"
        rb"\.registers 3\s+"
        rb"sget\-object v0, (?P=classname)\->\w+:\[Ljava/lang/String;\s+"
        rb"invoke\-static \{p0, p1, v0\}, L[\w$/]+;\->\w+\(J\[Ljava/lang/String;\)Ljava/lang/String;\s+"
        rb"move\-result\-object p0\s+"
        rb"return\-object p0\s+"
        rb"\.end method", re.DOTALL)

decoder_method = None # e.g. Lio/michaelrocks/paranoid/Deobfuscator$app$Debug;->getString

data = None # concatenated chunks

def get_string(id, data):
    r = LameRandom(id & 0xffffffff)
    low = r.next()
    high = r.next() << 16
    index = ((id >> 32) ^ low ^ high)
    length = data[index] ^ r.next()
    s = b""
    for i in range(length):
        charcode = data[index + i + 1] ^ r.next()
        if charcode >= 127 or charcode < 20 or charcode in [92, 34, 39]:
            s += b"\\u%04x" % charcode
        else:
            s += b"%c" % charcode
    return s

def get_s(id):
    return get_string(id & 0xffffffffffffffff, data) # make id positive

def replacement(match):
    reg = match.group(4)
    if reg == None: # decoded string is not used by the code
        reg = match.group(1)
    id = int(match.group(2), 0)
    inserted_instructions = match.group(3)
    return inserted_instructions + b'const-string ' + reg + b', "' + get_s(id) + b'"'

def replacement2(match):
    id1 = int(match.group(2), 0)
    inserted1 = match.group(3)
    id2 = int(match.group(5), 0)
    inserted2 = match.group(6)
    reg = match.group(7)
    return (
        b'const-string ' + reg + b', "' + get_s(id1) + b'"' + inserted1 +
        b'const-string ' + reg + b', "' + get_s(id2) + b'"' + inserted2)

def change_file(filename):
    with open(filename, "rb") as f:
        content = f.read()
    oldcontent = content
    # first check for special if-then style string substitution
    content = re.sub(
        rb"const\-wide ([vp]\d+), (\-?0x[0-9a-f]+)L(\s+"
        rb"goto :goto_(\w+)\s+"
        rb":cond_\w+\s+)"
        rb"const\-wide \1, (\-?0x[0-9a-f]+)L(\s+"
        rb":goto_\4\s+)"
        rb"invoke-static(?:/range)? \{\1(?:\,| \.\.) [vp]\d+\}, " +
        re.escape(decoder_method) +
        rb"\(J\)Ljava/lang/String;\s+"
        rb"move-result-object ([vp]\d+)\s+",
        replacement2, content, flags=re.DOTALL)
    # then handle the simpler case
    content = re.sub(
        rb"const\-wide ([vp]\d+), (\-?0x[0-9a-f]+)L\s+"
        # between the const-wide and the method call anything can be inserted,
        # except for:
        #     another const-wide
        #     a label that is not :try_*
        rb"((?:(?!const\-wide)(?!:(?!try_)).)*?)"
        rb"invoke-static(?:/range)? \{\1(?:\,| \.\.) [vp]\d+\}, " +
        re.escape(decoder_method) +
        rb"\(J\)Ljava/lang/String;(?:\s+move-result-object ([vp]\d+))?",
        replacement, content, flags=re.DOTALL)
    if oldcontent != content:
        with open(filename, "wb") as g:
            g.write(content)
            return 1
    return 0

def change_files(directory):
    changed = 0
    for root, dirs, files in os.walk(directory):
        for name in files:
            changed += change_file(os.path.join(root, name))
    print(changed, "file(s) was/were changed.")

def get_data(chunks_smali):
    s = b"".join(re.findall(rb'"(.*?)(?<!\\)"', chunks_smali))
    i = 0
    a = []
    while i < len(s):
        if s[i:i+2] == b"\\u":
            a.append(int(s[i+2:i+6], 16))
            i = i + 6
        elif s[i] == b"\\": # this branch was never tested
            c = s[i+1]
            if c == b"b":
                a.append(8)
            elif c == b"t":
                a.append(9)
            elif c == b"n":
                a.append(10)
            elif c == b"f":
                a.append(12)
            elif c == b"r":
                a.append(13)
            else:
                a.append(c)
            i = i + 2
        else:
            a.append(s[i])
            i = i + 1
    return a

def search_file(filename):
    with open(filename, "rb") as f:
        content = f.read()
    mo = decoder_regex.match(content)
    if (mo):
        global data, decoder_method
        decoder_method = mo.group("classname") + b"->" + mo.group("methodname")
        print("Decoder method detected:")
        print(decoder_method)
        data = get_data(mo.group("chunks"))

def search_method(directory):
    global data, decoder_method
    data = None
    decoder_method = None
    for root, dirs, files in os.walk(directory):
        for name in files:
            search_file(os.path.join(root, name))

def process(directory):
    search_method(directory)
    if decoder_method:
        change_files(directory)
    else:
        print("No decoder was found!")

parser = argparse.ArgumentParser(description='Decoder for https://github.com/MichaelRocks/paranoid.')
parser.add_argument('directory', nargs='+', help='directory with smali files')

args = parser.parse_args()

for directory in args.directory:
    process(directory)
