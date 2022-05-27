#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import hashlib
import os
import sys
import time

import frida

output_dir = './output'


def on_message(message, data):
    if message['payload'] == 'image':
        filename = hashlib.sha1(data).hexdigest() + '.gif'
        output = os.path.join(output_dir, filename)
        if os.path.exists(output):
            return

        with open(output, 'wb') as f:
            f.write(data)
        print(f"wrote {output}")
    else:
        print("[%s] => %s" % (message, data))


def main():
    session = frida.attach('WeChat.exe')

    script = session.create_script("""

    var baseAddr = Module.findBaseAddress("VoipEngine.dll");
    console.log("VoipEngine.dll baseAddr: " + baseAddr);
    
    if (baseAddr) {
      // isWxGF 函数偏移地址, 从 DLL 中查看
      var isWxGF = baseAddr.add(0x2fd760);
      console.log("isWxGF 函数地址: " + isWxGF);
    
      // hook 函数, 监听参数
      Interceptor.attach(isWxGF, {
        onEnter: function (args) {
          var gif = Memory.readByteArray(args[0], args[1].toInt32());
          send('image', gif);
        },
      });
    } else {
      console.log("VoipEngine.dll 模块未加载");
    }
""")
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        output_dir = sys.argv[1]
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    main()
