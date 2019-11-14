import frida
import os

MAP_SIZE = 65536

payload = b"0000"

with open("frida_script.js") as f:
    code = f.read()

ba = bytearray(b"\x00" * MAP_SIZE)
shm = memoryview(ba)

tgt_addr = 0x0000000000401156

pid = frida.spawn(["./test"])
session = frida.attach(pid)

script = session.create_script(code)
script.load()

script.exports.settarget(tgt_addr)

has_crash = False
try:
    m = script.exports.execute(payload.hex())
except frida.core.RPCException as e:
    print (e)
    m = None
    has_crash = True

if m is None:
    m = script.exports.getcov()

for i in m:
    shm[int(i)] = m[i]
    if m[i] != 0:
        print (i, m[i])

if has_crash:
    os.abort()

