import frida
import struct
import ctypes
import sys
import os

TARGET_ADDR = 0x0000000000401156
TARGET_BIN = "./test"

MAP_SIZE = 65536
FORKSRV_FD = 198
SHM_ENV_VAR = "__AFL_SHM_ID"
MAX_LEN = 10

input_fname = None # use stdin
if len(sys.argv) > 1:
    input_fname = sys.argv[1]

shm_str = os.getenv(SHM_ENV_VAR)

if shm_str:
    shm_id = int(shm_str)
else:
    print(SHM_ENV_VAR, "is not set! You have to run this script from AFL++. Try afl-showmap if you want to run only one time the script.")
    sys.exit(-1)

with open("frida_script.js") as f:
    code = f.read()

has_frksrv = True
try:
    os.write(FORKSRV_FD + 1, b"\x00"*4)
except:
    has_frksrv = False

script = None
pid_bytes = "\x00"*4

def spawn(cmd, tgt_addr, code):
    global script, pid_bytes
    pid = frida.spawn(cmd)
    session = frida.attach(pid)

    script = session.create_script(code)
    script.load()

    script.exports.setupshm(shm_id)
    script.exports.settarget(tgt_addr, MAX_LEN)
    
    pid_bytes = struct.pack("I", pid)
    
    return pid

pid = spawn([TARGET_BIN], TARGET_ADDR, code)

if has_frksrv:
    while True:

        if len(os.read(FORKSRV_FD, 4)) != 4: sys.exit(2)
        
        if os.write(FORKSRV_FD + 1, pid_bytes) != 4: sys.exit(5)

        has_crash = False
        
        try:
            if input_fname is not None:
                with open(input_fname, "rb") as f:
                    payload = f.read()
            else:
                payload = os.read(0, MAX_LEN)

            try:
                m = script.exports.execute(payload.hex())
            except frida.core.RPCException as e:
                print (e)
                m = None
                has_crash = True

        except Exception:
            sys.exit(6)
        
        if has_crash:
            status = b'\x86\x00\x00\x00' # 134 abort
            pid = spawn([TARGET_BIN], TARGET_ADDR, code)
        else: status = b"\x00\x00\x00\x00"
        
        if os.write(FORKSRV_FD + 1, status) != 4: sys.exit(7)
else:
    has_crash = False
        
    try:
        payload = os.read(0, MAX_LEN)

        try:
            m = script.exports.execute(payload.hex())
        except frida.core.RPCException as e:
            print (e)
            m = None
            has_crash = True

    except Exception:
        sys.exit(6)
    
    if has_crash:
        sys.exit(134) # abort

sys.exit(0)
