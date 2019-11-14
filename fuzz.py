import frida
import ctypes
import sys
import os

MAP_SIZE = 65536
FORKSRV_FD = 198
SHM_ENV_VAR = "__AFL_SHM_ID"
MAX_LEN = 4096

shm_str = os.getenv(SHM_ENV_VAR)

libc_so = {"darwin": "libc.dylib", "linux2": None, "linux": None}[sys.platform]
libc = ctypes.CDLL(libc_so, use_errno=True, use_last_error=True)

# void* shmat(int shmid, const void *shmaddr, int shmflg);
shmat = libc.shmat
shmat.restype = ctypes.c_void_p
shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)

with open("frida_script.js") as f:
    code = f.read()

if shm_str:
    shm_id = int(shm_str)
    #shm = multiprocessing.shared_memory.SharedMemory(shm_id)
    ptr = shmat(shm_id, 0, 0)
    shm = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_byte))
else:
    ba = bytearray(b"\x00" * MAP_SIZE)
    shm = memoryview(ba)

os.write(FORKSRV_FD + 1, b"\x00"*4)

payload = b"0000"

tgt_addr = 0x0000000000401156

pid = frida.spawn(["./test"])
session = frida.attach(pid)

script = session.create_script(code)
script.load()

script.exports.settarget(tgt_addr)

fake_pid = b"\x66\x00\x00\x00"

while True:

    if len(os.read(FORKSRV_FD, 4)) != 4: os.exit(2)
    
    if os.write(FORKSRV_FD + 1, fake_pid) != 4: os.exit(5)

    has_crash = False
    
    try:
        payload = os.read(0, MAX_LEN)

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
    except Exception:
        os.exit(6)
    
    if has_crash:
        status = '\x86\x00\x00\x00' # 134 abort
    else: status = b"\x00\x00\x00\x00"
    
    if os.write(FORKSRV_FD + 1, status) != 4: os.exit(7)

os.exit(0)
