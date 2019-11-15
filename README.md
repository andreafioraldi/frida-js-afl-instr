# frida-js-afl-instr

One upon a time there was frizzer, a fuzzer based on Frida, and a guy, Andrea, that sometimes writes stuffs for the awesome project AFLplusplus.
One day Andrea found frizzer while walking on GitHub and so decided to try to implement an instrumentation for AFLplusplus based on Frida with the aim to discover bugs in Andorid applications.
That day, Andrea loosed 2 hours of his precious time.

This shit **works**. How works is a problem. 3 exec/s on my laptop fuzzing the test binary.

Do you want to use it? Good luck.

`afl-fuzz -U -i in -o out -- python3 fuzz.py`

PS: I'll try to create something usable for fuzzing with Frida, maybe it will take some time and the reengineering of some parts of frida-gum with a performance-oriented translation mechanism. Stay tuned.
Thanks to Ole for the patience in advance.
