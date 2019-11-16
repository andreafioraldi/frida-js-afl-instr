'use strict'

// some code from frizzer: https://github.com/demantz/frizzer

var shmat_addr = Module.findExportByName(null, "shmat");

var shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);

var MAP_SIZE = 65536;

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

var afl_area_ptr = undefined;
var target_function = undefined;

var payload_memory = undefined;

// Stalker tuning
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;

var maps = function() {

    var maps = Process.enumerateModulesSync();
    var i = 0;
    
    /* Add an id to each module */
    maps.map(function(o) { o.id = i++; });
    /* Add an end address to each module */
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;

}();

rpc.exports = {

    vmmap: function(args) {
        return maps;
    },
    getpid: function(args) {
        return Process.id;
    },

    setupshm: function(shm_id) {
    
      afl_area_ptr = shmat(shm_id, ptr(0), 0);
    
    },

    /* Initialize the address of the target function (to-be-hooked) and attach
       the Interceptor */
    settarget: function(target, max_len) {
        target_function = ptr(target);

        payload_memory = Memory.alloc(max_len);

        var prev_loc = 0;
        function afl_maybe_log (context) {
          
          var cur_loc = context.pc.toInt32();
          
          cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
          cur_loc &= MAP_SIZE - 1;

          //afl_area[cur_loc ^ prev_loc]++;
          
          var x = afl_area_ptr.add(cur_loc ^ prev_loc);
          x.writeU8((x.readU8() +1) & 0xff);

          prev_loc = cur_loc >> 1;

        }
        
        //var prev_loc_ptr = Memory.alloc(32);
        
        Stalker.follow(Process.getCurrentThreadId(), {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: true
            },
            
          transform: function (iterator) {
          
            var i = iterator.next();
            
            // TODO inlined instrumentation x86_64
            /*var cur_loc = i.address.toInt32();
            cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
            cur_loc &= MAP_SIZE - 1;
            
            iterator.putPushfx();
            iterator.putPushReg("rdx");
            iterator.putPushReg("rcx");
            iterator.putPushReg("rbx");

            // rdx = cur_loc
            iterator.putMovRegU32("rdx", cur_loc);
            // rbx = &cur_loc
            iterator.putMovRegAddress("rbx", prev_loc_ptr);
            // rcx = *rbx
            iterator.putMovRegRegPtr("rcx", "rbx");
            // rcx ^= rdx
            iterator.putXorRegReg("rcx", "rdx");
            // rdx = cur_loc >> 1
            iterator.putMovRegU32("rdx", cur_loc >> 1);
            // *rbx = rdx
            iterator.putMovRegPtrReg("rbx", "rdx");
            // rbx = afl_area_ptr
            iterator.putMovRegAddress("rbx", afl_area_ptr);
            // rbx += rcx
            iterator.putAddRegReg("rbx", "rcx");
            // (*rbx)++
            iterator.putU8(0xfe); // inc byte ptr [rbx]
            iterator.putU8(0x03);
            
            iterator.putPopReg("rbx");
            iterator.putPopReg("rcx");
            iterator.putPopReg("rdx");
            iterator.putPopfx();*/
            
            iterator.putCallout(afl_maybe_log);

            do iterator.keep()
            while ((i = iterator.next()) !== null);

          },
        });
    },

    execute: function (payload_hex) {
        var func_handle = undefined;
        
        if(target_function == undefined)
            return false;

        // Create the function handle (specify type and number of arguments)
        func_handle = new NativeFunction(target_function, 'void', ['pointer', 'int']);

        // Prepare function arguments:
        // payload = Uint8Array.from(Buffer.from(payload_hex, "hex"));
        
        var payload = [];
        for(var i = 0; i < payload_hex.length; i+=2)
        {
            payload.push(parseInt(payload_hex.substring(i, i + 2), 16));
        }

        // Prepare function arguments:
        payload = new Uint8Array(payload)
        
        Memory.writeByteArray(payload_memory, payload)

        // Call the target
        var retval = func_handle(payload_memory, payload.length);
        
        return 0;
        return Memory.readByteArray(afl_area_ptr, MAP_SIZE);
    },
};

