'use strict'

var MAP_SIZE = 65536;

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

var WHITELIST = ['all'];

//var afl_area = Memory.alloc(MAP_SIZE + 32);
var afl_area = new Uint8Array(MAP_SIZE);

var gc_cnt = 0;

var maps = function() {

    var maps = Process.enumerateModulesSync();
    var i = 0;
    
    /* Add an id to each module */
    maps.map(function(o) { o.id = i++; });
    /* Add an end address to each module */
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;

}();

// Always trust code. Make it faster
Stalker.trustThreshold = 0;

var target_function = undefined;

// ======== For in-process fuzzing =================
var arg1  = Memory.alloc(0x100000);
// var arg2  = Memory.alloc(0x100000);
// var zero_0x100000 = new Uint8Array(0x100000);
// =================================================

rpc.exports = {

    vmmap: function(args) {
        return maps;
    },
    getpid: function(args) {
        return Process.id;
    },

    /* Initialize the address of the target function (to-be-hooked) and attach
       the Interceptor */
    settarget: function(target) {
        target_function = ptr(target);

        Interceptor.attach(target_function, {
            onEnter: function (args) {
                Stalker.queueCapacity = STALKER_QUEUE_CAP;
                Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;

                /*var cm = new CModule(" \
                  \
                  #include <gum/gumstalker.h> \
                  #include <stdint.h> \
                  \
                  static void afl_maybe_log (GumCpuContext * cpu_context, \
                                             gpointer user_data); \
                  \
                  void \
                  transform (GumStalkerIterator * iterator, \
                             GumStalkerWriter * output, \
                             gpointer user_data) { \
                              \
                  \
                    cs_insn * insn; \
                    gum_stalker_iterator_next (iterator, &insn); \
                  \
                    gum_stalker_iterator_put_callout (iterator, afl_maybe_log, \
                                                      user_data, NULL); \
                  \
                    do \
                      gum_stalker_iterator_keep (iterator); \
                    while (gum_stalker_iterator_next (iterator, &insn)); \
                  \
                  } \
                  \
                  static void \
                  afl_maybe_log (GumCpuContext * cpu_context, \
                                 gpointer user_data) { \
                  \
                    uintptr_t cur_loc = (uintptr_t) cpu_context->rip; \
                    uint8_t * afl_area_ptr = user_data; \
                    // seems to not support global vars \
                    uintptr_t* prev_loc = afl_area_ptr + MAP_SIZE; \
                     \
                    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8); \
                    cur_loc &= MAP_SIZE - 1; \
                \
                    afl_area_ptr[cur_loc ^ *prev_loc]++; \
                    *prev_loc = cur_loc >> 1; \
                \
                  } \
                \
                ".replace("MAP_SIZE", MAP_SIZE));
                
                
                Stalker.follow(Process.getCurrentThreadId(), {
                    events: {
                        call: false,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: true
                    },
                    
                  transform: cm.transform,
                  data: afl_area
                                  
                });
                
                */
                var prev_loc = 0;
                function afl_maybe_log (context) {
                  
                  var cur_loc = context.pc.toInt32();
                  
                  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
                  cur_loc &= MAP_SIZE - 1;

                  afl_area[cur_loc ^ prev_loc]++;
                  prev_loc = cur_loc >> 1;

                }
                
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
                  
                    iterator.putCallout(afl_maybe_log);
                  
                    do iterator.keep()
                    while ((i = iterator.next()) !== null);

                  },
                });
            },
            
            onLeave: function (retval) {
                Stalker.unfollow(Process.getCurrentThreadId())
                Stalker.flush();
                if(gc_cnt % 100 == 0){
                    Stalker.garbageCollect();
                }
                gc_cnt++;
            }
        });
    },

    // Call the target function with fuzzing payload (in-process fuzzing)
    execute: function (payload_hex) {
        var func_handle = undefined;
        
        if(target_function == undefined)
            return false;

        // Create the function handle (specify type and number of arguments)
        func_handle = new NativeFunction(target_function, 'void', ['pointer', 'int']);

        // Prepare function arguments:
        //payload = Uint8Array.from(Buffer.from(payload_hex, "hex"));
        
        var payload = [];
        for(var i = 0; i < payload_hex.length; i+=2)
        {
            payload.push(parseInt(payload_hex.substring(i, i + 2), 16));
        }

        // Prepare function arguments:
        payload = new Uint8Array(payload)
        
        Memory.writeByteArray(arg1, payload)

        //// manage malloc/free
        //var next_buffer_index = 0;

        //// Intercept malloc in order to free all allocated memory after the call:
        //Interceptor.replace(malloc, new NativeCallback(function (size) {
        //    if(size > buffers_size)
        //        return ptr(0);
        //    var buf = buffers[next_buffer_index];
        //    next_buffer_index += 1;
        //    return buf;
        //}, 'pointer', ['int']));

        //// Intercept calloc in order to free all allocated memory after the call:
        //Interceptor.replace(calloc, new NativeCallback(function (size) {
        //    if(size > buffers_size)
        //        return ptr(0);
        //    var buf = buffers[next_buffer_index];
        //    next_buffer_index += 1;
        //    return buf;
        //}, 'pointer', ['int']));

        //// Intercept free as well
        //Interceptor.replace(free, new NativeCallback(function (pointer) {
        //    return 0;
        //}, 'int', ['pointer']));

        //Interceptor.flush()

        //for (var i = 0; i < MAP_SIZE; ++i)
        //  afl_area[i] = 0;

        // Call the target
        var retval = func_handle(arg1, payload.length);

        //// free all allocated memory:
        //Interceptor.revert(malloc)
        //Interceptor.revert(calloc)
        //Interceptor.revert(free)
        //Interceptor.flush()

        //return Memory.readByteArray(afl_area, MAP_SIZE);
        return afl_area;
    },

    // Get the coverage
    getcov: function(args) {
        //return Memory.readByteArray(afl_area, MAP_SIZE);
        return afl_area;
    }
};

