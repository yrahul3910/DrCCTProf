/* 
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <map>
#include <string.h>
#include <string>
#include <algorithm>
#include <vector>
#include <set>
#include <cstdio>
#include <iostream>
#include <cstddef>
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"
#include "drutil.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("heap_overflow", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("heap_overflow", format, \
                                          ##args)
#define STDOUT_FP 1

#define SHOW_RESULTS
#undef SHOW_RESULTS

static int tls_idx;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert
#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

typedef int instr_type;
#define INSTR_READ 0x0
#define INSTR_WRITE 0x1

#define TLS_MEM_REF_BUFF_SIZE 100


#ifdef WINDOWS
#    define IF_WINDOWS_ELSE(x, y) x
#else
#    define IF_WINDOWS_ELSE(x, y) y
#endif

#ifdef WINDOWS
#    define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
#    define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif
#define NULL_TERMINATE(buf) (buf)[(sizeof((buf)) / sizeof((buf)[0])) - 1] = '\0'
static void
event_exit(void);
static void
wrap_pre(void *wrapcxt, OUT void **user_data);
static void
wrap_post(void *wrapcxt, void *user_data);

static size_t max_malloc;
#ifdef SHOW_RESULTS
static uint malloc_oom;
#endif
static void *max_lock; /* to synch writes to max_malloc */

#define MALLOC_ROUTINE_NAME IF_WINDOWS_ELSE("HeapAlloc", "malloc")

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, MALLOC_ROUTINE_NAME);
    if (towrap != NULL) {
#ifdef SHOW_RESULTS
        bool ok =
#endif
            drwrap_wrap(towrap, wrap_pre, wrap_post);
#ifdef SHOW_RESULTS
        if (ok) {
            dr_fprintf(STDERR, "<wrapped " MALLOC_ROUTINE_NAME " @" PFX "\n", towrap);
        } else {
            /* We expect this w/ forwarded exports (e.g., on win7 both
             * kernel32!HeapAlloc and kernelbase!HeapAlloc forward to
             * the same routine in ntdll.dll)
             */
            dr_fprintf(STDERR,
                       "<FAILED to wrap " MALLOC_ROUTINE_NAME " @" PFX
                       ": already wrapped?\n",
                       towrap);
        }
#endif
    }
}

void
InsertMemCleanCall(int slot, instr_t* instr, instr_type type, int num)
{
    void *drcontext = dr_get_current_drcontext();
	context_handle_t cur_ctxt = drcctlib_get_context_handle(drcontext, slot);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

	app_pc addr = (&pt->cur_buf_list[num])->addr;

	if (type == INSTR_WRITE) {
	} else if (type == INSTR_READ) {
	}

    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}



// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, free_reg;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &free_reg) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));

    // store mem_ref_t->size
#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                             OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
#endif

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, free_reg) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
		// Read
		opnd_t op = instr_get_src(instr, i);
        if (opnd_is_memory_reference(op)) {
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));

			dr_insert_clean_call(drcontext, bb, instr, (void*) InsertMemCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_READ), OPND_CREATE_CCT_INT(num));
					num++;
        } 
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
		// Write
		opnd_t op = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(op)) {
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
			dr_insert_clean_call(drcontext, bb, instr, (void*) InsertMemCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_WRITE), OPND_CREATE_CCT_INT(num));
            num++;
		}
    }
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    
}


// from https://github.com/DynamoRIO/dynamorio/blob/master/api/samples/wrap.c
static void
wrap_pre(void *wrapcxt, OUT void **user_data)
{
    /* malloc(size) or HeapAlloc(heap, flags, size) */
    size_t sz = (size_t)drwrap_get_arg(wrapcxt, IF_WINDOWS_ELSE(2, 0));
    /* find the maximum malloc request */
    if (sz > max_malloc) {
        dr_mutex_lock(max_lock);
        if (sz > max_malloc)
            max_malloc = sz;
        dr_mutex_unlock(max_lock);
    }
    *user_data = (void *)sz;
}

static void
wrap_post(void *wrapcxt, void *user_data)
{
	char* addr = (char*) drwrap_get_retval(wrapcxt);
	std::printf("addr = %p\n", addr);
    size_t sz = (size_t)user_data;
	std::printf("size = %lu\n", sz);
    /* test out-of-memory by having a random moderately-large alloc fail */
#ifdef SHOW_RESULTS /* we want determinism in our test suite */

#endif
}

static void
ClientExit(void)
{
    // add output module here

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_heap_overflow dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
		!drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
		!drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_heap_overflow failed to "
                        "unregister in ClientExit");
    }
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
}

static void
event_exit(void)
{
#ifdef SHOW_RESULTS
    char msg[256];
    int len;
    len = dr_snprintf(msg, sizeof(msg) / sizeof(msg[0]),
                      "<Largest " MALLOC_ROUTINE_NAME
                      " request: %d>\n<OOM simulations: %d>\n",
                      max_malloc, malloc_oom);
    DR_ASSERT(len > 0);
    NULL_TERMINATE(msg);
    DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */

    dr_mutex_destroy(max_lock);
    drwrap_exit();
    drmgr_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_heap_overflow'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drmgr");
    }
	drwrap_init();
	dr_register_exit_event(event_exit);
	drmgr_register_module_load_event(module_load_event);
	max_lock = dr_mutex_create();

    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_heap_overflow dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, false);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
