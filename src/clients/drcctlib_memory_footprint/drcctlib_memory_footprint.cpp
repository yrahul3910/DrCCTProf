/* 
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>
#include <map>
#include <string.h>
#include <string>
#include <algorithm>
#include <vector>
#include <set>
#include <cstdio>
#include <iostream>
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
//#include "drcctlib_hpcviewer_format.h"

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_footprint", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_footprint", format, \
                                          ##args)
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

using MAP_TYPE = std::map<app_pc, int>;

MAP_TYPE mem_writes;
MAP_TYPE mem_stats;

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

#define TLS_MEM_REF_BUFF_SIZE 100

// Read = 0, Write = 1
typedef int instr_type;
#define INSTR_READ 0
#define INSTR_WRITE 1

void
InsertRegCleanCall(int slot, reg_id_t reg, instr_type type)
{
}

void
InsertMemCleanCall(int slot, instr_t* instr, instr_type type)
{
	std::cout << "Entered mem clean call!" << std::endl;
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);

	app_pc addr = (&pt->cur_buf_list[0])->addr;

	if (type == INSTR_WRITE) {
		if (mem_writes.find(addr) != mem_writes.end()) {
			// Dead write
			mem_writes[addr]++;
		}
	} else if (type == INSTR_READ) {
		MAP_TYPE::iterator it;	
		if ((it = mem_writes.find(addr)) != mem_writes.end()) {
			int count = mem_writes[addr];
			mem_writes.erase(it);
			mem_stats[addr] += count;
		}
	}

    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
	std::cout << "Exited mem clean call!" << std::endl;
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
	std::cout << "ins begin" << std::endl;
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int slot = instrument_msg->slot;
    instr_type type;
	std::cout << "ins end" << std::endl;


	int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
        }
    }


	context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
	context_t* full_cct = drcctlib_get_full_cct(cur_ctxt_hndl, 1);
	std::cout << full_cct->code_asm << std::endl;
    
	std::cout << "instr num srcs = " << instr_num_srcs(instr) << std::endl;
	std::cout << "instr num dsts = " << instr_num_dsts(instr) << std::endl;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
		std::cout << i << std::endl;
		std::cout << "Getting the src..." << std::endl;
        opnd_t op = instr_get_src(instr, i);
		std::cout << "Got the src!" << std::endl;

        if (opnd_is_memory_reference(op)) {
			std::cout << "Putting the thing in..." << std::endl;
            dr_insert_clean_call(drcontext, bb, instr, (void *) InsertMemCleanCall, false, 2,
                    OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(0x0));
			std::cout << "Wrote the thing in!" << std::endl;
        } else {
            int num_regs = opnd_num_regs_used(op);
            for (int j = 0; j < num_regs; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);

                // Read from reg
				std::cout << "Putting the reg thing in..." << std::endl;
                dr_insert_clean_call(drcontext, bb, instr, (void *) InsertRegCleanCall, false, 3,
                        OPND_CREATE_CCT_INT(slot), opnd_create_reg(reg), OPND_CREATE_CCT_INT(0x0));
				std::cout << "Wrote the reg!" << std::endl;
            }
        }
    }

    for (int i = 0; i < instr_num_dsts(instr); i++) {
		std::cout << i << std::endl;
		std::cout << "Getting the dest..." << std::endl;
        opnd_t op = instr_get_dst(instr, i);
		std::cout << "Got the dest!" << std::endl;

        if (opnd_is_memory_reference(op)) {
			std::cout << "Putting the thing in..." << std::endl;
            dr_insert_clean_call(drcontext, bb, instr, (void *) InsertMemCleanCall, false, 2,
                    OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(0x1));
			std::cout << "Read the mem!" << std::endl;
        } else {
            int num_regs = opnd_num_regs_used(op);
            for (int j = 0; j < num_regs; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);

                // Write to reg
				std::cout << "Putting the reg thing in..." << std::endl;
                dr_insert_clean_call(drcontext, bb, instr, (void *) InsertRegCleanCall, false, 3,
                        OPND_CREATE_CCT_INT(slot), opnd_create_reg(reg), OPND_CREATE_CCT_INT(0x1));
				std::cout << "Read the reg!" << std::endl;
            }
        }
    }

	std::cout << mem_writes.size() << std::endl;
	std::cout << mem_stats.size() << std::endl;
}


static void
ClientInit(int argc, const char *argv[])
{
    
}

static void
ClientExit(void)
{
    // add output module here
    drcctlib_exit();
	std::cout << "Starting output..." << std::endl;
	for (auto it = mem_writes.begin(); it != mem_writes.end(); ++it)
		std::cout << std::hex << it->first << std::dec << ": " <<  it->second << std::endl;


	//hpcrun_format_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_footprint dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_memory_footprint failed to "
                        "unregister in ClientExit");
    }
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_footprint'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drutil");
    }
    //drmgr_register_thread_init_event(ClientThreadStart);
    //drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_footprint dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, false);
	//hpcrun_format_init(dr_get_application_name(), true);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
