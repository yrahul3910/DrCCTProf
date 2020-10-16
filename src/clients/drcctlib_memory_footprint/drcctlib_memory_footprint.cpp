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

std::vector<app_pc> accessed;

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

#define TLS_MEM_REF_BUFF_SIZE 100

typedef enum {
    INSTR_READ_MEM,
    INSTR_WRITE_MEM,
    INSTR_READ_REG,
    INSTR_WRITE_REG,
    INSTR_NOT_MEM
} instr_type;

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref, instr_type type)
{
	//for (app_pc start = ref->addr; start < ref->addr + ref->size; ++start)
	//	global[cur_ctxt_hndl].insert(start);

    switch (type) {
        case INSTR_READ_MEM:
            break;
        case INSTR_WRITE_MEM:
            break
    }
}

void
InsertRegCleanCall(int slot, reg_id_t reg, instr_type type)
{
}

void
InsertMemCleanCall(int slot, instr_t* instr, instr_type type)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i], type);
        }
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
    int slot = instrument_msg->slot;
    instr_type type;
    
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd_t op = instr_get_src(instr, i);

        if (opnd_is_memory_reference(op)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *) InsertMemCleanCall, false, 2,
                    OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_MEM_READ));
        } else {
            int num_regs = opnd_num_regs_used(op);
            for (int j = 0; j < num_regs; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);

                // Read from reg
                dr_insert_clean_call(drcontext, bb, instr, (void *) InsertRegCleanCall, false, 3,
                        OPND_CREATE_CCT_INT(slot), opnd_create_reg(reg), OPND_CREATE_CCT_INT(INSTR_REG_READ));
            }
        }
    }

    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t op = instr_get_dst(instr, i);

        if (opnd_is_memory_reference(op)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *) InsertMemCleanCall, false, 2,
                    OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_MEM_WRITE));
        } else {
            int num_regs = opnd_num_regs_used(op);
            for (int j = 0; j < num_regs; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);

                // Write to reg
                dr_insert_clean_call(drcontext, bb, instr, (void *) InsertRegCleanCall, false, 3,
                        OPND_CREATE_CCT_INT(slot), opnd_create_reg(reg), OPND_CREATE_CCT_INT(INSTR_REG_WRITE));
            }
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

//	write_thread_all_cct_hpcrun_format(drcontext);
}

static void
ClientInit(int argc, const char *argv[])
{
    
}

static void
ClientExit(void)
{
    // add output module here
    typedef struct {
	    context_t* ctxt;
	    std::set<app_pc> addr;
    } my_struct;
	std::map<std::string, my_struct> mapper;
	for (std::map<context_handle_t, std::set<app_pc>>::iterator it = global.begin(); 
			it != global.end(); ++it) {
		context_t* ctxt = drcctlib_get_full_cct(it->first, 100);
		if (mapper.find(ctxt->func_name) == mapper.end()) mapper[ctxt->func_name] = {ctxt, it->second};
		else {
			std::set<app_pc> first = mapper[ctxt->func_name].addr;
			mapper[ctxt->func_name].addr.insert(it->second.begin(), it->second.end());
		}
	}
	for (std::map<std::string, my_struct>::iterator it = mapper.begin(); it != mapper.end(); it++) {
		context_t* ctxt = it->second.ctxt;
		for (context_t* ptr = ctxt; ptr; ptr = ptr->pre_ctxt) {
			std::string fn = ptr->func_name;
			mapper[fn].addr.insert(it->second.addr.begin(), it->second.addr.end());
		}
	}
	for (std::pair<std::string, my_struct> pair : mapper) {
		context_t* ctxt = pair.second.ctxt;
		context_handle_t cur_ctxt_hndl = ctxt->ctxt_hndl;
		std::cout << "\n\nMEMORY FOOTPRINT OF " << pair.first;
		std::cout << " = " << pair.second.addr.size() << " BYTES." << std::endl;
		std::cout << std::string(20 + pair.first.length() + 13, '=') << "\n";
		std::cout << "Full context:" << std::endl;
		for (context_t* ptr = ctxt; ptr; ptr = ptr->pre_ctxt)
			std::cout << "-->" << ptr->func_name;
		std::cout << "\n" << std::string(20 + pair.first.length() + 13, '=') << std::endl;
	}

    drcctlib_exit();
	//hpcrun_format_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_footprint dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
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
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

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
