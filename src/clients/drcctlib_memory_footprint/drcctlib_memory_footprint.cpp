#include <iostream>
#include <cstdio>
#include <iomanip>
#include <typeinfo>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <climits>
#include <iterator>
#include <unistd.h>
#include <vector>
#include <map>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_only_clean_call", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_only_clean_call", format, ##args)

static int tls_idx;

#define MINSERT instrlist_meta_preinsert

#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    ifdef CCTLIB_64
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT64
#    else
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#    endif
#endif

#ifdef CCTLIB_64
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM64
#else
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM32
#endif

#define OPND_CREATE_MEM_IDX_MEM OPND_CREATE_MEM64

typedef struct _per_thread_t {
    aligned_ctxt_hndl_t cur_ctxt_hndl;
} per_thread_t;

#define TLS_MEM_REF_BUFF_SIZE 100

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, int32_t size, int32_t* pc)
{
    // use {cur_ctxt_hndl}
	std::printf("Memory reference %p of size %u\n", pc, size);
	std::fflush(stdout);
    context_t* full_cct = drcctlib_get_full_cct(cur_ctxt_hndl, 100);
    std::cout << "Context: ";
    for (context_t* ptr = full_cct; ptr; ptr = ptr->pre_ctxt )
        std::cout << "-->" << ptr->func_name;
    std::cout << std::endl;
}

// dr clean call
void
InsertCleancall(int32_t slot, int32_t size, int32_t* pc)
{
	void *drcontext = dr_get_current_drcontext();
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, size, pc);
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;

    dr_mcontext_t ctxt;
    ctxt.size = sizeof(dr_mcontext_t);
    ctxt.flags = DR_MC_ALL;
    if (dr_get_mcontext(drcontext, &ctxt)) {
	    app_pc pc = instr_compute_address(instr, &ctxt);
	    unsigned int size = instr_memory_reference_size(instr);
            dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 3, OPND_CREATE_INT32(slot), OPND_CREATE_INT32(size), OPND_CREATE_INTPTR(pc));
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
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    drcctlib_exit();

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_memory_only_clean_call failed to unregister in ClientExit");
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_only_clean_call'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_only_clean_call unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_only_clean_call unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_only_clean_call unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_only_clean_call drmgr_register_tls_field fail");
    }
    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE,
                     InstrumentInsCallback, NULL, NULL, DRCCTLIB_DEFAULT);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
