#include <iostream>
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
#include <stdio.h>
#include <stddef.h> /* for offsetof */

using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_only", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_only", format, ##args)
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * 4096)
static int tls_idx;
static uint tls_offs;

typedef struct _mem_ref_t {
    ushort type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
    ushort size; /* mem ref size or instr length */
    app_pc addr; /* mem ref addr or instr pc */
} mem_ref_t;


typedef struct {
    byte *seg_base;
    mem_ref_t *buf_base;
    file_t log;
    FILE *logf;
    uint64 num_refs;
} per_thread_t;

// dr clean call per ins cache
static inline void
InstrumentPerInsCache(void *drcontext, context_handle_t ctxt_hndl, int32_t mem_ref_num,
                      mem_ref_msg_t *mem_ref_start, void *data)
{
    per_thread_t* dat = (per_thread_t*) data;

    context_t* full_cct = drcctlib_get_full_cct(ctxt_hndl, 100);
    std::cout << "Context: ";
    for (context_t* ptr = full_cct; ptr; ptr = ptr->pre_ctxt )
        std::cout << "-->" << ptr->func_name;
    std::cout << std::endl;
    
    std::cout << "mem_ref done" << std::endl;
    dat->buf_base = (mem_ref_t*)dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);

    if (dat) {
        mem_ref_t* buf_ptr = dat->buf_base;
        if (buf_ptr) {
        } else {
            std::cout << "buf_base is null" << std::endl;
        }
    } else {
        std::cout << "dat is null\n" << std::endl;
    }

    instr_t instr;
    instr_init(drcontext, &instr);
    instr_reset(drcontext, &instr);

    dr_mcontext_t mcontext;
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_ALL;

    if (dr_get_mcontext(drcontext, &mcontext)) {
		std::cout << "got mcontext" << std::endl;
		int index = 0;
		app_pc addr;
		while(instr_compute_address(&instr, &mcontext))
			std::cout << "got addr " << addr << std::endl;
	}

	instr_free(drcontext, &instr);
}

static inline void
InstrumentPerBBCache(void *drcontext, context_handle_t ctxt_hndl, int32_t slot_num,
                     int32_t mem_ref_num, mem_ref_msg_t *mem_ref_start, void **data)
{    
    int32_t temp_index = 0;
    for (int32_t i = 0; i < slot_num; i++) {
        int32_t ins_ref_number = 0;
        mem_ref_msg_t *ins_cache_mem_start = NULL;
        for (; temp_index < mem_ref_num; temp_index++) {
            if (mem_ref_start[temp_index].slot == i) {
                if (ins_cache_mem_start == NULL) {
                    ins_cache_mem_start = mem_ref_start + temp_index;
                }
                ins_ref_number++;
            } else if (mem_ref_start[temp_index].slot > i) {
                break;
            }
        }
        InstrumentPerInsCache(drcontext, ctxt_hndl + i, ins_ref_number,
                              ins_cache_mem_start, data);
    }
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    std::cout << "start" << std::endl;
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_footprint'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    std::cout << "init done" << std::endl;

    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache, DRCCTLIB_CACHE_MODE);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
