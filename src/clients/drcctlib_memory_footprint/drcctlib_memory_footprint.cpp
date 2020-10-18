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
#include "drutil.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_footprint", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_footprint", format, \
                                          ##args)
#define STDOUT_FP 1

/**
 * Dear beloved TA.
 * You must be wondering why there is a long switch-case statement of
 * 200+ lines. Don't worry, dear TA; for I did not write all of these
 * lines; instead, like a true data mining researcher, I data mined the
 * API docs. Don't believe me? Here's how you do it. Inspect element
 * the table of registers at https://dynamorio.org/dynamorio_docs/dr__ir__opnd_8h.html
 * Find the table of registers, and add 'id="mytbl"' as an attribute to it.
 * Then, in the console:
 *
 * let tbl = document.getElementById('mytbl');
 * let tbody = tbl.children[0]
 *
 * let regs = []
 * for (c of tbody) {
 *     let el = c.children[1];
 *     if (el)
 *         regs.push(el.innerText.split('"')[1]);
 * }
 *
 * let code = "switch (reg) {\n";
 * for (let i = 0; i < regs.length; i++) {
 *     code += `case ${i}: return "${regs[i]}";\n`;
 * }
 * code += "}\n";
 *
 * Love,
 * Rahul
 */
std::string get_reg_name(int reg) {
	switch (reg) {
	case 0: return "rax";
	case 1: return "rcx";
	case 2: return "rdx";
	case 3: return "rbx";
	case 4: return "rsp";
	case 5: return "rbp";
	case 6: return "rsi";
	case 7: return "rdi";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "eax";
	case 17: return "ecx";
	case 18: return "edx";
	case 19: return "ebx";
	case 20: return "esp";
	case 21: return "ebp";
	case 22: return "esi";
	case 23: return "edi";
	case 24: return "r8d";
	case 25: return "r9d";
	case 26: return "r10d";
	case 27: return "r11d";
	case 28: return "r12d";
	case 29: return "r13d";
	case 30: return "r14d";
	case 31: return "r15d";
	case 32: return "ax";
	case 33: return "cx";
	case 34: return "dx";
	case 35: return "bx";
	case 36: return "sp";
	case 37: return "bp";
	case 38: return "si";
	case 39: return "di";
	case 40: return "r8w";
	case 41: return "r9w";
	case 42: return "r10w";
	case 43: return "r11w";
	case 44: return "r12w";
	case 45: return "r13w";
	case 46: return "r14w";
	case 47: return "r15w";
	case 48: return "al";
	case 49: return "cl";
	case 50: return "dl";
	case 51: return "bl";
	case 52: return "ah";
	case 53: return "ch";
	case 54: return "dh";
	case 55: return "bh";
	case 56: return "r8l";
	case 57: return "r9l";
	case 58: return "r10l";
	case 59: return "r11l";
	case 60: return "r12l";
	case 61: return "r13l";
	case 62: return "r14l";
	case 63: return "r15l";
	case 64: return "spl";
	case 65: return "bpl";
	case 66: return "sil";
	case 67: return "dil";
	case 68: return "mm0";
	case 69: return "mm1";
	case 70: return "mm2";
	case 71: return "mm3";
	case 72: return "mm4";
	case 73: return "mm5";
	case 74: return "mm6";
	case 75: return "mm7";
	case 76: return "xmm0";
	case 77: return "xmm1";
	case 78: return "xmm2";
	case 79: return "xmm3";
	case 80: return "xmm4";
	case 81: return "xmm5";
	case 82: return "xmm6";
	case 83: return "xmm7";
	case 84: return "xmm8";
	case 85: return "xmm9";
	case 86: return "xmm10";
	case 87: return "xmm11";
	case 88: return "xmm12";
	case 89: return "xmm13";
	case 90: return "xmm14";
	case 91: return "xmm15";
	case 92: return "xmm16";
	case 93: return "xmm17";
	case 94: return "xmm18";
	case 95: return "xmm19";
	case 96: return "xmm20";
	case 97: return "xmm21";
	case 98: return "xmm22";
	case 99: return "xmm23";
	case 100: return "xmm24";
	case 101: return "xmm25";
	case 102: return "xmm26";
	case 103: return "xmm27";
	case 104: return "xmm28";
	case 105: return "xmm29";
	case 106: return "xmm30";
	case 107: return "xmm31";
	case 108: return "st0";
	case 109: return "st1";
	case 110: return "st2";
	case 111: return "st3";
	case 112: return "st4";
	case 113: return "st5";
	case 114: return "st6";
	case 115: return "st7";
	case 116: return "es";
	case 117: return "cs";
	case 118: return "ss";
	case 119: return "ds";
	case 120: return "fs";
	case 121: return "gs";
	case 122: return "dr0";
	case 123: return "dr1";
	case 124: return "dr2";
	case 125: return "dr3";
	case 126: return "dr4";
	case 127: return "dr5";
	case 128: return "dr6";
	case 129: return "dr7";
	case 130: return "dr8";
	case 131: return "dr9";
	case 132: return "dr10";
	case 133: return "dr11";
	case 134: return "dr12";
	case 135: return "dr13";
	case 136: return "dr14";
	case 137: return "dr15";
	case 138: return "cr0";
	case 139: return "cr1";
	case 140: return "cr2";
	case 141: return "cr3";
	case 142: return "cr4";
	case 143: return "cr5";
	case 144: return "cr6";
	case 145: return "cr7";
	case 146: return "cr8";
	case 147: return "cr9";
	case 148: return "cr10";
	case 149: return "cr11";
	case 150: return "cr12";
	case 151: return "cr13";
	case 152: return "cr14";
	case 153: return "cr15";
	case 154: return "cr15";
	case 155: return "undefined";
	case 156: return "ymm0";
	case 157: return "ymm1";
	case 158: return "ymm2";
	case 159: return "ymm3";
	case 160: return "ymm4";
	case 161: return "ymm5";
	case 162: return "ymm6";
	case 163: return "ymm7";
	case 164: return "ymm8";
	case 165: return "ymm9";
	case 166: return "ymm10";
	case 167: return "ymm11";
	case 168: return "ymm12";
	case 169: return "ymm13";
	case 170: return "ymm14";
	case 171: return "ymm15";
	case 172: return "ymm16";
	case 173: return "ymm17";
	case 174: return "ymm18";
	case 175: return "ymm19";
	case 176: return "ymm20";
	case 177: return "ymm21";
	case 178: return "ymm22";
	case 179: return "ymm23";
	case 180: return "ymm24";
	case 181: return "ymm25";
	case 182: return "ymm26";
	case 183: return "ymm27";
	case 184: return "ymm28";
	case 185: return "ymm29";
	case 186: return "ymm30";
	case 187: return "ymm31";
	case 188: return "zmm0";
	case 189: return "zmm1";
	case 190: return "zmm2";
	case 191: return "zmm3";
	case 192: return "zmm4";
	case 193: return "zmm5";
	case 194: return "zmm6";
	case 195: return "zmm7";
	case 196: return "zmm8";
	case 197: return "zmm9";
	case 198: return "zmm10";
	case 199: return "zmm11";
	case 200: return "zmm12";
	case 201: return "zmm13";
	case 202: return "zmm14";
	case 203: return "zmm15";
	case 204: return "zmm16";
	case 205: return "zmm17";
	case 206: return "zmm18";
	case 207: return "zmm19";
	case 208: return "zmm20";
	case 209: return "zmm21";
	case 210: return "zmm22";
	case 211: return "zmm23";
	case 212: return "zmm24";
	case 213: return "zmm25";
	case 214: return "zmm26";
	case 215: return "zmm27";
	case 216: return "zmm28";
	case 217: return "zmm29";
	case 218: return "zmm30";
	case 219: return "zmm31";
	case 220: return "k0";
	case 221: return "k1";
	case 222: return "k2";
	case 223: return "k3";
	case 224: return "k4";
	case 225: return "k5";
	case 226: return "k6";
	case 227: return "k7";
	case 228: return "bnd0";
	case 229: return "bnd1";
	case 230: return "bnd2";
	case 231: return "bnd3";
}
    return "";
}


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

struct dead_write_t {
	context_handle_t dead_ctxt;
	context_handle_t killing_ctxt;
	int count;
};

bool operator<(const dead_write_t& left, const dead_write_t& right) {
	return left.count < right.count;
}

bool operator<=(const dead_write_t& left, const dead_write_t& right) {
	return left.count <= right.count;
}

bool operator==(const dead_write_t& left, const dead_write_t& right) {
	return left.count == right.count;
}

using MAP_TYPE = std::map<app_pc, dead_write_t>;
MAP_TYPE mem_writes;
MAP_TYPE mem_stats;

using REG_MAP_T = std::map<int, dead_write_t>;
REG_MAP_T reg_writes;
REG_MAP_T reg_stats;

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

void
InsertRegCleanCall(int slot, instr_t* instr, instr_type type, int reg)
{
	void *drcontext = dr_get_current_drcontext();
	context_handle_t cur_ctxt = drcctlib_get_context_handle(drcontext, slot);

	if (type == INSTR_WRITE) {
		if (reg_writes.find(reg) != reg_writes.end()) {
			// Dead write
			reg_writes[reg].killing_ctxt = cur_ctxt;
			reg_writes[reg].count--;
		} else {
			reg_writes[reg].dead_ctxt = cur_ctxt;
			reg_writes[reg].count = 0;
		}
	} else if (type == INSTR_READ) {
		REG_MAP_T::iterator it;	
		if ((it = reg_writes.find(reg)) != reg_writes.end()) {
			int count = reg_writes[reg].count;

			if (count < 0) {
				reg_stats[reg].count += count;
				reg_stats[reg].killing_ctxt = reg_writes[reg].killing_ctxt;

				reg_stats[reg].dead_ctxt = reg_writes[reg].dead_ctxt;
			}

			reg_writes.erase(it);
		}
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
		if (mem_writes.find(addr) != mem_writes.end()) {
			// Dead write
			mem_writes[addr].count--;
			mem_writes[addr].killing_ctxt = cur_ctxt;
		} else {
			mem_writes[addr].dead_ctxt = cur_ctxt;
			mem_writes[addr].count = 0;
		}
	} else if (type == INSTR_READ) {
		MAP_TYPE::iterator it;	
		if ((it = mem_writes.find(addr)) != mem_writes.end()) {
			int count = mem_writes[addr].count;

			if (count < 0) {
				mem_stats[addr].count += count;
				mem_stats[addr].killing_ctxt = mem_writes[addr].killing_ctxt;
				mem_stats[addr].dead_ctxt = mem_writes[addr].dead_ctxt;
			}

			mem_writes.erase(it);
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
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
		// Read
		opnd_t op = instr_get_src(instr, i);
        if (opnd_is_memory_reference(op)) {
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));

			dr_insert_clean_call(drcontext, bb, instr, (void*) InsertMemCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_READ), OPND_CREATE_CCT_INT(num));
					num++;
        } else {
			// Reg
			int reg_count = opnd_num_regs_used(op);
			for (int j = 0; j < reg_count; j++) {
				int reg = (int) opnd_get_reg_used(op, j);
				dr_insert_clean_call(drcontext, bb, instr, (void*) InsertRegCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_READ), OPND_CREATE_CCT_INT(reg));
			}
		}
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
		// Write
		opnd_t op = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(op)) {
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
			dr_insert_clean_call(drcontext, bb, instr, (void*) InsertMemCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_WRITE), OPND_CREATE_CCT_INT(num));
            num++;
        } else {
			// Reg
			int reg_count = opnd_num_regs_used(op);
			for (int j = 0; j < reg_count; ++j) {
				int reg = (int) opnd_get_reg_used(op, j);
				dr_insert_clean_call(drcontext, bb, instr, (void*) InsertRegCleanCall, false, 4, OPND_CREATE_CCT_INT(slot), opnd_create_instr(instr), OPND_CREATE_CCT_INT(INSTR_WRITE), OPND_CREATE_CCT_INT(reg));
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
}

static void
ClientInit(int argc, const char *argv[])
{
    
}

// from https://stackoverflow.com/a/5056797/10066306
template<typename A, typename B>
std::pair<B,A> flip_pair(const std::pair<A,B> &p)
{
    return std::pair<B,A>(p.second, p.first);
}

template<typename A, typename B>
std::multimap<B,A> flip_map(const std::map<A,B> &src)
{
    std::multimap<B,A> dst;
    std::transform(src.begin(), src.end(), std::inserter(dst, dst.begin()),
                   flip_pair<A,B>);
    return dst;
}

static void
ClientExit(void)
{
    // add output module here
	std::multimap<dead_write_t, app_pc> mem_stats_flipped = flip_map(mem_stats);

	int total_mem_dead_writes = 0;
	for (auto it = mem_stats_flipped.begin(); it != mem_stats_flipped.end(); it++)
		total_mem_dead_writes += it->first.count;

	std::cout << std::string(20, '=') << -total_mem_dead_writes << " MEMORY DEAD WRITES " << std::string(20, '=') << "\n";

	int i = 0;
	for (auto it = mem_stats_flipped.begin(); 
			it != mem_stats_flipped.end() && i < 100; 
			++it, ++i) {
		std::cout << "[" << i + 1 << "]" << '\n';
		std::printf("%p: %d\n", it->second, -it->first.count);

		std::cout << "[Killing context]\n";
		drcctlib_print_full_cct(STDOUT_FP, it->first.killing_ctxt, true, true, 0);

		std::cout << "\n[Dead context]\n";
		drcctlib_print_full_cct(STDOUT_FP, it->first.dead_ctxt, true, true, 0);

		std::cout << std::string(20, '=') << "\n\n";
	}
	std::fflush(stdout);
	
	std::multimap<dead_write_t, int> reg_stats_flipped = flip_map(reg_stats);

	int total_reg_dead_writes = 0;
	for (auto it = reg_stats_flipped.begin(); it != reg_stats_flipped.end(); it++)
		total_reg_dead_writes += it->first.count;

	std::cout << std::string(20, '=') << -total_reg_dead_writes << " REG DEAD WRITES " << std::string(20, '=') << "\n";

	i = 0;
	for (auto it = reg_stats_flipped.begin(); 
			it != reg_stats_flipped.end() && i < 100; 
			++it, ++i) {
		std::cout << '[' << i + 1 << ']' << '\n';
		std::cout << get_reg_name(it->second) << ": " << -it->first.count << "\n";

		std::cout << "[Killing context]\n";
		drcctlib_print_full_cct(STDOUT_FP, it->first.killing_ctxt, true, true, 0);

		std::cout << "\n[Dead context]\n";
		drcctlib_print_full_cct(STDOUT_FP, it->first.dead_ctxt, true, true, 0);
		std::cout << std::string(20, '=') << "\n\n";
	}


    drcctlib_exit();

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
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
