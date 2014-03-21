/////////////////////////////////////////////////////////////////////////
// $Id: instrument.h,v 1.24 2007/12/13 21:53:55 sshwarts Exp $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001  MandrakeSoft S.A.
//
//    MandrakeSoft S.A.
//    43, rue d'Aboukir
//    75002 Paris - France
//    http://www.linux-mandrake.com/
//    http://www.mandrakesoft.com/
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

#include "Python.h"

#include "bochs.h"
#include "cpu/cpu.h"

#include <queue>
#include <map>
#include <set>

#define BX_INSTR_IS_JCC_TAKEN   19
#define BX_INSTR_IS_JCC_NOTTAKEN 20

#define BX_INSTR_COND(EVENT) if(bx_instr_mask & BX_INSTR_COND_##EVENT)
/* initialization/deinitialization of instrumentalization*/
#define BX_INSTR_COND_INIT_ENV (1 << 0)
#define BX_INSTR_COND_EXIT_ENV (1 << 1)

/* simulation init, shutdown, reset */
#define BX_INSTR_COND_INITIALIZE (1 << 2)
#define BX_INSTR_COND_EXIT       (1 << 3)
#define BX_INSTR_COND_RESET      (1 << 4)
#define BX_INSTR_COND_HLT        (1 << 5)
#define BX_INSTR_COND_MWAIT      (1 << 6)

/* called from command line debugger */
#define BX_INSTR_COND_DEBUG_PROMPT (1 << 7)
#define BX_INSTR_COND_DEBUG_CMD    (1 << 8)

/* branch resolution */
#define BX_INSTR_COND_CNEAR_BRANCH_TAKEN     (1 << 9)
#define BX_INSTR_COND_CNEAR_BRANCH_NOT_TAKEN (1 << 10)
#define BX_INSTR_COND_UCNEAR_BRANCH          (1 << 11)
#define BX_INSTR_COND_FAR_BRANCH             (1 << 12)
#define BX_INSTR_COND_BRANCH                 (BX_INSTR_COND_CNEAR_BRANCH_TAKEN | BX_INSTR_COND_CNEAR_BRANCH_NOT_TAKEN | BX_INSTR_COND_UCNEAR_BRANCH | BX_INSTR_COND_FAR_BRANCH)

/* decoding completed */
#define BX_INSTR_COND_OPCODE                (1 << 13)

/* exceptional case and interrupt */
#define BX_INSTR_COND_EXCEPTION             (1 << 14)
#define BX_INSTR_COND_INTERRUPT             (1 << 15)
#define BX_INSTR_COND_HWINTERRUPT           (1 << 16)

/* TLB/CACHE control instruction executed */
#define BX_INSTR_COND_CLFLUSH               (1 << 17)
#define BX_INSTR_COND_CACHE_CNTRL           (1 << 18)
#define BX_INSTR_COND_TLB_CNTRL             (1 << 19)
#define BX_INSTR_COND_PREFETCH_HINT         (1 << 20)

/* execution */
#define BX_INSTR_COND_BEFORE_EXECUTION      (1 << 21)
#define BX_INSTR_COND_AFTER_EXECUTION       (1 << 22)
#define BX_INSTR_COND_REPEAT_ITERATION      (1 << 23)

/* linear memory access */
#define BX_INSTR_COND_LIN_ACCESS            (1 << 24)

/* physical memory access */
#define BX_INSTR_COND_PHY_ACCESS            (1 << 25)

/* feedback from device units */
#define BX_INSTR_COND_INP                   (1 << 26)
#define BX_INSTR_COND_INP2                  (1 << 27)
#define BX_INSTR_COND_OUTP                  (1 << 28)

/* wrmsr callback */
#define BX_INSTR_COND_WRMSR                 (1 << 29)

#define BX_INSTR_COND_FINE                  (BX_INSTR_COND_BRANCH | BX_INSTR_COND_LIN_ACCESS)

extern Bit32u bx_instr_mask;

#if BX_WITH_PYTHON != 1
#error This instrumentation skin requires Python
#endif

#if BX_WITH_POSTGRESQL != 1
#error This instrumentation skin requires Postgres support
#endif

#if BX_SUPPORT_X86_64
#error This instrumentation skin doesnt support x86_64
#endif

#if defined( BX_SupportRepeatSpeedups) && BX_SupportRepeatSpeedups != 0
#error BX_SupportRepeatSpeedups must not be used with this instrumentation skin!
#endif

#define PAGESIZE 4096

#define PY_IGNORE_EXCEPTION(name) if(NULL != PyErr_Occurred()) { printf("%s ... -> ",name);PyErr_Print();printf("<-\n");}


extern bx_bool bx_instr_enabled;
extern Bit32u bx_instr_mask;
extern bx_bool bx_instr_pending_page;
extern PyObject *PyBochs_ev_branch;
extern PyObject *PyBochs_ev_mod_cr3;
extern PyObject *PyBochs_ev_write;
extern PyObject *PyBochs_pending_page;


#define USER_KERNEL_SPLIT 0x80000000

#if BX_INSTRUMENTATION

class bxInstruction_c;

void bx_instr_atexit();

// called from the CPU core

void bx_instr_init(unsigned cpu);

void fetch_pending_page();

void bx_instr_interrupt(unsigned cpu, unsigned vector);
void bx_instr_exception(unsigned cpu, unsigned vector);
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx_address eip);

static inline void ev_mod_cr3(unsigned new_cr3) {
   PyObject *result;
   result = PyObject_CallFunction(PyBochs_ev_mod_cr3, (char*)"(I)", new_cr3);
   PY_IGNORE_EXCEPTION("ev_mod_cr3 1");
   int r = PyInt_AsLong(result);
   if(r) {
       bx_instr_mask |= BX_INSTR_COND_FINE;
   } else {
       bx_instr_mask &= ~BX_INSTR_COND_FINE;
   }
   PY_IGNORE_EXCEPTION("ev_mod_cr3 2");
   Py_XDECREF(result);
}

static inline void bx_instr_tlb_cntrl(unsigned cpu, unsigned what, Bit32u newval) {
   switch(what) {
      case BX_INSTR_MOV_CR3:
         ev_mod_cr3(newval);
         break;
     default:
         break;
   }
}


static inline void ev_write(unsigned address, unsigned length) {
   PyObject *result;
   result = PyObject_CallFunction(PyBochs_ev_write, (char*)"(II)", address, length);
   if(PyInt_AsLong(result)) {
   }
   PY_IGNORE_EXCEPTION("ev_write");
   Py_XDECREF(result);
}

static inline void ev_branch(unsigned source, unsigned target, unsigned type) {
   PyObject *result;
   result = PyObject_CallFunction(PyBochs_ev_branch, (char*)"(III)", source, target, type);
   PY_IGNORE_EXCEPTION("ev_branch 1");
   if(PyInt_AsLong(result)) {
   }
   PY_IGNORE_EXCEPTION("ev_branch 2");
   Py_XDECREF(result);
}

/* initialization/deinitialization of instrumentalization */
#define BX_INSTR_INIT_ENV()
#define BX_INSTR_EXIT_ENV()

/* simulation init, shutdown, reset */
#define BX_INSTR_INITIALIZE(cpu_id) BX_INSTR_COND(INITIALIZE) bx_instr_init(cpu_id)
#define BX_INSTR_EXIT(cpu_id)
#define BX_INSTR_RESET(cpu_id, type)
#define BX_INSTR_HLT(cpu_id)
#define BX_INSTR_MWAIT(cpu_id, addr, len, flags)

/* called from command line debugger */
#  define BX_INSTR_DEBUG_PROMPT()
#  define BX_INSTR_START()
#  define BX_INSTR_STOP()
#  define BX_INSTR_PRINT()

/* branch resolution */
// FIXME Include information about current CPU for all of these
#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu_id, branch_eip, new_eip) \
    BX_INSTR_COND(CNEAR_BRANCH_TAKEN) ev_branch( branch_eip, new_eip, BX_INSTR_IS_JCC_TAKEN);
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu_id, branch_eip) \
    BX_INSTR_COND(CNEAR_BRANCH_NOT_TAKEN) ev_branch( branch_eip, BX_CPU(cpu)->gen_reg[BX_32BIT_REG_EIP].dword.erx, BX_INSTR_IS_JCC_NOTTAKEN);
// FIXME does not cover where the branch would've ended up
#define BX_INSTR_UCNEAR_BRANCH(cpu_id, what, branch_eip, new_eip) \
    BX_INSTR_COND(UCNEAR_BRANCH)  ev_branch( branch_eip, new_eip, what);
#define BX_INSTR_FAR_BRANCH(cpu_id, what, new_cs, new_eip) \
    BX_INSTR_COND(FAR_BRANCH) ev_branch( BX_CPU(cpu)->prev_rip, new_eip, what);
// FIXME also use information about new CS

/* decoding completed */
#define BX_INSTR_OPCODE(cpu_id, i, opcode, len, is32, is64)

/* exceptional case and interrupt */
#define BX_INSTR_EXCEPTION(cpu_id, vector, error_code) /*\
                       BX_INSTR_COND(EXCEPTION) bx_instr_exception(cpu_id, vector) // FIXME error_code not used*/

#define BX_INSTR_INTERRUPT(cpu_id, vector)            BX_INSTR_COND(INTERRUPT) bx_instr_interrupt(cpu_id, vector)
#define BX_INSTR_HWINTERRUPT(cpu_id, vector, cs, eip) BX_INSTR_COND(HWINTERRUPT) bx_instr_hwinterrupt(cpu_id, vector, cs, eip)

/* TLB/CACHE control instruction executed */
#define BX_INSTR_CLFLUSH(cpu_id, laddr, paddr)
#define BX_INSTR_CACHE_CNTRL(cpu_id, what)
#define BX_INSTR_TLB_CNTRL(cpu_id, what, new_cr3) BX_INSTR_COND(TLB_CNTRL) bx_instr_tlb_cntrl(cpu_id, what, new_cr3)
#define BX_INSTR_PREFETCH_HINT(cpu_id, what, seg, offset)

/* execution */
#define BX_INSTR_BEFORE_EXECUTION(cpu_id, i) BX_INSTR_COND(BEFORE_EXECUTION) fetch_pending_page();
#define BX_INSTR_AFTER_EXECUTION(cpu_id, i)
#define BX_INSTR_REPEAT_ITERATION(cpu_id, i)

/* linear memory access */
#define BX_INSTR_LIN_ACCESS(cpu_id, lin, phy, len, rw) \
    BX_INSTR_COND(LIN_ACCESS) if( BX_READ != rw) ev_write( lin, len);

/* physical memory access */
#define BX_INSTR_PHY_ACCESS(cpu_id, phy, len, rw)

/* feedback from device units */
#define BX_INSTR_INP(addr, len)
#define BX_INSTR_INP2(addr, len, val)
#define BX_INSTR_OUTP(addr, len, val)

/* wrmsr callback */
#  define BX_INSTR_WRMSR(cpu_id, addr, value)

#else

/* initialization/deinitialization of instrumentalization*/
#define BX_INSTR_INIT_ENV() bx_instr_init_env()
#define BX_INSTR_EXIT_ENV() bx_instr_exit_env()

/* simulation init, shutdown, reset */
#define BX_INSTR_INITIALIZE(cpu_id)      bx_instr_initialize(cpu_id)
#define BX_INSTR_EXIT(cpu_id)            bx_instr_exit(cpu_id)
#define BX_INSTR_RESET(cpu_id, type)     bx_instr_reset(cpu_id, type)
#define BX_INSTR_HLT(cpu_id)             bx_instr_hlt(cpu_id)

#define BX_INSTR_MWAIT(cpu_id, addr, len, flags) \
                       bx_instr_mwait(cpu_id, addr, len, flags)

/* called from command line debugger */
#define BX_INSTR_DEBUG_PROMPT()          bx_instr_debug_promt()
#define BX_INSTR_DEBUG_CMD(cmd)          bx_instr_debug_cmd(cmd)

/* branch resolution */
#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu_id, branch_eip, new_eip) bx_instr_cnear_branch_taken(cpu_id, branch_eip, new_eip)
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu_id, branch_eip) bx_instr_cnear_branch_not_taken(cpu_id, branch_eip)
#define BX_INSTR_UCNEAR_BRANCH(cpu_id, what, branch_eip, new_eip) bx_instr_ucnear_branch(cpu_id, what, branch_eip, new_eip)
#define BX_INSTR_FAR_BRANCH(cpu_id, what, new_cs, new_eip) bx_instr_far_branch(cpu_id, what, new_cs, new_eip)

/* decoding completed */
#define BX_INSTR_OPCODE(cpu_id, i, opcode, len, is32, is64) \
                       bx_instr_opcode(cpu_id, i, opcode, len, is32, is64)

/* exceptional case and interrupt */
#define BX_INSTR_EXCEPTION(cpu_id, vector, error_code) \
                bx_instr_exception(cpu_id, vector, error_code)

#define BX_INSTR_INTERRUPT(cpu_id, vector) bx_instr_interrupt(cpu_id, vector)
#define BX_INSTR_HWINTERRUPT(cpu_id, vector, cs, eip) bx_instr_hwinterrupt(cpu_id, vector, cs, eip)

/* TLB/CACHE control instruction executed */
#define BX_INSTR_CLFLUSH(cpu_id, laddr, paddr)    bx_instr_clflush(cpu_id, laddr, paddr)
#define BX_INSTR_CACHE_CNTRL(cpu_id, what)        bx_instr_cache_cntrl(cpu_id, what)
#define BX_INSTR_TLB_CNTRL(cpu_id, what, new_cr3) bx_instr_tlb_cntrl(cpu_id, what, new_cr3)
#define BX_INSTR_PREFETCH_HINT(cpu_id, what, seg, offset) \
                       bx_instr_prefetch_hint(cpu_id, what, seg, offset)

/* execution */
#define BX_INSTR_BEFORE_EXECUTION(cpu_id, i)  bx_instr_before_execution(cpu_id, i)
#define BX_INSTR_AFTER_EXECUTION(cpu_id, i)   bx_instr_after_execution(cpu_id, i)
#define BX_INSTR_REPEAT_ITERATION(cpu_id, i)  bx_instr_repeat_iteration(cpu_id, i)

/* linear memory access */
#define BX_INSTR_LIN_ACCESS(cpu_id, lin, phy, len, rw)  bx_instr_lin_access(cpu_id, lin, phy, len, rw)

/* physical memory access */
#define BX_INSTR_PHY_ACCESS(cpu_id, phy, len, rw)  bx_instr_phy_access(cpu_id, phy, len, rw)

/* feedback from device units */
#define BX_INSTR_INP(addr, len)               bx_instr_inp(addr, len)
#define BX_INSTR_INP2(addr, len, val)         bx_instr_inp2(addr, len, val)
#define BX_INSTR_OUTP(addr, len, val)         bx_instr_outp(addr, len, val)

/* wrmsr callback */
#define BX_INSTR_WRMSR(cpu_id, addr, value)   bx_instr_wrmsr(cpu_id, addr, value)

#endif
