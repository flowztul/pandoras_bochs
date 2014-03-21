/////////////////////////////////////////////////////////////////////////
// $Id: instrument.cc,v 1.16 2007/03/14 21:15:15 sshwarts Exp $
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
#if 0
#include <boost/python.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(bochs)
{
    class_<bx_gen_reg_t>("gen_reg_t")
        .def_readwrite("erx", &bx_gen_reg_t::dword)
        .def_readwrite("rx", &bx_gen_reg_t::word)
#if BX_SUPPORT_X86_64
        .def_readwrite("rrx", &bx_gen_reg_t::rrx)
#endif
        ;
    class_<BX_CPU_C>("CPU")
        .def_readwrite("gen_reg", &BX_CPU_C::gen_reg)
       
        .def_readwrite("eflags", &BX_CPU_C::eflags)
    ;
}
#endif

unsigned commit_counter = 0;
unsigned startup_time = 0;
char vmem_read_buf[16384];

#if BX_SUPPORT_SMP
#error This instrumentation skin does not support SMP yet
#define BX_CPU(x)                   (bx_cpu_array[x])
#else
#define BX_CPU(x)                   (&bx_cpu)
#endif

#define vmem_read(...) bx_dbg_read_linear( 0, __VA_ARGS__)
#define pmem_read(addr,len,buf) BX_MEM(0)->dbg_fetch_mem(BX_CPU(0),addr,len,buf)

#define ERROR_NOT_PRESENT       0x00 // from paging.cc
void page_fault( bx_address laddr) {
    BX_CPU(0)->page_fault(ERROR_NOT_PRESENT, laddr, 1, 0);
}

#if BX_INSTRUMENTATION

// #define PROFILE_PYTHON

Bit32u bx_instr_mask = BX_INSTR_COND_INITIALIZE 
                     | BX_INSTR_COND_TLB_CNTRL
                     | BX_INSTR_COND_EXIT
                    /* BX_INSTR_COND_INIT_ENV
                     | BX_INSTR_COND_EXIT_ENV
                     | BX_INSTR_COND_INITIALIZE
                     | BX_INSTR_COND_RESET
                     | BX_INSTR_COND_HLT
                     | BX_INSTR_COND_MWAIT
                     | BX_INSTR_COND_DEBUG_PROMPT
                     | BX_INSTR_COND_DEBUG_CMD
                     | BX_INSTR_COND_CNEAR_BRANCH_TAKEN
                     | BX_INSTR_COND_CNEAR_BRANCH_NOT_TAKEN
                     | BX_INSTR_COND_UCNEAR_BRANCH
                     | BX_INSTR_COND_FAR_BRANCH
                     | BX_INSTR_COND_OPCODE
                     | BX_INSTR_COND_EXCEPTION
                     | BX_INSTR_COND_INTERRUPT
                     | BX_INSTR_COND_HWINTERRUPT
                     | BX_INSTR_COND_CLFLUSH
                     | BX_INSTR_COND_CACHE_CNTRL
                     | BX_INSTR_COND_TLB_CNTRL
                     | BX_INSTR_COND_PREFETCH_HINT
                     | BX_INSTR_COND_BEFORE_EXECUTION
                     | BX_INSTR_COND_AFTER_EXECUTION
                     | BX_INSTR_COND_REPEAT_ITERATION
                     | BX_INSTR_COND_LIN_ACCESS
                     | BX_INSTR_COND_PHY_ACCESS
                     | BX_INSTR_COND_INP
                     | BX_INSTR_COND_INP2
                     | BX_INSTR_COND_OUTP
                     | BX_INSTR_COND_WRMSR
                     */;

bx_bool bx_instr_pending_page;

static PyObject *PyBochs_Python_Module;
static PyObject *PyBochs_C_Module;
static PyObject *PyBochs_PageFaultException;

PyObject *PyBochs_ev_branch;
PyObject *PyBochs_ev_mod_cr3;
PyObject *PyBochs_ev_write;
PyObject *PyBochs_pending_page;

#ifdef PROFILE_PYTHON
static PyObject *PyBochs_Hotshot_Module;
static PyObject *PyBochs_Hotshot_Profiler;
#endif

static PyObject *PyBochs_REG_EAX;
static PyObject *PyBochs_REG_ECX;
static PyObject *PyBochs_REG_EDX;
static PyObject *PyBochs_REG_EBX;
static PyObject *PyBochs_REG_ESP;
static PyObject *PyBochs_REG_EBP;
static PyObject *PyBochs_REG_ESI;
static PyObject *PyBochs_REG_EDI;


PyObject* PyBochsC_pending_page(PyObject* self, PyObject* args) {
   unsigned pending_page;

   if(!PyArg_ParseTuple(args, "I", &pending_page)) {
      return NULL;
   } else {
      bx_instr_pending_page = pending_page;
   }
   Py_INCREF(Py_None);
   return Py_None;
}

// FIXME pdb not used?
bool py_pending_page(bx_address pdb, bx_address *page) {
   bool result = false;
   PyObject* retval = NULL;
   retval = PyObject_CallFunction(PyBochs_pending_page, (char*)"()");
   if(PyErr_Occurred()) {
       PY_IGNORE_EXCEPTION("py_pending_page 1");
   } else {
       if(Py_None == retval) {
       } else {
          *page = PyLong_AsUnsignedLong(retval);
          Py_XDECREF(retval);
          if(PyErr_Occurred()) {
              result = false;
              PY_IGNORE_EXCEPTION("py_pending_page 2");
              return result;
          } else {
              result = true;
              PY_IGNORE_EXCEPTION("py_pending_page 3");
              return result;
          }
        }
  }
   PY_IGNORE_EXCEPTION("pending_page");
    return result;
}


static PyObject* PyBochsC_linear2phy(PyObject *self, PyObject *args) {
   bx_address laddr;
   bx_phy_address pt_address = BX_CPU(0)->cr3;
   if(!PyArg_ParseTuple(args, "I|I", &laddr, &pt_address)) {
      return NULL;
   }
   bx_phy_address phy;
   if(BX_CPU(0)->dbg_xlate_linear2phy(laddr, &phy, true, pt_address)) {
       return Py_BuildValue("I",phy);
   } else {
      //FIXME need to increase reference count?
      PyErr_SetObject(PyBochs_PageFaultException, Py_BuildValue("((II))", laddr, pt_address));
      return NULL;
   }

}

static PyObject* PyBochsC_registers(PyObject *self, PyObject *args) {
   PyObject *retval = NULL;
   if(!PyArg_ParseTuple(args, "")) {
      // raise exception, too?
      return NULL;
   }
   retval = Py_BuildValue(
      "{s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I"
      ",s:h,s:h,s:h,s:h,s:h,s:h"
      ",s:I"
      ",s:I,s:I,s:I,s:I"
      ",s:I"
      "}",
      "eax", BX_CPU(0)->gen_reg[ BX_32BIT_REG_EAX].dword.erx,
      "ecx", BX_CPU(0)->gen_reg[ BX_32BIT_REG_ECX].dword.erx,
      "edx", BX_CPU(0)->gen_reg[ BX_32BIT_REG_EDX].dword.erx,
      "ebx", BX_CPU(0)->gen_reg[ BX_32BIT_REG_EBX].dword.erx,
      "esp", BX_CPU(0)->gen_reg[ BX_32BIT_REG_ESP].dword.erx,
      "ebp", BX_CPU(0)->gen_reg[ BX_32BIT_REG_EBP].dword.erx,
      "esi", BX_CPU(0)->gen_reg[ BX_32BIT_REG_ESI].dword.erx,
      "edi", BX_CPU(0)->gen_reg[ BX_32BIT_REG_EDI].dword.erx,
      "es", BX_CPU(0)->sregs[ BX_SEG_REG_ES].selector.value,
      "cs", BX_CPU(0)->sregs[ BX_SEG_REG_CS].selector.value,
      "ss", BX_CPU(0)->sregs[ BX_SEG_REG_SS].selector.value,
      "ds", BX_CPU(0)->sregs[ BX_SEG_REG_DS].selector.value,
      "fs", BX_CPU(0)->sregs[ BX_SEG_REG_FS].selector.value,
      "gs", BX_CPU(0)->sregs[ BX_SEG_REG_GS].selector.value,
      "eflags", BX_CPU(0)->eflags,
      "cr0", BX_CPU(0)->cr0.val32,
//      "cr1", BX_CPU(0)->cr1, gone
      "cr2", BX_CPU(0)->cr2,
      "cr3", BX_CPU(0)->cr3,
      "cr4", BX_CPU(0)->cr4.val32,
      "eip", BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx
   );
   return retval;
}


static PyObject* PyBochsC_eip(PyObject *self, PyObject *args) {
    return Py_BuildValue("I", BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx);
}

static PyObject* PyBochsC_set_eip(PyObject *self, PyObject *args) {
   unsigned value;
   if(!PyArg_ParseTuple(args, "I", &value)) {
      // raise exception, too?
      return NULL;
   }
   BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = value;
   BX_CPU(0)->prev_rip = value; // FIXME necessary or even correct?
   Py_INCREF(Py_None);
   return Py_None;
}


static PyObject* PyBochsC_genreg(PyObject *self, PyObject *args) {
   unsigned index;
   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   // BX_32BIT_REG_EDI is last register in the gen_reg array
   if(index > BX_32BIT_REG_EDI) {
      return NULL;
   }
   return Py_BuildValue("I", BX_CPU(0)->gen_reg[ index]);
}

static PyObject* PyBochsC_set_genreg(PyObject *self, PyObject *args) {
   unsigned index, value;
   if(!PyArg_ParseTuple(args, "II", &index, &value)) {
      // raise exception, too?
      return NULL;
   }
   // BX_32BIT_REG_EDI is last register in the gen_reg array
   if(index > BX_32BIT_REG_EDI) {
      return NULL;
   }
   BX_CPU(0)->gen_reg[ index].dword.erx = value; // bx_gen_reg_t
   Py_INCREF(Py_None);
   return Py_None;
}

static PyObject* PyBochsC_creg(PyObject *self, PyObject *args) {
   unsigned index;
   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   switch(index) {
      case 0: return Py_BuildValue("I", BX_CPU(0)->cr0.val32);break;
//      case 1: return Py_BuildValue("I", BX_CPU(0)->cr1);break; gone
      case 2: return Py_BuildValue("I", BX_CPU(0)->cr2);break;
      case 3: return Py_BuildValue("I", BX_CPU(0)->cr3);break;
      case 4: return Py_BuildValue("I", BX_CPU(0)->cr4.val32);break;
      default:
          return NULL;
   }
}

static PyObject* PyBochsC_dreg(PyObject *self, PyObject *args) {
   unsigned index;
   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   switch(index) {
      case 0: return Py_BuildValue("I", BX_CPU(0)->dr[0]);break;
      case 1: return Py_BuildValue("I", BX_CPU(0)->dr[1]);break;
      case 2: return Py_BuildValue("I", BX_CPU(0)->dr[2]);break;
      case 3: return Py_BuildValue("I", BX_CPU(0)->dr[3]);break;
      case 4: return NULL;break; // DR4 is reserved, or aliased to DR6
      case 5: return NULL;break; // DR5 is reserved, or aliased to DR7
      case 6: return Py_BuildValue("I", BX_CPU(0)->dr6);break;
      case 7: return Py_BuildValue("I", BX_CPU(0)->dr7);break;
      default:
          return NULL;
   }
}


static PyObject* PyBochsC_sreg(PyObject *self, PyObject *args) {
   unsigned index;
   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   // BX_SEG_REG_GS is last register in the sregs array
   if(index > BX_SEG_REG_GS) {
      return NULL;
   }
   return Py_BuildValue("(hII)", 
                         BX_CPU(0)->sregs[ index].selector.value,
                         BX_CPU(0)->sregs[ index].cache.u.segment.base,
                         BX_CPU(0)->sregs[ index].cache.u.segment.limit_scaled
                       );
}

static PyObject* PyBochsC_logical2linear(PyObject *self, PyObject *args) {
   unsigned short selector;
   unsigned offset, laddr, pdb;
   if(!PyArg_ParseTuple(args, "hII", &selector, &offset, &pdb)) {
      // raise exception, too?
      return NULL;
   }

   laddr = bx_dbg_get_laddr(selector, offset, pdb);

   PyObject *retval = Py_BuildValue("I", laddr);
   return retval;

}

static PyObject* PyBochsC_vmem_read(PyObject *self, PyObject *args) {
   unsigned len, result;
   bx_address addr;
   bx_phy_address pdb;
   PyObject *retval;
   if(!PyArg_ParseTuple(args, "III", &addr, &len, &pdb)) {
      return NULL;
   }
   // FIXME optimization, doesn't work too well when we're still non-paged
//   if(addr % PAGESIZE + len < PAGESIZE) {
//       bx_phy_address phy;
//       if(BX_CPU(0)->dbg_xlate_linear2phy(addr, &phy, true, pdb)) {
//           retval = Py_BuildValue("s#", BX_MEM(0)->get_vector(phy), len);
//           return retval;
//       } else {
//           //FIXME need to increase reference count?
//           PyErr_SetObject(PyBochs_PageFaultException, Py_BuildValue("((II))", addr, pdb));
//           return NULL;
//       }
//   }
   if(len > 16384) {
      char *buf = (char*)malloc(len);
      result = vmem_read(addr, len, (Bit8u*)buf, pdb);
      if(result) {
         retval = Py_BuildValue("s#", buf, len);
      }
      free(buf);
   } else {
      result = vmem_read(addr, len, (Bit8u*)vmem_read_buf, pdb);
      if(result) {
         retval = Py_BuildValue("s#", vmem_read_buf, len);
      }
   }

   if(result) {
      return retval;
   } else {
       //FIXME need to increase reference count?
      PyErr_SetObject(PyBochs_PageFaultException, Py_BuildValue("((II))", addr, pdb));
//      PyErr_Format(PyExc_Exception, "vmem_read(0x%08x, %u, 0x%08x) could not fetch virtual memory", addr, len, pdb);
      return NULL;
   }
}

static PyObject* PyBochsC_shutdown(PyObject *self, PyObject *args) {
      printf("Shutdown requested by Python code - shutting down\n");
      BX_EXIT(0);
      Py_INCREF(Py_None);
      return Py_None;
}

static PyObject* PyBochsC_emulator_time(PyObject *self, PyObject *args) {
    PyObject* retval = PyLong_FromLongLong(bx_pc_system.time_ticks());
    return retval;
}

static PyObject* PyBochsC_pmem_read(PyObject *self, PyObject *args) {
   // def pmem_read(addr, len)
   unsigned addr, len, result;

   if(!PyArg_ParseTuple(args, "II", &addr, &len)) {
      // raise exception, too?
      return NULL;
   }

   char* buf = (char*) malloc(len);
   if(NULL == buf) {
      // raise exception, too?
      return NULL;
   }

   result = BX_MEM(0)->dbg_fetch_mem(BX_CPU(0), addr, len, (Bit8u*)buf);
   if(result) {
       PyObject *retval = Py_BuildValue("s#", buf, len);
       free(buf);
       return retval;
   }
   return NULL;

}


static PyMethodDef PyBochsC_methods[] = {
    {"linear2phy", (PyCFunction)PyBochsC_linear2phy, METH_VARARGS,
     "Convert a linear to a physical address"
    },
    {"vmem_read", (PyCFunction)PyBochsC_vmem_read, METH_VARARGS,
     "Reads from virtual memory and returns a string"
    },
    {"pmem_read", (PyCFunction)PyBochsC_pmem_read, METH_VARARGS,
     "Reads from physical memory and returns a string"
    },
    {"logical2linear", (PyCFunction)PyBochsC_logical2linear, METH_VARARGS,
     "Converts a segment:offset logical address to a linear address"
    },
    {"registers", (PyCFunction)PyBochsC_registers, METH_VARARGS,
     "Returns a dictionary containing all registers"
    },
    {"eip", (PyCFunction)PyBochsC_eip, METH_VARARGS,
     "Returns the eip register"
    },
    {"set_eip", (PyCFunction)PyBochsC_set_eip, METH_VARARGS,
     "Changes the eip register"
    },
    {"genreg", (PyCFunction)PyBochsC_genreg, METH_VARARGS,
     "Returns a general purpose register"
    },
    {"set_genreg", (PyCFunction)PyBochsC_set_genreg, METH_VARARGS,
     "Changes a general purpose register"
    },
    {"creg", (PyCFunction)PyBochsC_creg, METH_VARARGS,
     "Returns a control register"
    },
     {"dreg", (PyCFunction)PyBochsC_dreg, METH_VARARGS,
     "Returns a debug register"
    },
    {"sreg", (PyCFunction)PyBochsC_sreg, METH_VARARGS,
     "Returns a segment register"
    },
    {"emulator_time", (PyCFunction)PyBochsC_emulator_time, METH_VARARGS,
     "Returns the current emulator time"
    },
    {"shutdown", (PyCFunction)PyBochsC_shutdown, METH_VARARGS,
     "Shuts down Bochs"
    },
    {"pending_page", (PyCFunction)PyBochsC_pending_page, METH_VARARGS,
     "Signal to bochs that the python part requires at least one page to be paged in for the current process"
    },
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC
initpybochs(void) 
{
    // Py_InitModule3 takes 3 arguments. Other versions of this function are deprecated
    PyBochs_C_Module = Py_InitModule3("PyBochsC", PyBochsC_methods,
                                       "Python Bochs Interface");
    Py_XINCREF(PyBochs_C_Module);

    PyBochs_REG_EAX = PyInt_FromLong(BX_32BIT_REG_EAX);
    Py_XINCREF(PyBochs_REG_EAX);
    PyBochs_REG_ECX = PyInt_FromLong(BX_32BIT_REG_ECX);
    Py_XINCREF(PyBochs_REG_ECX);
    PyBochs_REG_EDX = PyInt_FromLong(BX_32BIT_REG_EDX);
    Py_XINCREF(PyBochs_REG_EDX);
    PyBochs_REG_EBX = PyInt_FromLong(BX_32BIT_REG_EBX);
    Py_XINCREF(PyBochs_REG_EBX);
    PyBochs_REG_ESP = PyInt_FromLong(BX_32BIT_REG_ESP);
    Py_XINCREF(PyBochs_REG_ESP);
    PyBochs_REG_EBP = PyInt_FromLong(BX_32BIT_REG_EBP);
    Py_XINCREF(PyBochs_REG_EBP);
    PyBochs_REG_ESI = PyInt_FromLong(BX_32BIT_REG_ESI);
    Py_XINCREF(PyBochs_REG_ESI);
    PyBochs_REG_EDI = PyInt_FromLong(BX_32BIT_REG_EDI);
    Py_XINCREF(PyBochs_REG_EDI);

    PyObject_SetAttrString(PyBochs_C_Module, "REG_EAX", PyBochs_REG_EAX );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_ECX", PyBochs_REG_ECX );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_EDX", PyBochs_REG_EDX );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_EBX", PyBochs_REG_EBX );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_ESP", PyBochs_REG_ESP );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_EBP", PyBochs_REG_EBP );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_ESI", PyBochs_REG_ESI );
    PyObject_SetAttrString(PyBochs_C_Module, "REG_EDI", PyBochs_REG_EDI );
}

void fetch_pending_page() {
   // If the current instruction would execute in ring 3,
   // we can instead simulate a page fault to get Windows to
   // page in memory for this process
   if(bx_instr_pending_page && BX_CPU(cpu)->sregs[BX_SEG_REG_CS].selector.rpl == 3) {
      bx_address pagein;
      bool result;
      result = py_pending_page(BX_CPU(0)->cr3, &pagein);
      if(result) {
         page_fault(pagein);
      }
   }
}

// Needed to add an instrumentation event that is called before bochs starts to destruct its objects!
void bx_instr_atexit() {
   PyObject_CallMethod(PyBochs_Python_Module, (char*)"shutdown", (char*)"()");
   PY_IGNORE_EXCEPTION("shutdown");
#ifdef PROFILE_PYTHON
   PyObject_CallMethod(PyBochs_Hotshot_Profiler, "stop", "()");
   Py_XDECREF(PyBochs_Hotshot_Profiler);
   Py_XDECREF(PyBochs_Hotshot_Module);
#endif
 
   Py_XDECREF(PyBochs_PageFaultException);
   Py_XDECREF(PyBochs_Python_Module);
   Py_XDECREF(PyBochs_C_Module);

   Py_Finalize();
}


void bx_instr_init(unsigned cpu) { 
   Py_Initialize();
   initpybochs();
   PyBochs_Python_Module = PyImport_ImportModule("PyBochs");
   PY_IGNORE_EXCEPTION("instr_init");
   Py_XINCREF(PyBochs_Python_Module);
   PyBochs_PageFaultException = PyObject_GetAttrString(PyBochs_Python_Module, "PageFaultException");
   Py_XINCREF(PyBochs_PageFaultException);
   PyBochs_ev_branch = PyObject_GetAttrString(PyBochs_Python_Module, "ev_branch");
   Py_XINCREF(PyBochs_ev_branch);
   PyBochs_ev_write = PyObject_GetAttrString(PyBochs_Python_Module, "ev_write");
   Py_XINCREF(PyBochs_ev_write);
   PyBochs_ev_mod_cr3 = PyObject_GetAttrString(PyBochs_Python_Module, "ev_mod_cr3");
   Py_XINCREF(PyBochs_ev_mod_cr3);
   PyBochs_pending_page = PyObject_GetAttrString(PyBochs_Python_Module, "pending_page");
   Py_XINCREF(PyBochs_pending_page);
#ifdef PROFILE_PYTHON
   PyBochs_Hotshot_Module = PyImport_ImportModule("hotshot");
   PY_IGNORE_EXCEPTION("instr_init");
   Py_XINCREF(PyBochs_Hotshot_Module);
   PyBochs_Hotshot_Profiler = PyObject_CallMethod(PyBochs_Hotshot_Module, "Profile", "(s)", "pybochs-hotshot.log");
   PY_IGNORE_EXCEPTION("instr_init");
   Py_XINCREF(PyBochs_Hotshot_Profiler);
   PyObject_CallMethod(PyBochs_Hotshot_Profiler, "start", "()");
   PY_IGNORE_EXCEPTION("instr_init");
#endif
   startup_time = time(NULL);
   PyObject_CallMethod(PyBochs_Python_Module, (char*)"init", (char*)"I",startup_time);
   PY_IGNORE_EXCEPTION("init");

   bx_instr_pending_page = false;

}

void bx_instr_interrupt(unsigned cpu, unsigned vector) {}
void bx_instr_exception(unsigned cpu, unsigned vector) {}
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, unsigned short cs, unsigned int eip) {}

#endif
