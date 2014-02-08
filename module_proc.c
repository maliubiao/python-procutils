#include <Python.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/quota.h> 
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <attr/xattr.h>
#include <execinfo.h>
#include <linux/capability.h>

extern PyObject *get_cpu_brand();
extern int *do_cpuid(int);

PyDoc_STRVAR(proc_getrusage_doc, "call getrusage");

static PyObject *
proc_getrusage(PyObject *object, PyObject *args)
{
	struct rusage usage;		
	PyObject *ru_utime_tuple;
	PyObject *ru_stime_tuple;
	PyObject *usage_dict; 
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	usage_dict = PyDict_New();
	ru_utime_tuple = PyTuple_Pack(2, 
			PyInt_FromLong(usage.ru_utime.tv_sec),
			PyInt_FromLong(usage.ru_utime.tv_usec)
			); 
	ru_stime_tuple = PyTuple_Pack(2,
			PyInt_FromLong(usage.ru_stime.tv_sec),
			PyInt_FromLong(usage.ru_stime.tv_usec)
			); 

	PyDict_SetItemString(usage_dict, "utime", ru_utime_tuple);
	PyDict_SetItemString(usage_dict, "stime", ru_stime_tuple); 
	PyDict_SetItemString(usage_dict, "maxrss", PyInt_FromLong(usage.ru_maxrss));
	PyDict_SetItemString(usage_dict, "ixrss", PyInt_FromLong(usage.ru_ixrss));
	PyDict_SetItemString(usage_dict, "isrss", PyInt_FromLong(usage.ru_isrss));
	PyDict_SetItemString(usage_dict, "minflt", PyInt_FromLong(usage.ru_minflt));
	PyDict_SetItemString(usage_dict, "majflt", PyInt_FromLong(usage.ru_majflt));
	PyDict_SetItemString(usage_dict, "nswap", PyInt_FromLong(usage.ru_nswap));
	PyDict_SetItemString(usage_dict, "inblock", PyInt_FromLong(usage.ru_inblock));
	PyDict_SetItemString(usage_dict, "oublock", PyInt_FromLong(usage.ru_oublock));
	PyDict_SetItemString(usage_dict, "msgsnd", PyInt_FromLong(usage.ru_msgsnd));
	PyDict_SetItemString(usage_dict, "msgrcv", PyInt_FromLong(usage.ru_msgrcv));
	PyDict_SetItemString(usage_dict, "nsignals", PyInt_FromLong(usage.ru_nsignals));
	PyDict_SetItemString(usage_dict, "nvcsw", PyInt_FromLong(usage.ru_nvcsw));
	PyDict_SetItemString(usage_dict, "nivcsw", PyInt_FromLong(usage.ru_nivcsw));
	return usage_dict;
}


PyDoc_STRVAR(proc_getrlimit_doc, "call getrlimit, return None if failed");

static PyObject *
proc_getrlimit(PyObject *object, PyObject *args)
{
	int resource; 
	struct rlimit limit; 
	if(!PyArg_ParseTuple(args, "i:getrlimit", &resource)) {
		return NULL;
	}
	if(getrlimit(resource, &limit) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	} 
	return  PyTuple_Pack(2, 
			PyInt_FromLong(limit.rlim_cur),
			PyInt_FromLong(limit.rlim_max)
			);

}


PyDoc_STRVAR(proc_setrlimit_doc, "call setrlimit, return False if failed");

static PyObject *
proc_setrlimit(PyObject *object, PyObject *args)
{
	int resource;
	struct rlimit limit;
	PyObject *limit_tuple;
	if(!PyArg_ParseTuple(args, "IO:setrlimit", &resource, &limit_tuple)){
		return NULL;
	}
	limit.rlim_cur = PyInt_AsLong(PyTuple_GetItem(limit_tuple, 0));
	limit.rlim_max = PyInt_AsLong(PyTuple_GetItem(limit_tuple, 1));
	if(setrlimit(resource, &limit) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}
	Py_RETURN_NONE; 
}

PyDoc_STRVAR(proc_getcpu_doc, "syscall getcpu, return tuple (cpu, numanode), or None if failed");

static PyObject *
proc_getcpu(PyObject *object, PyObject *args)
{
	unsigned cpu;
	unsigned node;
	/*ignored since 2.6.24*/ 
	if (syscall(SYS_getcpu, &cpu, &node, NULL) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);	
		return NULL;
	}
	return PyTuple_Pack(2, PyInt_FromLong((signed long)(cpu)), PyInt_FromLong((signed long)(node)));
}


PyDoc_STRVAR(proc_sched_setaffinity_doc, "call sched_setaffinity");

static PyObject *
proc_sched_setaffinity(PyObject *object, PyObject *args)
{
	int pid; 
	PyObject *set_list;
	PyObject *set_iter;
	PyObject *set_next;
	cpu_set_t set;
	
	if(!PyArg_ParseTuple(args, "IO:sched_setaffinity", &pid, &set_list)) {
		return NULL;
	} 

	CPU_ZERO(&set);	
	set_iter = PyObject_GetIter(set_list);
	if (!set_iter) {
		PyErr_SetString(PyExc_TypeError, "set_list is not iterable");
		return NULL;
	}
	set_next = PyIter_Next(set_iter);
	while(set_next) {	
		if (!PyInt_Check(set_next)) {
			Py_DECREF(set_iter); 
			Py_DECREF(set_next);
			PyErr_SetString(PyExc_TypeError, "there is somethingthat is not a integer in set_list");
			return NULL;
		}
		CPU_SET(PyInt_AsLong(set_next), &set);
		Py_DECREF(set_next);
		set_next = PyIter_Next(set_iter);
	}
	Py_DECREF(set_iter);
	if (sched_setaffinity(pid, sizeof(set), &set) < 0) { 
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;

	} 
	Py_RETURN_NONE;
}	

PyDoc_STRVAR(proc_sched_getaffinity_doc, "call sched_getaffinity");

static PyObject *
proc_sched_getaffinity(PyObject *object, PyObject *args)
{
	int cpus_count;
	int pid;
	cpu_set_t set;
	PyObject *set_list; 
	if(!PyArg_ParseTuple(args, "I:sched_getaffinity", &pid)) {
		return NULL;
	} 
	CPU_ZERO(&set);
	if (sched_getaffinity(pid, sizeof(cpu_set_t), &set) < 0){ 
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	cpus_count = CPU_COUNT(&set);
	set_list = PyList_New(0);
	/*0->n util we find all cpus in this set */
	int n = 0; 
	while (cpus_count > 0) {
		if (CPU_ISSET(n, &set)) { 
			PyList_Append(set_list, PyInt_FromLong(n));
			cpus_count -= 1; 		
		}
		n += 1; 
	} 
	return set_list; 
}


PyDoc_STRVAR(proc_getpriority_doc, "call getpriority");

static PyObject *
proc_getpriority(PyObject *object, PyObject *args)
{
	int which;
	int who; 
	int priority;
	if(!PyArg_ParseTuple(args, "II:getpriority", &which, &who)) {
		return NULL;
	}
	priority = getpriority(which , who);
	if(priority < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	return PyInt_FromLong(priority); 
}	


PyDoc_STRVAR(proc_get_cpu_brand_doc, "call get_cpu_brand");


static PyObject *
proc_get_cpu_brand(PyObject *object, PyObject *args)
{
	PyObject *name;
	name = get_cpu_brand();
	if (name) {
		return name;
	}
	Py_RETURN_NONE;

}

PyDoc_STRVAR(proc_get_cpu_feature_doc, "call get_cpu_feature");

static PyObject *
proc_get_cpu_feature(PyObject *object, PyObject *args)
{
	int *buf;
	PyObject *rd;
	unsigned int *ptr; 
	buf = do_cpuid(0x1); 
	if (!buf)
		Py_RETURN_NONE;
	ptr = (unsigned int *)buf;
	//stepping id bits[0:3]
	rd = PyDict_New();
	PyDict_SetItemString(rd, "stepping_id", PyInt_FromLong(*ptr & 0xf));
	//model bits[4:7]
	PyDict_SetItemString(rd, "model", PyInt_FromLong((*ptr & 0xf0)>>4));
	//family bits[8:11]
	PyDict_SetItemString(rd, "family", PyInt_FromLong((*ptr & 0xf00) >> 8));
	//type bits[12:13], 00b OEM, 01b OVerDrive, 10b Dual Procssor
	PyDict_SetItemString(rd, "process_type", PyInt_FromLong((*ptr & 0x3000) >> 12));
	//extended model id bits[16:19]
	PyDict_SetItemString(rd, "extended_mode", PyInt_FromLong((*ptr & 0xf0000) >> 16));
	//extended family id bits[20:27]
	PyDict_SetItemString(rd, "extended_family", PyInt_FromLong((*ptr & 0xff00000) >> 20));
	ptr += 1; 
	//brand index bits[0:7]
	PyDict_SetItemString(rd, "brand", PyInt_FromLong(*ptr & 0xff));
	//clflush line size bits[8:15]
	PyDict_SetItemString(rd, "clflush", PyInt_FromLong((*ptr & 0xff00) >> 8));
	//inital APIC ID bits[24:31]
	PyDict_SetItemString(rd, "initial_apic", PyInt_FromLong((*ptr & 0xff000000) >> 24));
	ptr += 1; 
	//bit 0, SSE3, Streaming SIMD Extension 3
	PyDict_SetItemString(rd, "sse3", PyBool_FromLong(*ptr & 0x1));
	//bit 1, PCLMULQDQ
	PyDict_SetItemString(rd, "pclmulqdq", PyBool_FromLong(*ptr & 0x2));
	//bit 2, DTES64,  DS area using 64-bit layout
	PyDict_SetItemString(rd, "dtes64", PyBool_FromLong(*ptr & 0x4));
	//bit 3, MONITOR
	PyDict_SetItemString(rd, "monitor", PyBool_FromLong(*ptr & 0x8));
	//bit 4 DS_CPL, CPL Qualified Debug Store
	PyDict_SetItemString(rd, "ds_cpl", PyBool_FromLong(*ptr & 0x10));
	//bit 5 VMX, Virtual Machine Extension
	PyDict_SetItemString(rd, "vmx", PyBool_FromLong(*ptr & 0x20));
	//bit 6 SMX, Safer Mode Extensions
	PyDict_SetItemString(rd, "smx", PyBool_FromLong(*ptr & 0x40));
	//bit 7 EIST, Enhanced Intel SpeedStep Technology
	PyDict_SetItemString(rd, "eist", PyBool_FromLong(*ptr & 0x80));
	//bit 8 TM2, Thermal Monitor 2
	PyDict_SetItemString(rd, "tm2", PyBool_FromLong(*ptr & 0x100));
	//bit 9 SSSE3, Supplemental SSE3
	PyDict_SetItemString(rd, "ssse3", PyBool_FromLong(*ptr & 0x200));
	//bit 10 CNXT-ID, L1 Context ID
	PyDict_SetItemString(rd, "cnxt-id", PyBool_FromLong(*ptr & 0x400));
	//bit 11 Reserved
	//*ptr & 0x800;
	//bit 12 FMA
	PyDict_SetItemString(rd, "fma", PyBool_FromLong(*ptr & 0x1000));
	//bit 13 CMPXCHG16B
	PyDict_SetItemString(rd, "cmpxchg16b", PyBool_FromLong(*ptr & 0x2000));
	//bit 14 xTPR Update Control
	PyDict_SetItemString(rd, "xtpr", PyBool_FromLong(*ptr & 0x4000));
	//bit 15 PDCM, Perfmon and Debug Capability
	PyDict_SetItemString(rd, "pdcm", PyBool_FromLong(*ptr & 0x8000));
	//bit 16 Reserved
	//*ptr & 0x10000;
	//bit 17 PCID, Process-context identifiers
	PyDict_SetItemString(rd, "pcid", PyBool_FromLong(*ptr & 0x20000));
	//bit 18 DCA, prefetch data from a memory mapped device
	PyDict_SetItemString(rd, "dca", PyBool_FromLong(*ptr & 0x40000));
	//bit 19 SSE4.1
	PyDict_SetItemString(rd, "sse41", PyBool_FromLong(*ptr & 0x80000));
	//bit 20 SSE 4.2
	PyDict_SetItemString(rd, "sse42", PyBool_FromLong(*ptr & 0x100000));
	//bit 21 x2APIC
	PyDict_SetItemString(rd, "x2apic", PyBool_FromLong(*ptr & 0x200000));
	//bit 22 MOVBE
	PyDict_SetItemString(rd, "movbe", PyBool_FromLong(*ptr & 0x400000));
	//bit 23 POPCNT
	PyDict_SetItemString(rd, "popcnt", PyBool_FromLong(*ptr & 0x800000));
	//bit 24 TSC-Dealine
	PyDict_SetItemString(rd, "tsc", PyBool_FromLong(*ptr & 0x1000000));
	//bit 25 AESNI
	PyDict_SetItemString(rd, "aesni", PyBool_FromLong(*ptr & 0x2000000));
	//bit 26 XSAVE
	PyDict_SetItemString(rd, "xsave", PyBool_FromLong(*ptr & 0x4000000));
	//bit 27 OSXSAVE
	PyDict_SetItemString(rd, "osxsave", PyBool_FromLong(*ptr & 0x8000000));
	//bit 28 AVX
	PyDict_SetItemString(rd, "avx", PyBool_FromLong(*ptr & 0x10000000));
	//bit 29 F16C
	PyDict_SetItemString(rd, "f16c", PyBool_FromLong(*ptr & 0x20000000));
	//bit 30 RDRAND
	PyDict_SetItemString(rd, "rdrand", PyBool_FromLong(*ptr & 0x40000000));
	//bit 31 Not Used
	//*ptr & 0x80000000; 
	ptr += 1;
	//bit 0, FPU-x87 FPU on Chip 
	PyDict_SetItemString(rd, "fpu_x87", PyBool_FromLong(*ptr & 0x1));
	//bit 1, VME-Virtual-8086 Mode Enancement
	PyDict_SetItemString(rd, "vme", PyBool_FromLong(*ptr & 0x2));
	//bit 2, DE-Debuggin Extensions
	PyDict_SetItemString(rd, "de", PyBool_FromLong(*ptr & 0x4));
	//bit 3, PSE-Page Size Extensions
	PyDict_SetItemString(rd, "pse", PyBool_FromLong(*ptr & 0x8));
	//bit 4, TSC-Time Stamp Counter
	PyDict_SetItemString(rd, "tsc", PyBool_FromLong(*ptr & 0x10));
	//bit 5, MSR-RDMSR and WRMSR Support
	PyDict_SetItemString(rd, "msr_rdmsr", PyBool_FromLong(*ptr & 0x20));
	//bit 6, PAE-Physical Address Extension
	PyDict_SetItemString(rd, "pae", PyBool_FromLong(*ptr & 0x40));
	//bit 7, MCE-Machine Check Exception
	PyDict_SetItemString(rd, "mce", PyBool_FromLong(*ptr & 0x80));
	//bit 8, CX8-CMPXCHG8B Inst
	PyDict_SetItemString(rd, "cx8_cmpxchg8b", PyBool_FromLong(*ptr & 0x100));
	//bit 9, APIC-APIC on Chip
	PyDict_SetItemString(rd, "apic", PyBool_FromLong(*ptr & 0x200));
	//bit 10, Reserved
	//*ptr & 0x400;
	//bit 11, SEP-SYSENTER and SYSEXIT 
	PyDict_SetItemString(rd, "sep", PyBool_FromLong(*ptr & 0x800));
	//bit 12, MTRR-Memory Type Range Registers
	PyDict_SetItemString(rd, "mtrr", PyBool_FromLong(*ptr & 0x1000));
	//bit 13, PGE-PTE Global Bit
	PyDict_SetItemString(rd, "pge_pte", PyBool_FromLong(*ptr & 0x2000));
	//bit 14, MCA-Macine Check Architecture
	PyDict_SetItemString(rd, "mca", PyBool_FromLong(*ptr & 0x4000));
	//bit 15, CMOV-Conditional Move/Compare Instruction
	PyDict_SetItemString(rd, "cmov", PyBool_FromLong(*ptr & 0x8000));
	//bit 16, PAT-Page Attribute Table
	PyDict_SetItemString(rd, "pat", PyBool_FromLong(*ptr & 0x10000));
	//bit 17, PSE-36-Page Size Extension
	PyDict_SetItemString(rd, "pse", PyBool_FromLong(*ptr & 0x20000));
	//bit 18, PSN-Processor Serial Number
	PyDict_SetItemString(rd, "psn", PyBool_FromLong(*ptr & 0x40000));
	//bit 19, CLFSH-CFLUSH instruction
	PyDict_SetItemString(rd, "clfsh_cflush", PyBool_FromLong(*ptr & 0x80000));
	//bit 20, Reserved
	//*ptr & 0x100000;;
	//bit 21, DS-Debug Store
	PyDict_SetItemString(rd, "ds", PyBool_FromLong(*ptr & 0x200000));
	//bit 22, ACPI-Thermal Monitor and Clock Ctrl
	PyDict_SetItemString(rd, "acpi_thermal", PyBool_FromLong(*ptr & 0x400000));
	//bit 23, MMX-MMx Technology
	PyDict_SetItemString(rd, "mmx", PyBool_FromLong(*ptr & 0x800000));
	//bit 24, FXSR-FXSAVE/FXRSTOR
	PyDict_SetItemString(rd, "fxsr_sxsave", PyBool_FromLong(*ptr & 0x1000000));
	//bit 25, SSE-SSE Extensions
	PyDict_SetItemString(rd, "sse", PyBool_FromLong(*ptr & 0x2000000));
	//bit 26, SSE2- SSE2 Exension
	PyDict_SetItemString(rd, "sse2", PyBool_FromLong(*ptr & 0x4000000));
	//bit 27, SS-Self SNoop
	PyDict_SetItemString(rd, "ss", PyBool_FromLong(*ptr & 0x8000000));
	//bit 28, HTT, Multi-threading, 
	PyDict_SetItemString(rd, "htt", PyBool_FromLong(*ptr & 0x10000000));
	//bit 29, TM-Therm.Monitor
	PyDict_SetItemString(rd, "tm", PyBool_FromLong(*ptr & 0x20000000));		 //bit 30, Reserved
	//*ptr & 0x40000000;
	//bit 31, PBE-Pend.Brk.EN
	PyDict_SetItemString(rd, "pbe", PyBool_FromLong(*ptr & 0x80000000)); 
	PyMem_Free(buf);
	return rd; 
}

PyDoc_STRVAR(proc_setpriority_doc, "call setpriority");

static PyObject *
proc_setpriority(PyObject *object, PyObject *args)
{
	int which;
	int who;
	int prio;
	if(!PyArg_ParseTuple(args, "III:setpriority", &which, &who, &prio)) {
		return NULL;
	}
	if(setpriority(which, who, prio) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;
}

PyDoc_STRVAR(proc_enable_quota_doc, "call quotactl with QUOTAON");

static PyObject *
proc_enable_quota(PyObject *object, PyObject *args)
{
	char *dev;	
	int id;
	int type;
	int ret;
	char *quota_file;
	if(!PyArg_ParseTuple(args, "iiss:quotactl", &type, &id, &dev, &quota_file)) {
		return NULL;
	}
	ret = quotactl(QCMD(Q_QUOTAON, type), dev, id, (caddr_t)quota_file);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;

}

PyDoc_STRVAR(proc_disable_quota_doc, "call quotactl with QUOTAOFF");

static PyObject *
proc_disable_quota(PyObject *object, PyObject *args)
{
	char *dev; 
	int type;
	int ret;
	if(!PyArg_ParseTuple(args, "iis:quotactl", &type, &dev)) {
		return NULL;
	}
	ret = quotactl(QCMD(Q_QUOTAOFF, type), dev, 0, NULL);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	Py_RETURN_NONE;
}

PyDoc_STRVAR(proc_get_quota_doc, "call quotactl with GETQUOTA");

static PyObject *
proc_get_quota(PyObject *object, PyObject *args)
{
	char *dev;
	int id;
	int type;
	int ret;
	uint32_t valid;
	PyObject *ret_dict;
	struct dqblk info;
	
	if (!PyArg_ParseTuple(args, "iis:quotactl", &type, &id, &dev)) {
		return NULL;
	}
	ret = quotactl(QCMD(Q_GETQUOTA, type), dev, id, (caddr_t)&info);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	ret_dict = PyDict_New();
	valid = info.dqb_valid; 
	if (valid & QIF_BLIMITS) {
		PyDict_SetItemString(ret_dict, "block_hard_limit", PyInt_FromLong(info.dqb_bhardlimit));
		PyDict_SetItemString(ret_dict, "block_soft_limit", PyInt_FromLong(info.dqb_bsoftlimit));
	}
	if (valid & QIF_SPACE) {
		PyDict_SetItemString(ret_dict, "current_block_count", PyInt_FromLong(info.dqb_curspace));
	}
	if (valid & QIF_ILIMITS) {
		PyDict_SetItemString(ret_dict, "hard_inode_limit", PyInt_FromLong(info.dqb_ihardlimit));
		PyDict_SetItemString(ret_dict, "soft_inode_limit", PyInt_FromLong(info.dqb_isoftlimit)); 

		PyDict_SetItemString(ret_dict, "current_inode_count", PyInt_FromLong(info.dqb_curinodes));
	}
	if (valid & QIF_ITIME) {
		PyDict_SetItemString(ret_dict, "file_time_limit", PyInt_FromLong(info.dqb_btime));
	}
	if (valid & QIF_BTIME) {
		PyDict_SetItemString(ret_dict, "disk_time_limit", PyInt_FromLong(info.dqb_itime)); 
	}
	return ret_dict; 
}

PyDoc_STRVAR(proc_setxattr_doc, "call setxattr");

static PyObject *
proc_setxattr(PyObject *object, PyObject *args)
{
	char *path;
	char *name;
	char *value;
	int flags;
	int ret;
	if (!PyArg_ParseTuple(args, "ssss:setxattr", &path, &name, &value, &flags)) {
		return NULL;
	}
	ret = setxattr(path, name, value, strlen(value), flags);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}

PyDoc_STRVAR(proc_lsetxattr_doc, "call lsetxattr");

static PyObject *
proc_lsetxattr(PyObject *object, PyObject *args)
{
	char *path;
	char *name;
	char *value;
	int flags;
	int ret;
	if (!PyArg_ParseTuple(args, "ssss:lsetxattr", &path, &name, &value, &flags)) {
		return NULL;
	}
	ret = lsetxattr(path, name, value, strlen(value), flags);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}

PyDoc_STRVAR(proc_fsetxattr_doc, "call fsetxattr"); 

static PyObject *
proc_fsetxattr(PyObject *object, PyObject *args)
{
	int fd;
	char *name;
	char *value;
	int flags;
	int ret;
	if (!PyArg_ParseTuple(args, "ssss:fsetxattr", &fd, &name, &value, &flags)) {
		return NULL;
	}
	ret = fsetxattr(fd, name, value, strlen(value), flags);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}


PyDoc_STRVAR(proc_listxattr_doc, "call listxattr"); 

static PyObject *
proc_listxattr(PyObject *object, PyObject *args)
{
	char *path; 
	char *buf;
	int ret; 
	if (!PyArg_ParseTuple(args, "s:listxattr", &path)) {
		return NULL;
	} 
	buf = PyMem_Malloc(1024); 
	ret = listxattr(path, buf, 1024);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	return PyString_FromStringAndSize(buf, ret);
}


PyDoc_STRVAR(proc_llistxattr_doc, "call listxattr"); 

static PyObject *
proc_llistxattr(PyObject *object, PyObject *args)
{
	char *path; 
	char *buf;
	int ret; 
	if (!PyArg_ParseTuple(args, "s:llistxattr", &path)) {
		return NULL;
	} 
	buf = PyMem_Malloc(1024); 
	ret = llistxattr(path, buf, 1024);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	return PyString_FromStringAndSize(buf, ret);
	
}


PyDoc_STRVAR(proc_flistxattr_doc, "call listxattr"); 

static PyObject *
proc_flistxattr(PyObject *object, PyObject *args)
{
	int fd ; 
	char *buf;
	int ret; 
	if (!PyArg_ParseTuple(args, "i:flistxattr", &fd)) {
		return NULL;
	} 
	buf = PyMem_Malloc(1024); 
	ret = flistxattr(fd, buf, 1024);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	return PyString_FromStringAndSize(buf, ret); 
}

PyDoc_STRVAR(proc_removexattr_doc, "call removexattr");

static PyObject *
proc_removexattr(PyObject *object, PyObject *args)
{
	char *path;
	char *name;
	int ret;
	if (!PyArg_ParseTuple(args, "ss:removexattr", &path, &name)) {
		return NULL;
	}
	ret = removexattr(path, name);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;	
}
	

PyDoc_STRVAR(proc_lremovexattr_doc, "call lremovexattr");

static PyObject *
proc_lremovexattr(PyObject *object, PyObject *args)
{
	char *path;
	char *name;
	int ret;
	if (!PyArg_ParseTuple(args, "ss:lremovexattr", &path, &name)) {
		return NULL;
	}
	ret = lremovexattr(path, name);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;	
}

PyDoc_STRVAR(proc_fremovexattr_doc, "call fremovexattr");

static PyObject *
proc_fremovexattr(PyObject *object, PyObject *args)
{
	int fd;
	char *name;
	int ret;
	if (!PyArg_ParseTuple(args, "is:fremovexattr", &fd, &name)) {
		return NULL;
	}
	ret = fremovexattr(fd, name);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;	
}

/*
PyDoc_STRVAR(proc_getxattr_doc, "call getxattr"); 
static PyObject *
proc_getxattr(PyObject *object, PyObject *args)
{
	Py_RETURN_NONE;
}
*/

PyDoc_STRVAR(proc_sendfile_doc, "call sendfile, see man sendfile, return"
		"(the number of bytes writted to out_fd,"
		"The last read byte location");


static PyObject *
proc_sendfile(PyObject *object, PyObject *args)
{
	int in_fd;
	int out_fd;
	off_t offset;
	int count;	
	int ret;
	if (!PyArg_ParseTuple(args, "iiii:sendfile", &out_fd, &in_fd, &count)) {
		return NULL;
	}
	ret = sendfile(out_fd, in_fd, &offset, count);	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);		
		return NULL;
	}
	return PyTuple_Pack(2, PyInt_FromLong(ret), PyInt_FromLong(offset));
}


PyDoc_STRVAR(proc_force_exit_doc, "force_exit, end process without any exception");

static PyObject *
proc_force_exit(PyObject *object, PyObject *args)
{
	int ret;
	if (!PyArg_ParseTuple(args, "i:force_exit", &ret)) {
		return NULL;
	} 
	exit(ret);
}

PyDoc_STRVAR(proc_cap_get_doc, "get capability of pid");

static PyObject *
proc_cap_get(PyObject *object, PyObject *args)
{
	int pid = 0; 
	int ret = 0;
	struct __user_cap_data_struct *cap_data = NULL; 
	struct __user_cap_header_struct cap_header;
	if (!PyArg_ParseTuple(args, "i:cap_get", &pid)) {
		return NULL;
	}
	cap_header.version = _LINUX_CAPABILITY_VERSION_3;
	cap_header.pid = pid;
	cap_data = PyMem_Malloc(_LINUX_CAPABILITY_U32S_3 * sizeof(struct __user_cap_data_struct));
	if (!cap_data) {
		PyErr_SetString(PyExc_OSError, "failed to allocate memory");
		return NULL;
	}
	ret = syscall(SYS_capget, &cap_header, cap_data);
	if (ret) {
		errno = ret;
		PyErr_SetFromErrno(PyExc_OSError);
		PyMem_Free(cap_data);
		return 0; 
	}
	unsigned i = 0;
	PyObject *cap_ret_list = PyList_New(0);
	for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++) {
		PyObject *cap_dict = PyDict_New();
		PyDict_SetItemString(cap_dict, "effective", PyLong_FromUnsignedLong((cap_data + i)->effective));
		PyDict_SetItemString(cap_dict, "permitted", PyLong_FromUnsignedLong((cap_data + i)->permitted));
		PyDict_SetItemString(cap_dict, "inheritable", PyLong_FromUnsignedLong((cap_data +i)->inheritable));
		PyList_Append(cap_ret_list, cap_dict);

	}
	return cap_ret_list; 
}

PyDoc_STRVAR(proc_backtrace_doc, "backtrace n frames, use n=0 to get as many as possible"); 

static PyObject *
proc_backtrace(PyObject *object, PyObject *args)
{
	int count = 0; 
	int memsize = 0;
	int nptrs = 0; 
	void **buffer = NULL; 
	char **strings = NULL; 
	PyObject *retlist = NULL;

	if(!PyArg_ParseTuple(args, "I:backtrace", &count)) {
		return NULL;
	}
#define BUFFER_SIZE 1024 
	if (count == 0) {
		count = BUFFER_SIZE; 
	} 
	memsize = sizeof(void *) * count;
#undef BUFFER_SIZE
	buffer = PyMem_Malloc(memsize);
	if (buffer == NULL) {
		goto NOMEMORY;
	}
	nptrs = backtrace(buffer, count);	
	strings = backtrace_symbols(buffer, nptrs); 
	PyMem_Free(buffer);
	if (strings == NULL) {
		goto SYMFAILED;
	}
	retlist = PyList_New(0);	
	unsigned i = 0;
	for (i = 0; i < nptrs; i++) {
		PyList_Append(retlist, PyString_FromString(strings[i]));
	}
	free(strings);
	return retlist;
NOMEMORY: 
	PyErr_SetString(PyExc_RuntimeError, "failed to allocate memory");
	return NULL;
SYMFAILED:
	PyErr_SetString(PyExc_RuntimeError, "failed to get symbols");
	return NULL;

}


static PyMethodDef proc_methods[] = {
	{"getrusage", (PyCFunction)proc_getrusage, 
		METH_VARARGS, proc_getrusage_doc},
	{"getrlimit", (PyCFunction)proc_getrlimit,
		METH_VARARGS, proc_getrlimit_doc},
	{"setrlimit", (PyCFunction)proc_setrlimit,
		METH_VARARGS, proc_setrlimit_doc},
	{"sched_getaffinity", (PyCFunction)proc_sched_getaffinity,
		METH_VARARGS, proc_sched_getaffinity_doc},
	{"sched_setaffinity", (PyCFunction)proc_sched_setaffinity,
		METH_VARARGS, proc_sched_setaffinity_doc},
	{"getpriority", (PyCFunction)proc_getpriority,
		METH_VARARGS, proc_getpriority_doc},
	{"setpriority", (PyCFunction)proc_setpriority,
		METH_VARARGS, proc_setpriority_doc},
	{"getcpu", (PyCFunction)proc_getcpu,
		METH_VARARGS, proc_getcpu_doc}, 
	{"get_cpu_brand", (PyCFunction)proc_get_cpu_brand,
		METH_VARARGS, proc_get_cpu_brand_doc}, 
	{"get_cpu_feature", (PyCFunction)proc_get_cpu_feature,
		METH_VARARGS, proc_get_cpu_feature_doc},
	{"get_quota", (PyCFunction)proc_get_quota,
		METH_VARARGS, proc_get_quota_doc},
	{"enable_quota", (PyCFunction)proc_enable_quota,
		METH_VARARGS, proc_enable_quota_doc},
	{"disable_quota", (PyCFunction)proc_disable_quota,
		METH_VARARGS, proc_disable_quota_doc},
	{"sendfile", (PyCFunction)proc_sendfile,
		METH_VARARGS, proc_sendfile_doc},
	{"setxattr", (PyCFunction)proc_setxattr,
		METH_VARARGS, proc_setxattr_doc},
	{"lsetxattr", (PyCFunction)proc_lsetxattr,
		METH_VARARGS, proc_lsetxattr_doc},
	{"fsetxattr", (PyCFunction)proc_fsetxattr,
		METH_VARARGS, proc_fsetxattr_doc},
	{"listxattr", (PyCFunction)proc_listxattr,
		METH_VARARGS, proc_listxattr_doc},
	{"llistxattr", (PyCFunction)proc_llistxattr,
		METH_VARARGS, proc_llistxattr_doc},
	{"flistxattr", (PyCFunction)proc_flistxattr,
		METH_VARARGS, proc_flistxattr_doc},
	{"removexattr", (PyCFunction)proc_removexattr,
		METH_VARARGS, proc_removexattr_doc},
	{"lremovexattr", (PyCFunction)proc_lremovexattr,
		METH_VARARGS, proc_lremovexattr_doc},
	{"fremovexattr", (PyCFunction)proc_fremovexattr,
		METH_VARARGS, proc_fremovexattr_doc}, 
	{"force_exit", (PyCFunction)proc_force_exit,
		METH_VARARGS, proc_force_exit_doc},
	{"cap_get", (PyCFunction)proc_cap_get,
		METH_VARARGS, proc_cap_get_doc},
	{"backtrace", (PyCFunction)proc_backtrace,
		METH_VARARGS, proc_backtrace_doc}, 
	{NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC init_proc(void)
{
	PyObject *m;
	m = Py_InitModule("_proc", proc_methods);
	if (m != NULL) { 
	PyModule_AddObject(m, "RLIMIT_AS", PyInt_FromLong(RLIMIT_AS));	
	PyModule_AddObject(m, "RLIMIT_CORE", PyInt_FromLong(RLIMIT_CORE));
	PyModule_AddObject(m, "RLIMIT_CPU", PyInt_FromLong(RLIMIT_CPU));
	PyModule_AddObject(m, "RLIMIT_DATA", PyInt_FromLong(RLIMIT_DATA));
	PyModule_AddObject(m, "RLIMIT_FSIZE", PyInt_FromLong(RLIMIT_FSIZE));
	PyModule_AddObject(m, "RLIMIT_MEMLOCK", PyInt_FromLong(RLIMIT_MEMLOCK));
	PyModule_AddObject(m, "RLIMIT_STACK", PyInt_FromLong(RLIMIT_STACK));
	PyModule_AddObject(m, "RLIMIT_RSS", PyInt_FromLong(RLIMIT_RSS));
	PyModule_AddObject(m, "RLIMIT_NOFILE", PyInt_FromLong(RLIMIT_NOFILE));
	PyModule_AddObject(m, "RLIMIT_OFILE", PyInt_FromLong(RLIMIT_OFILE));
	PyModule_AddObject(m, "RLIMIT_NPROC", PyInt_FromLong(RLIMIT_NPROC));
	PyModule_AddObject(m, "RLIMIT_LOCKS", PyInt_FromLong(RLIMIT_LOCKS));
	PyModule_AddObject(m, "RLIMIT_SIGPENDING", PyInt_FromLong(RLIMIT_SIGPENDING));
	PyModule_AddObject(m, "RLIMIT_MSGQUEUE", PyInt_FromLong(RLIMIT_MSGQUEUE));
	PyModule_AddObject(m, "RLIMIT_NICE", PyInt_FromLong(RLIMIT_NICE));
	PyModule_AddObject(m, "RLIMIT_RTPRIO", PyInt_FromLong(RLIMIT_RTPRIO));
	PyModule_AddObject(m, "RLIMIT_RTTIME", PyInt_FromLong(RLIMIT_RTTIME));
	PyModule_AddObject(m, "RLIMIT_NLIMITS", PyInt_FromLong(RLIMIT_NLIMITS));
	/* for getpriority, setpriority */
	PyModule_AddObject(m, "PRIO_PROCESS", PyInt_FromLong(PRIO_PROCESS));
	PyModule_AddObject(m, "PRIO_USER", PyInt_FromLong(PRIO_USER));
	PyModule_AddObject(m, "PRIO_PGRP", PyInt_FromLong(PRIO_PGRP));
	/* linux quote conts */
	PyModule_AddObject(m, "USRQUOTA", PyInt_FromLong(USRQUOTA));
	PyModule_AddObject(m, "GRPQUOTA", PyInt_FromLong(GRPQUOTA));
	PyModule_AddObject(m, "SYNC", PyInt_FromLong(Q_SYNC));
	PyModule_AddObject(m, "QUOTAON", PyInt_FromLong(Q_QUOTAON));
	PyModule_AddObject(m, "QUOTAOFF", PyInt_FromLong(Q_QUOTAOFF));
	PyModule_AddObject(m, "GETFMT", PyInt_FromLong(Q_GETFMT));
	PyModule_AddObject(m, "GETINFO", PyInt_FromLong(Q_GETINFO));
	PyModule_AddObject(m, "SETINFO", PyInt_FromLong(Q_SETINFO));
	PyModule_AddObject(m, "GETQUOTA", PyInt_FromLong(Q_GETQUOTA));
	PyModule_AddObject(m, "SETQUOTA", PyInt_FromLong(Q_SETQUOTA)); 
	/* setxattr contst */
	PyModule_AddObject(m, "XATTR_CREATE", PyInt_FromLong(XATTR_CREATE));
	PyModule_AddObject(m, "XATTR_REPLACE", PyInt_FromLong(XATTR_REPLACE));
	}
}
