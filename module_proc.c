#include <Python.h>
#include <unistd.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
//#include <linux/getcpu.h> 
#include <sys/syscall.h>

extern PyObject *get_cpu_brand();

PyDoc_STRVAR(proc_getrusage_doc, "call getrusage");

static PyObject *
proc_getrusage(PyObject *object, PyObject *args)
{
	struct rusage usage;		
	PyObject *ru_utime_tuple;
	PyObject *ru_stime_tuple;
	PyObject *usage_dict;
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		Py_RETURN_NONE;
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
		Py_RETURN_NONE;
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
		Py_RETURN_FALSE;
	}
	Py_RETURN_TRUE; 
}

PyDoc_STRVAR(proc_getcpu_doc, "syscall getcpu, return tuple (cpu, numanode), or None if failed");

static PyObject *
proc_getcpu(PyObject *object, PyObject *args)
{
	unsigned cpu;
	unsigned node;
	/*ignored since 2.6.24*/ 
	if (syscall(SYS_getcpu, &cpu, &node, NULL) < 0) {
		Py_RETURN_NONE;	
	}
	return PyTuple_Pack(2, PyInt_FromLong((signed long)(cpu)), PyInt_FromLong((signed long)(node)));
}


PyDoc_STRVAR(proc_sched_setaffinity_doc, "call sched_setaffinity");

static PyObject *
proc_sched_setaffinity(PyObject *object, PyObject *args)
{
	int pid;
	int size;
	PyObject *set_list;
	cpu_set_t set;
	int i; 
	if(!PyArg_ParseTuple(args, "IO:sched_setaffinity", &pid, &set_list)) {
		return NULL;
	}
	if (!PyTuple_Check(set_list)) {
		Py_RETURN_NONE;
	} 
	CPU_ZERO(&set);	
	size = PyTuple_Size(set_list);
	
	for (i=0; i < size; i++) {
		CPU_SET(PyInt_AsLong(PyTuple_GetItem(set_list, i)), &set);
	}
	if (sched_setaffinity(pid, sizeof(set), &set) < 0) { 
		goto ERROR;

	} 
	Py_RETURN_TRUE;
ERROR: 
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
		goto ERROR; 
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
ERROR: 
	Py_RETURN_NONE;		
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
		Py_RETURN_NONE;
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
		Py_RETURN_NONE;
	}
	Py_RETURN_TRUE;
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
	}
}
