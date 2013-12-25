python-procutils
================

interface to access fs/proc,  kernel scheduler, os environment
##build
```shell
#yasm -f elf64 cpuid.asm 
#gcc -o_proc.o -c module_proc.c  -shared -fPIC $(/usr/bin/python2.7-config --libs --includes --cflags)
#gcc -o_proc.so _proc.o cpuid.o -shared $(/usr/bin/python2.7-config --libs --includes --cflags)
##Demo
```shell

>>> pprint.pprint(proc.read_task_stat(os.getpid())
... )
{'arg_end': 140734885481808,
 'arg_start': 140734885481801,
 'blkio_ticks': 20,
 'blocked_sig': 0,
 'cgtime': 0,
 'cmaj_flt': 0,
 'cmin_flt': 0,
 'cstime': 0,
 'cutime': 0,
 'eip': 140488407889360,
 'end_code': 4196868,
 'end_data': 6295616,
 'env_end': 140734885486568,
 'env_start': 140734885481808,
 'esp': 140734885475368,
 'exit_code': 0,
 'exit_signal': 17,
 'flags': 4202496,
 'gtim': 0,
 'maj_flt': 2,
 'min_flt': 2144,
 'mm': 1690,
 'nice': 0,
 'num_threads': 1,
 'pending_sig': 0,
 'pgid': 2720,
 'pid': 2720,
 'policy': 0,
 'ppid': 2697,
 'priority': 20,
 'rsslim': 18446744073709551615L,
 'rt_priority': 0,
 'sid': 2697,
 'sigcatch_sig': 2,
 'sigign_sig': 16781312,
 'start_brk': 26923008,
 'start_code': 4194304,
 'start_data': 6295008,
 'start_stack': 140734885476912,
 'start_time': 607214,
 'state': 'running',
 'stime': 7,
 'task': 0,
 'tcomm': '(python)',
 'tty_nr': 34821,
 'tty_pgrp': 2720,
 'utime': 12,
 'vsize': 33071104,
 'wchan': 0}
```
```shell 
>>> pprint.pprint(proc.read_pid_statm(os.getpid()))
{'data': 1086, 'resident': 1696, 'shared': 562, 'size': 8074, 'text': 1}
```
```shell

>>> pprint.pprint(proc.read_pid_status(os.getpid()))
{'CapBnd': '0000001fffffffff',
 'CapEff': '0000000000000000',
 'CapInh': '0000000000000000',
 'CapPrm': '0000000000000000',
 'Cpus_allowed': 'ff',
 'Cpus_allowed_list': '0-7',
 'FDSize': '256',
 'Gid': '100 100 100 100',
 'Groups': '100 488 ',
 'Mems_allowed': '00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001',
 'Mems_allowed_list': '0',
 'Name': 'python',
 'PPid': '2697',
 'Pid': '2720',
 'Seccomp': '0',
 'ShdPnd': '0000000000000000',
 'SigBlk': '0000000000000000',
 'SigCgt': '0000000180000002',
 'SigIgn': '0000000001001000',
 'SigPnd': '0000000000000000',
 'SigQ': '0/63111',
 'State': 'R (running)',
 'Tgid': '2720',
 'Threads': '1',
 'TracerPid': '0',
 'Uid': '1001 1001 1001 1001',
 'VmData': '    4708 kB',
 'VmExe': '       4 kB',
 'VmHWM': '    7376 kB',
 'VmLck': '       0 kB',
 'VmLib': '    4748 kB',
 'VmPTE': '      88 kB',
 'VmPeak': '   32804 kB',
 'VmPin': '       0 kB',
 'VmRSS': '    7372 kB',
 'VmSize': '   32800 kB',
 'VmStk': '     140 kB',
 'VmSwap': '       0 kB',
 'nonvoluntary_ctxt_switches': '39',
 'voluntary_ctxt_switches': '953'}
```
```shell

>>> pprint.pprint(proc.read_pid_mountinfo(os.getpid()))
[{'devname': 'devtmpfs',
  'major_s_dev': '0',
  'minor_s_dev': '5',
  'mnt_id': 17,
  'mnt_opts': 'rw,relatim',
  'mnt_path': '/dev',
  'parent_mnt_pid': 21,
  'root': '/',
  'sb_opts': 'rw,size=4039144k,nr_inodes=1009786,mode=755',
  'shared': 2,
  'type': 'devtmpfs'},
 {'devname': 'tmpfs',
  'major_s_dev': '0',
  'minor_s_dev': '15',
  'mnt_id': 18,
  'mnt_opts': 'rw,relatim',
  'mnt_path': '/dev/shm',
  'parent_mnt_pid': 17,
  'root': '/',
  'sb_opts': 'rw',
  'shared': 3,
  'type': 'tmpfs'},
...  
```
```shell 
>>> pprint.pprint(proc.read_pid_mountstats(os.getpid()))
[{'rootfs': {'fstype': 'rootfs', 'path': '/'}},
 {'devtmpfs': {'fstype': 'devtmpfs', 'path': '/dev'}},
 {'tmpfs': {'fstype': 'tmpfs', 'path': '/dev/shm'}},
 {'tmpfs': {'fstype': 'tmpfs', 'path': '/run'}},
 {'devpts': {'fstype': 'devpts', 'path': '/dev/pts'}},
 {'/dev/sda1': {'fstype': 'ext4', 'path': '/'}},
 {'proc': {'fstype': 'proc', 'path': '/proc'}},
 {'sysfs': {'fstype': 'sysfs', 'path': '/sys'}},
 {'securityfs': {'fstype': 'securityfs', 'path': '/sys/kernel/security'}},
 {'tmpfs': {'fstype': 'tmpfs', 'path': '/sys/fs/cgroup'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/systemd'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/cpuset'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/cpu,cpuacct'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/memory'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/devices'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/freezer'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/net_cls'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/blkio'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/perf_event'}},
 {'cgroup': {'fstype': 'cgroup', 'path': '/sys/fs/cgroup/hugetlb'}},
 {'systemd-1': {'fstype': 'autofs', 'path': '/proc/sys/fs/binfmt_misc'}},
 {'hugetlbfs': {'fstype': 'hugetlbfs', 'path': '/dev/hugepages'}},
 {'mqueue': {'fstype': 'mqueue', 'path': '/dev/mqueue'}},
 {'tmpfs': {'fstype': 'tmpfs', 'path': '/var/run'}},
 {'debugfs': {'fstype': 'debugfs', 'path': '/sys/kernel/debug'}},
 {'tmpfs': {'fstype': 'tmpfs', 'path': '/var/lock'}},
 {'/dev/sda5': {'fstype': 'ext4', 'path': '/home'}},
 {'/dev/sda3': {'fstype': 'ext4', 'path': '/data'}},
 {'fusectl': {'fstype': 'fusectl', 'path': '/sys/fs/fuse/connections'}}, 
 {'none': {'fstype': 'proc', 'path': '/var/lib/ntp/proc'}},
 {'gvfsd-fuse': {'fstype': 'fuse.gvfsd-fuse', 'path': '/run/user/1001/gvfs'}},
 {'gvfsd-fuse': {'fstype': 'fuse.gvfsd-fuse',
                 'path': '/var/run/user/1001/gvfs'}}]
```
```shell

>>> pprint.pprint(proc.read_pid_io_counts(os.getpid()))
{'cancelled_write_bytes': 0,
 'rchar': 508717,
 'read_bytes': 131072,
 'syscr': 2388,
 'syscw': 1757,
 'wchar': 85630,
 'write_bytes': 49152}
```
```shell

>>> pprint.pprint(proc.read_pid_maps(os.getpid()))
...
{'end': 140488388579328,
  'inode': 1988073,
  'major_devid': 8,
  'minor_devid': 1,
  'pageoff': 0,
  'path': '/usr/lib64/python2.7/lib-dynload/cStringIO.so',
  'permission': 'r-xp',
  'start': 140488388562944},
 {'end': 140488390672384,
  'inode': 1988073,
  'major_devid': 8,
  'minor_devid': 1,
  'pageoff': 16384,
  'path': '/usr/lib64/python2.7/lib-dynload/cStringIO.so',
  'permission': '---p',
  'start': 140488388579328},
 {'end': 140488390676480,
  'inode': 1988073,
  'major_devid': 8,
  'minor_devid': 1,
  'pageoff': 12288,
  'path': '/usr/lib64/python2.7/lib-dynload/cStringIO.so',
  'permission': 'r--p',
  'start': 140488390672384} 
...
```
```shell

>>> pprint.pprint(proc.read_sys_net())
{'core/bpf_jit_enable': 0,
 'core/busy_poll': 0,
 'core/busy_read': 0,
 'core/dev_weight': 64,
 'core/flow_limit_cpu_bitmap': '00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,',
 'core/flow_limit_table_len': 4096,
 'core/message_burst': 10,
 'core/message_cost': 5,
 'core/netdev_budget': 300,
 'core/netdev_max_backlog': 2000000,
 'core/netdev_tstamp_prequeue': 1,
 'core/optmem_max': 20480,
 'core/rmem_default': 212992,
...
```

