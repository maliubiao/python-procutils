import _proc
import os
import sys

PROC_PID_PATH = "/proc/%d/%s"
PROC_PATH = "/proc/%s"
#task_state
TS_RUNNING = 0
TS_SLEEPING = 1
TS_DISK_SLEEP = 2
TS_STOPPED = 4
TS_TRACING_STOP = 8
TS_ZOMBIE = 16
TS_DEAD_1 = 32
TS_DEAD_2 = 64
TS_WAKEKILL = 128
TS_WAKING = 256
TS_PARKED = 512

#page flags
KPF_LOCKED = 0
KPF_ERROR = 1
KPF_REFERENCED = 2
KPF_UPTODATE = 3
KPF_DIRTY = 4
KPF_LRU = 5
KPF_ACTIVE = 6
KPF_SLAB = 7
KPF_WRITEBACK = 8
KPF_RECLAIM = 9
KPF_BUDDY = 10
KPF_MMAP = 11
KPF_ANON = 12
KPF_SWAPCACHE = 13
KPF_SWAPBACKED = 14
KPF_COMPOUND_HEAD = 15
KPF_COMPOUND_TAIL = 16
KPF_HUGE = 17
KPF_UNEVICTABLE = 18
KPF_HWPOISON = 19
KPF_NOPAGE = 20
KPF_KSM = 21
KPF_THP = 22

#SYSCTL Flags
SYSCTL_STRING = 0x1
SYSCTL_INTVEC = 0x1 << 1
SYSCTL_INTVEC_MINMAX = 0x1 << 2
SYSCTL_INTVEC_JIFFIES = 0x1 << 3
SYSCTL_INTVEC_USERHZ_JIFFIES = 0x1 << 4
SYSCTL_INTVEC_MS_JIFFIES = 0x1 << 5
SYSCTL_ULONGVEC_MINMAX =  0x1 << 6
SYSCTL_ULONGVEC_MS_JIFFIES_MIN_MAX = 0x1 << 7
SYSCTL_LARGE_BITMAP = 0x1 << 8
SYSCTL_PORT_RANGE = 0x1 << 9
SYSCTL_STRVEC = 0x1 << 10


task_state = {
        "R": "running",
        "S": "sleeping",
        "D": "disk sleep",
        "T": "stopped",
        "t": "tracing stop",
        "Z": "zombie",
        "X": "dead",
        "x": "dead",
        "K": "wakekill",
        "W": "waking",
        "P": "parked"
        } 

#[(format , False for int, need root or not), ]
PROC_NET_PATH = "/proc/sys/net/%s"
net_known_list_3_11 = [
            ("nf_conntrack_max",
                SYSCTL_INTVEC,
                False),
            ("core/somaxconn",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("core/bpf_jit_enable",
                SYSCTL_INTVEC,
                False),
            ("core/busy_poll",
                SYSCTL_INTVEC,
                False),
            ("core/busy_read",
                SYSCTL_INTVEC,
                False),
            ("core/dev_weight",
                SYSCTL_INTVEC,
                False),
            ("core/flow_limit_cpu_bitmap",
                SYSCTL_LARGE_BITMAP,
                False),
            ("core/flow_limit_table_len",
                SYSCTL_INTVEC,
                False),
            ("core/message_burst",
                SYSCTL_INTVEC,
                False),
            ("core/message_cost",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("core/netdev_budget",
                SYSCTL_INTVEC,
                False),
            ("core/netdev_max_backlog",
                SYSCTL_INTVEC,
                False),
            ("core/netdev_tstamp_prequeue",
                SYSCTL_INTVEC,
                False),
            ("core/optmem_max",
                SYSCTL_INTVEC,
                False),
            ("core/rmem_default",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("core/rmem_max",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("core/rps_sock_flow_entries",
                SYSCTL_INTVEC,
                False),
            ("core/warnings",
                SYSCTL_INTVEC,
                False),
            ("core/wmem_default",
                SYSCTL_INTVEC,
                False),
            ("core/wmem_max",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("core/xfrm_acq_expires",
                SYSCTL_INTVEC,
                False),
            ("core/xfrm_aevent_etime",
                SYSCTL_INTVEC,
                False),
            ("core/xfrm_aevent_rseqth",
                SYSCTL_INTVEC,
                False),
            ("core/xfrm_larval_drop",
                SYSCTL_INTVEC,
                False),
            ("ipv4/cipso_cache_bucket_size",
                SYSCTL_INTVEC,
                False),
            ("ipv4/cipso_cache_enable",
                SYSCTL_INTVEC,
                False),
            ("ipv4/cipso_rbm_optfmt",
                SYSCTL_INTVEC,
                False),
            ("ipv4/cipso_rbm_strictvalid",
                SYSCTL_INTVEC,
                False),
            ("ipv4/icmp_echo_ignore_all",
                SYSCTL_INTVEC,
                False),
            ("ipv4/icmp_echo_ignore_broadcasts",
                SYSCTL_INTVEC,
                False),
            ("ipv4/icmp_errors_use_inbound_ifaddr",
                SYSCTL_INTVEC,
                False),
            ("ipv4/icmp_ignore_bogus_error_responses",
                SYSCTL_INTVEC,
                False),
            ("ipv4/icmp_ratelimit",
                SYSCTL_INTVEC_MS_JIFFIES,
                False),
            ("ipv4/icmp_ratemask",
                SYSCTL_INTVEC_MS_JIFFIES,
                False),
            ("ipv4/igmp_max_memberships",
                SYSCTL_INTVEC,
                False),
            ("ipv4/igmp_max_msf",
                SYSCTL_INTVEC,
                False),
            ("ipv4/inet_peer_maxttl",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("ipv4/inet_peer_minttl",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("ipv4/ip_default_ttl",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/ip_dynaddr",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ip_early_demux",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ip_forward",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ipfrag_high_thresh",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ipfrag_low_thresh",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ipfrag_max_dist",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/ipfrag_secret_interval",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/ipfrag_time",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ip_local_port_range",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ip_local_reserved_ports",
                True,
                False),
            ("ipv4/ip_nonlocal_bind",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ip_no_pmtu_disc",
                SYSCTL_INTVEC,
                False),
            ("ipv4/ping_group_range",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_abort_on_overflow",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_adv_win_scale",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_allowed_congestion_control",
                SYSCTL_STRVEC,
                False),
            ("ipv4/tcp_app_win",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_available_congestion_control",
                SYSCTL_STRVEC,
                False),
            ("ipv4/tcp_base_mss",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_challenge_ack_limit",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_congestion_control",
                SYSCTL_STRVEC,
                False),
            ("ipv4/tcp_dma_copybreak",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_dsack",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_early_retrans",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_ecn",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_fack",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_fastopen",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_fastopen_key",
                SYSCTL_INTVEC,
                True),
            ("ipv4/tcp_fin_timeout",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("ipv4/tcp_frto",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_keepalive_intvl",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("ipv4/tcp_keepalive_probes",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_keepalive_time",
                SYSCTL_INTVEC_JIFFIES,
                False),
            ("ipv4/tcp_limit_output_bytes",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_low_latency",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_max_orphans",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_max_ssthresh",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_max_syn_backlog",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_max_tw_buckets",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_mem",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_moderate_rcvbuf",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_mtu_probing",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_no_metrics_save",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_orphan_retries",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_reordering",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_retrans_collapse",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_retries1",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_retries2",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_rfc1337",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_rmem",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_sack",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_slow_start_after_idle",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_stdurg",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_synack_retries",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_thin_dupack",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_thin_linear_timeouts",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_timestamps",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_tso_win_divisor",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_tw_recycle",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_tw_reuse",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_window_scaling",
                SYSCTL_INTVEC,
                False),
            ("ipv4/tcp_wmem",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/tcp_workaround_signed_windows",
                SYSCTL_INTVEC,
                False),
            ("ipv4/udp_mem",
                SYSCTL_INTVEC,
                False),
            ("ipv4/udp_rmem_min",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/udp_wmem_min",
                SYSCTL_INTVEC_MINMAX,
                False),
            ("ipv4/xfrm4_gc_thresh",
                SYSCTL_INTVEC,
                False),
            ]

INTMAX = 0xffffffff


def _handle_sysctl_string(value, write):
    if not write:
        return value.strip("\n")
    else:
        return value + "\x00"

def _handle_sysctl_intvec(value, write):
    if not write:
        return int(value.strip("\n"))
    else:
        if value > INTMAX:        
            return str(value)
        else:
            raise Exception("%d to big for SYSCTL_INTVEC" % value)

def _handle_sysctl_intvec_minmax(value, write): 
    if not write:
        if "\t" in write:
            return [int(x) for x in value.strip("\n").split("\t")]
        else:
            return [int(x.strip("\n"))]
    else:
        for i in value:
            if i > INTMAX:
                raise Exception("%d to big for SYSCTL_INTVEC_MINMAX" % i)
        return "\t".join([str(x) for x in value])


def read_task_stat(pid):
    f = open(PROC_PID_PATH % (pid, "stat"), "r") 
    stat = f.read().split(" ")
    f.close() 
    statlen = len(stat) 
    i = 3
    while i < statlen:
        stat[i] = int(stat[i])
        i += 1
    _tst = {}
    _tst["pid"] = int(stat[0])    
    _tst["tcomm"] = stat[1] 
    _tst["state"] = task_state[stat[2]]
    _tst["ppid"] = stat[3]
    _tst["pgid"] = stat[4]
    _tst["sid"] = stat[5]
    _tst["tty_nr"] = stat[6]
    _tst["tty_pgrp"] = stat[7]
    _tst["flags"] = stat[8]
    _tst["min_flt"]  = stat[9]
    _tst["cmin_flt"] = stat[10]
    _tst["maj_flt"]  = stat[11]
    _tst["cmaj_flt"]  = stat[12]
    _tst["utime"] = stat[13]
    _tst["stime"] = stat[14]
    _tst["cutime"] = stat[15]
    _tst["cstime"] = stat[16]
    _tst["priority"] = stat[17]
    _tst["nice"] = stat[18]
    _tst["num_threads"] = stat[19]
    _tst["start_time"] = stat[21]
    _tst["vsize"] = stat[22]
    _tst["mm"] = stat[23]
    _tst["rsslim"] = stat[24]
    _tst["start_code"] = stat[25]
    _tst["end_code"] = stat[26]
    _tst["start_stack"] = stat[27]
    _tst["esp"] = stat[28]
    _tst["eip"] = stat[29]
    _tst["pending_sig"] = stat[30]
    _tst["blocked_sig"] = stat[31]
    _tst["sigign_sig"] = stat[32]
    _tst["sigcatch_sig"] = stat[33]
    _tst["wchan"] = stat[34]
    _tst["exit_signal"] = stat[37]
    _tst["task"] = stat[38]
    _tst["rt_priority"] = stat[39]
    _tst["policy"] = stat[40]
    _tst["blkio_ticks"] = stat[41]
    _tst["gtim"] = stat[42]
    _tst["cgtime"] = stat[43]
    _tst["start_data"] = stat[44]
    _tst["end_data"]  = stat[45]
    _tst["start_brk"] = stat[46]
    _tst["arg_start"] = stat[47]
    _tst["arg_end"] = stat[48]
    _tst["env_start"] = stat[49]
    _tst["env_end"] = stat[50]
    _tst["exit_code"] = stat[51]
    return _tst

def read_pid_statm(pid): 
    f = open(PROC_PID_PATH % (pid, "statm"), "r") 
    lines = f.read().split(" ")
    f.close()
    statm_dict = {}
    statm_dict["size"] = int(lines[0])
    statm_dict["resident"] = int(lines[1])
    statm_dict["shared"] = int(lines[2])
    statm_dict["text"] = int(lines[3])
    statm_dict["data"] = int(lines[5])
    return statm_dict        

def read_pid_status(pid):
    f = open(PROC_PID_PATH % (pid, "status"), "r")
    lines = f.readlines()
    f.close()
    status_dict = {}
    for line in lines:
        entry = line.split(":\t")
        status_dict[entry[0]] = entry[1].strip("\n").replace("\t", " ") 
    return status_dict

def read_pid_mountinfo(pid):
    """
    mnt opts:
        nosuid, nodev, noexec, noatime, nodiratime, relatime
    read: ro, rw
    """
    f = open(PROC_PID_PATH % (pid, "mountinfo"), "r")
    lines = f.readlines()
    f.close()
    infos = []
    for line in lines:
        mountinfo_dict = {}
        entry = line.split(" ")
        mountinfo_dict["mnt_id"] = int(entry[0])
        mountinfo_dict["parent_mnt_pid"] = int(entry[1])
        mountinfo_dict["major_s_dev"] = entry[2].split(":")[0]
        mountinfo_dict["minor_s_dev"] = entry[2].split(":")[1]
        mountinfo_dict["root"] = entry[3]
        mountinfo_dict["mnt_path"] = entry[4]
        mountinfo_dict["mnt_opts"] = entry[5][:-1]
        mountinfo_dict["shared"] = int(entry[6].split(":")[-1])
        continue_at = 7
        if entry[7].startswith("master"):
            mountinfo_dict["master"] = int(entry[7].split(":")[-1])
            continue_at = 8
            if entry[8].startswith("propagate"): 
                mountinfo_dict["propagate_from"] = int(entry[8].split(":")[-1])
                continue_at = 9
        if entry[continue_at].startswith("unbindable"):
            mountinfo_dict["unbindable"] = True
            continue_at = 10
        mountinfo_dict["type"] = entry[continue_at+1] 
        mountinfo_dict["devname"] = entry[continue_at+2]
        mountinfo_dict["sb_opts"] = entry[continue_at+3][:-1]
        infos.append(mountinfo_dict)
    return infos
                        
def read_pid_mountstats(pid):
    f = open(PROC_PID_PATH % (pid, "mountstats"), "r")
    lines = f.readlines()
    f.close()
    stats = []
    for line in lines:    
        stat_dict = {}
        entry = line.split(" ")
        device = entry[1] 
        path = entry[4]
        fstype = entry[7][:-1]
        stat_dict[device] = {
                "path": path,
                "fstype": fstype
                }
        stats.append(stat_dict)
    return stats

def read_pid_io_counts(pid):
    f = open(PROC_PID_PATH % (pid, "io"), "r")
    lines = f.readlines()
    f.close()
    counts_dict = {} 
    for line in lines:
        entry = line.split(":")
        counts_dict[entry[0]] = int(entry[1]) 
    return counts_dict

def read_pid_maps(pid):
    f = open(PROC_PID_PATH % (pid, "maps"), "r")
    lines = f.readlines()
    f.close()
    maps = [] 
    for line in lines:
        map_dict = {}
        entry = line.split(" ")
        addrs = entry[0].split("-")
        map_dict["start"] = int(addrs[0], 16)
        map_dict["end"] = int(addrs[1], 16)
        map_dict["permission"] = entry[1]
        map_dict["pageoff"] = int(entry[2], 16)
        devs = entry[3].split(":")
        map_dict["major_devid"] = int(devs[0])
        map_dict["minor_devid"] = int(devs[1])
        map_dict["inode"] = int(entry[4]) 
        map_dict["path"] =  entry[-1][:-1]
        maps.append(map_dict)
    return maps

def read_pid_pagemap(pid, rangelist):
    #addr align: u64
    f = open(PROC_PID_PATH % (pid, "pagemap"), "r") 
    pageinfos = []
    for off in rangelist:
        page_dict = {}
        f.seek(off) 
        num = unpack("<Q", f.read(8))[0]
        #keep bit 63
        page_dict["present"] = num & 0x1
        #keep bit 62
        page_dict["swapped"] = num & 0x2 
        #keep bit 61
        page_dict["filepage"] = num & 0x4 
        #keep bit 55 
        page_dict["pte"] = num & 0x100 
        if num & 0x2:
            #keep bits 0-4
            page_dict["swap_type"] = num & 0xf000000000000000 
            #keep bits 5-54
            page_dict["swap_offset"] = num & 0xffffffffffffe00            
        if present:
            #keep bits 0-54
            page_dict["pfn"] = num & 0xfffffffffffffe00            
        pageinfos.append(page_dict)         
    f.close()
    return pageinfos

def read_pid_pagesinfo(pid, rangelist): 
    fcount = open(PROC_PATH % "kpagecount", "r")
    fflags = open(PROC_PATH % "kpageflags", "r")
    pageinfos = read_pid_pagemap(pid, rangelist)
    for pageinfo in pageinfos:
        if "pfn" not in pageinfo:
            continue
        fcount.seek(pageinfo["pfn"])
        pageinfo["count"] = unpack("<Q", fcount.read(8))[0]
        fflags.seek(pageinfos["pfn"])
        pageinfo["flags"] = unpack("<Q", fflags.read(8))[0] 
    return pageinfos

def read_api_file(hit, perm=False): 
    if not hit[2]: 
        f = open(PROC_NET_PATH % hit[0], "r") 
        if not hit[1]: 
            data = int(f.read()[:-1]) 
        else:
            data = f.read()[:-1] 
        return data
    else:
        if not perm:
            return -1 
        f = open(PROC_NET_PATH % hit[0], "r") 
        if not hit[1]:
            data = int(f.read()[:-1])
        else:
            data = f.read()[:-1] 
        f.close()
        return data

def write_api_file(value, hit, perm=False):
    if not hit[2]:
        f = open(PROC_NET_PATH % hit[0], "r")
        f.truncate(0)
        if not hit[1]: 
            f.write(int(value))
        else:
            f.write(value) 
    else:        
        if not perm: 
            return -1
        f = open(PROC_NET_PATH % hit[0], "r")
        f.truncate(0)
        if not hit[1]:
            f.write(int(value))
        else:
            f.write(value)
        f.close()

def read_sys_net(keylist = None, perm=False):
    net_dict = {}
    if keylist:
        for key in keylist:
            hit = None                       
            for known in net_known_list_3_11:
                if key in known:
                    hit = known
            if hit:
                value = read_api_file(hit)
                if isinstance(value, str):
                    net_dict[key] = value.replace("\t", "\x20")
                else:
                    net_dict[key] = value
    else:        
        for known in net_known_list_3_11:
            value = read_api_file(known, perm) 
            if isinstance(value, str):
                net_dict[known[0]] = value.replace("\t", "\x20")
            else:
                net_dict[known[0]] = value
    return net_dict

def write_sys_net(net_dict, perm=False): 
    for key in net_dict: 
        hit = None
        for known in net_known_list_3_11:
            if key in known:
                hit = known
        if hit:            
            write_api_file(net_dict[key], hit, perm) 

#tests
#print read_task_stat("/proc/%s/stat" % sys.argv[1])
#print read_sys_net()
#print read_pid_mountinfo(os.getppid())
#print read_pid_mountstats(os.getppid())
#print read_pid_maps(os.getppid())
#print read_pid_io_counts(os.getppid())
#print read_pid_statm(os.getppid())
