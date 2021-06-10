/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** syscall_names
*/

#ifndef SYSCALL_NAMES_H_
# define SYSCALL_NAMES_H_

static syscall_t syscalls[] = {
    [0] = {
        .type = INTEGER,
        .name = "read",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [1] = {
        .type = INTEGER,
        .name = "write",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [2] = {
        .type = INTEGER,
        .name = "open",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [3] = {
        .type = INTEGER,
        .name = "close",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [4] = {
        .type = INTEGER,
        .name = "stat",
        .types = {STRING, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [5] = {
        .type = INTEGER,
        .name = "fstat",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [6] = {
        .type = INTEGER,
        .name = "lstat",
        .types = {STRING, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [7] = {
        .type = INTEGER,
        .name = "poll",
        .types = {OTHER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [8] = {
        .type = INTEGER,
        .name = "lseek",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [9] = {
        .type = OTHER,
        .name = "mmap",
        .types = {OTHER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER},
    },
    [10] = {
        .type = INTEGER,
        .name = "mprotect",
        .types = {OTHER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [11] = {
        .type = INTEGER,
        .name = "munmap",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [12] = {
        .type = INTEGER,
        .name = "brk",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [13] = {
        .type = INTEGER,
        .name = "rt_sigaction",
        .types = {INTEGER, OTHER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [14] = {
        .type = INTEGER,
        .name = "rt_sigprocmask",
        .types = {INTEGER, OTHER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [15] = {
        .type = INTEGER,
        .name = "rt_sigreturn",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [16] = {
        .type = INTEGER,
        .name = "ioctl",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [17] = {
        .type = INTEGER,
        .name = "pread64",
        .types = {INTEGER, STRING, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [18] = {
        .type = INTEGER,
        .name = "pwrite64",
        .types = {INTEGER, STRING, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [19] = {
        .type = INTEGER,
        .name = "readv",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [20] = {
        .type = INTEGER,
        .name = "writev",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [21] = {
        .type = INTEGER,
        .name = "access",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [22] = {
        .type = INTEGER,
        .name = "pipe",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [23] = {
        .type = INTEGER,
        .name = "select",
        .types = {INTEGER, OTHER, OTHER, OTHER, OTHER, UNDEF},
    },
    [24] = {
        .type = INTEGER,
        .name = "sched_yield",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [25] = {
        .type = INTEGER,
        .name = "mremap",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [26] = {
        .type = INTEGER,
        .name = "msync",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [27] = {
        .type = INTEGER,
        .name = "mincore",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [28] = {
        .type = INTEGER,
        .name = "madvise",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [29] = {
        .type = INTEGER,
        .name = "shmget",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [30] = {
        .type = INTEGER,
        .name = "shmat",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [31] = {
        .type = INTEGER,
        .name = "shmctl",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [32] = {
        .type = INTEGER,
        .name = "dup",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [33] = {
        .type = INTEGER,
        .name = "dup2",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [34] = {
        .type = INTEGER,
        .name = "pause",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [35] = {
        .type = INTEGER,
        .name = "nanosleep",
        .types = {OTHER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [36] = {
        .type = INTEGER,
        .name = "getitimer",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [37] = {
        .type = INTEGER,
        .name = "alarm",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [38] = {
        .type = INTEGER,
        .name = "setitimer",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [39] = {
        .type = INTEGER,
        .name = "getpid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [40] = {
        .type = INTEGER,
        .name = "sendfile",
        .types = {INTEGER, INTEGER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [41] = {
        .type = INTEGER,
        .name = "socket",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [42] = {
        .type = INTEGER,
        .name = "connect",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [43] = {
        .type = INTEGER,
        .name = "accept",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [44] = {
        .type = INTEGER,
        .name = "sendto",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, OTHER, INTEGER},
    },
    [45] = {
        .type = INTEGER,
        .name = "recvfrom",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, OTHER, OTHER},
    },
    [46] = {
        .type = INTEGER,
        .name = "sendmsg",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [47] = {
        .type = INTEGER,
        .name = "recvmsg",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [48] = {
        .type = INTEGER,
        .name = "shutdown",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [49] = {
        .type = INTEGER,
        .name = "bind",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [50] = {
        .type = INTEGER,
        .name = "listen",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [51] = {
        .type = INTEGER,
        .name = "getsockname",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [52] = {
        .type = INTEGER,
        .name = "getpeername",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [53] = {
        .type = INTEGER,
        .name = "socketpair",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [54] = {
        .type = INTEGER,
        .name = "setsockopt",
        .types = {INTEGER, INTEGER, INTEGER, STRING, INTEGER, UNDEF},
    },
    [55] = {
        .type = INTEGER,
        .name = "getsockopt",
        .types = {INTEGER, INTEGER, INTEGER, STRING, OTHER, UNDEF},
    },
    [56] = {
        .type = INTEGER,
        .name = "clone",
        .types = {INTEGER, INTEGER, OTHER, OTHER, INTEGER, UNDEF},
    },
    [57] = {
        .type = INTEGER,
        .name = "fork",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [58] = {
        .type = INTEGER,
        .name = "vfork",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [59] = {
        .type = INTEGER,
        .name = "execve",
        .types = {STRING, STRING, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [60] = {
        .type = INTEGER,
        .name = "exit",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [61] = {
        .type = INTEGER,
        .name = "wait4",
        .types = {INTEGER, OTHER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [62] = {
        .type = INTEGER,
        .name = "kill",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [63] = {
        .type = INTEGER,
        .name = "uname",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [64] = {
        .type = INTEGER,
        .name = "semget",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [65] = {
        .type = INTEGER,
        .name = "semop",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [66] = {
        .type = INTEGER,
        .name = "semctl",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [67] = {
        .type = INTEGER,
        .name = "shmdt",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [68] = {
        .type = INTEGER,
        .name = "msgget",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [69] = {
        .type = INTEGER,
        .name = "msgsnd",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [70] = {
        .type = INTEGER,
        .name = "msgrcv",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [71] = {
        .type = INTEGER,
        .name = "msgctl",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [72] = {
        .type = INTEGER,
        .name = "fcntl",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [73] = {
        .type = INTEGER,
        .name = "flock",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [74] = {
        .type = INTEGER,
        .name = "fsync",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [75] = {
        .type = INTEGER,
        .name = "fdatasync",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [76] = {
        .type = INTEGER,
        .name = "truncate",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [77] = {
        .type = INTEGER,
        .name = "ftruncate",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [78] = {
        .type = INTEGER,
        .name = "getdents",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [79] = {
        .type = INTEGER,
        .name = "getcwd",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [80] = {
        .type = INTEGER,
        .name = "chdir",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [81] = {
        .type = INTEGER,
        .name = "fchdir",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [82] = {
        .type = INTEGER,
        .name = "rename",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [83] = {
        .type = INTEGER,
        .name = "mkdir",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [84] = {
        .type = INTEGER,
        .name = "rmdir",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [85] = {
        .type = INTEGER,
        .name = "creat",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [86] = {
        .type = INTEGER,
        .name = "link",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [87] = {
        .type = INTEGER,
        .name = "unlink",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [88] = {
        .type = INTEGER,
        .name = "symlink",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [89] = {
        .type = INTEGER,
        .name = "readlink",
        .types = {STRING, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [90] = {
        .type = INTEGER,
        .name = "chmod",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [91] = {
        .type = INTEGER,
        .name = "fchmod",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [92] = {
        .type = INTEGER,
        .name = "chown",
        .types = {STRING, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [93] = {
        .type = INTEGER,
        .name = "fchown",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [94] = {
        .type = INTEGER,
        .name = "lchown",
        .types = {STRING, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [95] = {
        .type = INTEGER,
        .name = "umask",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [96] = {
        .type = INTEGER,
        .name = "gettimeofday",
        .types = {OTHER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [97] = {
        .type = INTEGER,
        .name = "getrlimit",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [98] = {
        .type = INTEGER,
        .name = "getrusage",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [99] = {
        .type = INTEGER,
        .name = "sysinfo",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [100] = {
        .type = INTEGER,
        .name = "times",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [101] = {
        .type = INTEGER,
        .name = "ptrace",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [102] = {
        .type = INTEGER,
        .name = "getuid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [103] = {
        .type = INTEGER,
        .name = "syslog",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [104] = {
        .type = INTEGER,
        .name = "getgid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [105] = {
        .type = INTEGER,
        .name = "setuid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [106] = {
        .type = INTEGER,
        .name = "setgid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [107] = {
        .type = INTEGER,
        .name = "geteuid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [108] = {
        .type = INTEGER,
        .name = "getegid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [109] = {
        .type = INTEGER,
        .name = "setpgid",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [110] = {
        .type = INTEGER,
        .name = "getppid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [111] = {
        .type = INTEGER,
        .name = "getpgrp",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [112] = {
        .type = INTEGER,
        .name = "setsid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [113] = {
        .type = INTEGER,
        .name = "setreuid",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [114] = {
        .type = INTEGER,
        .name = "setregid",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [115] = {
        .type = INTEGER,
        .name = "getgroups",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [116] = {
        .type = INTEGER,
        .name = "setgroups",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [117] = {
        .type = INTEGER,
        .name = "setresuid",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [118] = {
        .type = INTEGER,
        .name = "getresuid",
        .types = {OTHER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [119] = {
        .type = INTEGER,
        .name = "setresgid",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [120] = {
        .type = INTEGER,
        .name = "getresgid",
        .types = {OTHER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [121] = {
        .type = INTEGER,
        .name = "getpgid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [122] = {
        .type = INTEGER,
        .name = "setfsuid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [123] = {
        .type = INTEGER,
        .name = "setfsgid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [124] = {
        .type = INTEGER,
        .name = "getsid",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [125] = {
        .type = INTEGER,
        .name = "capget",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [126] = {
        .type = INTEGER,
        .name = "capset",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [127] = {
        .type = INTEGER,
        .name = "rt_sigpending",
        .types = {OTHER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [128] = {
        .type = INTEGER,
        .name = "rt_sigtimedwait",
        .types = {OTHER, OTHER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [129] = {
        .type = INTEGER,
        .name = "rt_sigqueueinfo",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [130] = {
        .type = INTEGER,
        .name = "rt_sigsuspend",
        .types = {OTHER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [131] = {
        .type = INTEGER,
        .name = "sigaltstack",
        .types = {OTHER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [132] = {
        .type = INTEGER,
        .name = "utime",
        .types = {STRING, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [133] = {
        .type = INTEGER,
        .name = "mknod",
        .types = {STRING, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [134] = {
        .type = INTEGER,
        .name = "uselib",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [135] = {
        .type = INTEGER,
        .name = "personality",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [136] = {
        .type = INTEGER,
        .name = "ustat",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [137] = {
        .type = INTEGER,
        .name = "statfs",
        .types = {STRING, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [138] = {
        .type = INTEGER,
        .name = "fstatfs",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [139] = {
        .type = INTEGER,
        .name = "sysfs",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [140] = {
        .type = INTEGER,
        .name = "getpriority",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [141] = {
        .type = INTEGER,
        .name = "setpriority",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [142] = {
        .type = INTEGER,
        .name = "sched_setparam",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [143] = {
        .type = INTEGER,
        .name = "sched_getparam",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [144] = {
        .type = INTEGER,
        .name = "sched_setscheduler",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [145] = {
        .type = INTEGER,
        .name = "sched_getscheduler",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [146] = {
        .type = INTEGER,
        .name = "sched_get_priority_max",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [147] = {
        .type = INTEGER,
        .name = "sched_get_priority_min",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [148] = {
        .type = INTEGER,
        .name = "sched_rr_get_INTEGERerval",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [149] = {
        .type = INTEGER,
        .name = "mlock",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [150] = {
        .type = INTEGER,
        .name = "munlock",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [151] = {
        .type = INTEGER,
        .name = "mlockall",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [152] = {
        .type = INTEGER,
        .name = "munlockall",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [153] = {
        .type = INTEGER,
        .name = "vhangup",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [154] = {
        .type = INTEGER,
        .name = "modify_ldt",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [155] = {
        .type = INTEGER,
        .name = "pivot_root",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [156] = {
        .type = INTEGER,
        .name = "_sysctl",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [157] = {
        .type = INTEGER,
        .name = "prctl",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [158] = {
        .type = INTEGER,
        .name = "arch_prctl",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [159] = {
        .type = INTEGER,
        .name = "adjtimex",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [160] = {
        .type = INTEGER,
        .name = "setrlimit",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [161] = {
        .type = INTEGER,
        .name = "chroot",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [162] = {
        .type = VOID,
        .name = "sync",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [163] = {
        .type = INTEGER,
        .name = "acct",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [164] = {
        .type = INTEGER,
        .name = "settimeofday",
        .types = {OTHER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [165] = {
        .type = INTEGER,
        .name = "mount",
        .types = {STRING, STRING, STRING, INTEGER, OTHER, UNDEF},
    },
    [166] = {
        .type = INTEGER,
        .name = "umount2",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [167] = {
        .type = INTEGER,
        .name = "swapon",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [168] = {
        .type = INTEGER,
        .name = "swapoff",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [169] = {
        .type = INTEGER,
        .name = "reboot",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [170] = {
        .type = INTEGER,
        .name = "sethostname",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [171] = {
        .type = INTEGER,
        .name = "setdomainname",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [172] = {
        .type = INTEGER,
        .name = "iopl",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [173] = {
        .type = INTEGER,
        .name = "ioperm",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [174] = {
        .type = INTEGER,
        .name = "create_module",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [175] = {
        .type = INTEGER,
        .name = "init_module",
        .types = {OTHER, INTEGER, STRING, UNDEF, UNDEF, UNDEF},
    },
    [176] = {
        .type = INTEGER,
        .name = "delete_module",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [177] = {
        .type = INTEGER,
        .name = "get_kernel_syms",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [178] = {
        .type = INTEGER,
        .name = "query_module",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [179] = {
        .type = INTEGER,
        .name = "quotactl",
        .types = {INTEGER, STRING, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [180] = {
        .type = INTEGER,
        .name = "nfsservctl",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [181] = {
        .type = INTEGER,
        .name = "getpmsg",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [182] = {
        .type = INTEGER,
        .name = "putpmsg",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [183] = {
        .type = INTEGER,
        .name = "afs_syscall",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [184] = {
        .type = INTEGER,
        .name = "tuxcall",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [185] = {
        .type = INTEGER,
        .name = "security",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [186] = {
        .type = INTEGER,
        .name = "gettid",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [187] = {
        .type = INTEGER,
        .name = "readahead",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [188] = {
        .type = INTEGER,
        .name = "setxattr",
        .types = {STRING, STRING, OTHER, INTEGER, INTEGER, UNDEF},
    },
    [189] = {
        .type = INTEGER,
        .name = "lsetxattr",
        .types = {STRING, STRING, OTHER, INTEGER, INTEGER, UNDEF},
    },
    [190] = {
        .type = INTEGER,
        .name = "fsetxattr",
        .types = {INTEGER, STRING, OTHER, INTEGER, INTEGER, UNDEF},
    },
    [191] = {
        .type = INTEGER,
        .name = "getxattr",
        .types = {STRING, STRING, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [192] = {
        .type = INTEGER,
        .name = "lgetxattr",
        .types = {STRING, STRING, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [193] = {
        .type = INTEGER,
        .name = "fgetxattr",
        .types = {INTEGER, STRING, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [194] = {
        .type = INTEGER,
        .name = "listxattr",
        .types = {STRING, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [195] = {
        .type = INTEGER,
        .name = "llistxattr",
        .types = {STRING, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [196] = {
        .type = INTEGER,
        .name = "flistxattr",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [197] = {
        .type = INTEGER,
        .name = "removexattr",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [198] = {
        .type = INTEGER,
        .name = "lremovexattr",
        .types = {STRING, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [199] = {
        .type = INTEGER,
        .name = "fremovexattr",
        .types = {INTEGER, STRING, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [200] = {
        .type = INTEGER,
        .name = "tkill",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [201] = {
        .type = INTEGER,
        .name = "time",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [202] = {
        .type = INTEGER,
        .name = "futex",
        .types = {OTHER, INTEGER, INTEGER, OTHER, OTHER, INTEGER},
    },
    [203] = {
        .type = INTEGER,
        .name = "sched_setaffinity",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [204] = {
        .type = INTEGER,
        .name = "sched_getaffinity",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [205] = {
        .type = INTEGER,
        .name = "set_thread_area",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [206] = {
        .type = INTEGER,
        .name = "io_setup",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [207] = {
        .type = INTEGER,
        .name = "io_deSTRINGoy",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [208] = {
        .type = INTEGER,
        .name = "io_getevents",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, OTHER, UNDEF},
    },
    [209] = {
        .type = INTEGER,
        .name = "io_submit",
        .types = {INTEGER, INTEGER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [210] = {
        .type = INTEGER,
        .name = "io_cancel",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [211] = {
        .type = INTEGER,
        .name = "get_thread_area",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [212] = {
        .type = INTEGER,
        .name = "lookup_dcookie",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [213] = {
        .type = INTEGER,
        .name = "epoll_create",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [214] = {
        .type = INTEGER,
        .name = "epoll_ctl_old",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [215] = {
        .type = INTEGER,
        .name = "epoll_wait_old",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [216] = {
        .type = INTEGER,
        .name = "remap_file_pages",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [217] = {
        .type = INTEGER,
        .name = "getdents64",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [218] = {
        .type = INTEGER,
        .name = "set_tid_address",
        .types = {OTHER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [219] = {
        .type = INTEGER,
        .name = "restart_syscall",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [220] = {
        .type = INTEGER,
        .name = "semtimedop",
        .types = {INTEGER, OTHER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [221] = {
        .type = INTEGER,
        .name = "fadvise64",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [222] = {
        .type = INTEGER,
        .name = "timer_create",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [223] = {
        .type = INTEGER,
        .name = "timer_settime",
        .types = {INTEGER, INTEGER, OTHER, OTHER, UNDEF, UNDEF},
    },
    [224] = {
        .type = INTEGER,
        .name = "timer_gettime",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [225] = {
        .type = INTEGER,
        .name = "timer_getoverrun",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [226] = {
        .type = INTEGER,
        .name = "timer_delete",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [227] = {
        .type = INTEGER,
        .name = "clock_settime",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [228] = {
        .type = INTEGER,
        .name = "clock_gettime",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [229] = {
        .type = INTEGER,
        .name = "clock_getres",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [230] = {
        .type = INTEGER,
        .name = "clock_nanosleep",
        .types = {INTEGER, INTEGER, OTHER, OTHER, UNDEF, UNDEF},
    },
    [231] = {
        .type = VOID,
        .name = "exit_group",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [232] = {
        .type = INTEGER,
        .name = "epoll_wait",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [233] = {
        .type = INTEGER,
        .name = "epoll_ctl",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [234] = {
        .type = INTEGER,
        .name = "tgkill",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [235] = {
        .type = INTEGER,
        .name = "utimes",
        .types = {STRING, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [236] = {
        .type = INTEGER,
        .name = "vserver",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [237] = {
        .type = INTEGER,
        .name = "mbind",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, INTEGER, INTEGER},
    },
    [238] = {
        .type = INTEGER,
        .name = "set_mempolicy",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [239] = {
        .type = INTEGER,
        .name = "get_mempolicy",
        .types = {OTHER, OTHER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [240] = {
        .type = INTEGER,
        .name = "mq_open",
        .types = {STRING, INTEGER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [241] = {
        .type = INTEGER,
        .name = "mq_unlink",
        .types = {STRING, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [242] = {
        .type = INTEGER,
        .name = "mq_timedsend",
        .types = {INTEGER, STRING, INTEGER, INTEGER, OTHER, UNDEF},
    },
    [243] = {
        .type = INTEGER,
        .name = "mq_timedreceive",
        .types = {INTEGER, STRING, INTEGER, OTHER, OTHER, UNDEF},
    },
    [244] = {
        .type = INTEGER,
        .name = "mq_notify",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [245] = {
        .type = INTEGER,
        .name = "mq_getsetattr",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [246] = {
        .type = INTEGER,
        .name = "kexec_load",
        .types = {INTEGER, INTEGER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [247] = {
        .type = INTEGER,
        .name = "waitid",
        .types = {INTEGER, INTEGER, OTHER, INTEGER, OTHER, UNDEF},
    },
    [248] = {
        .type = INTEGER,
        .name = "add_key",
        .types = {STRING, STRING, OTHER, INTEGER, INTEGER, UNDEF},
    },
    [249] = {
        .type = INTEGER,
        .name = "request_key",
        .types = {STRING, STRING, STRING, INTEGER, UNDEF, UNDEF},
    },
    [250] = {
        .type = INTEGER,
        .name = "keyctl",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [251] = {
        .type = INTEGER,
        .name = "ioprio_set",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [252] = {
        .type = INTEGER,
        .name = "ioprio_get",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [253] = {
        .type = INTEGER,
        .name = "inotify_init",
        .types = {UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [254] = {
        .type = INTEGER,
        .name = "inotify_add_watch",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [255] = {
        .type = INTEGER,
        .name = "inotify_rm_watch",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [256] = {
        .type = INTEGER,
        .name = "migrate_pages",
        .types = {INTEGER, INTEGER, OTHER, OTHER, UNDEF, UNDEF},
    },
    [257] = {
        .type = INTEGER,
        .name = "openat",
        .types = {INTEGER, STRING, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [258] = {
        .type = INTEGER,
        .name = "mkdirat",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [259] = {
        .type = INTEGER,
        .name = "mknodat",
        .types = {INTEGER, STRING, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [260] = {
        .type = INTEGER,
        .name = "fchownat",
        .types = {INTEGER, STRING, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [261] = {
        .type = INTEGER,
        .name = "futimesat",
        .types = {INTEGER, STRING, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [262] = {
        .type = INTEGER,
        .name = "newfstatat",
        .types = {INTEGER, STRING, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [263] = {
        .type = INTEGER,
        .name = "unlinkat",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [264] = {
        .type = INTEGER,
        .name = "renameat",
        .types = {INTEGER, STRING, INTEGER, STRING, UNDEF, UNDEF},
    },
    [265] = {
        .type = INTEGER,
        .name = "linkat",
        .types = {INTEGER, STRING, INTEGER, STRING, INTEGER, UNDEF},
    },
    [266] = {
        .type = INTEGER,
        .name = "symlinkat",
        .types = {STRING, INTEGER, STRING, UNDEF, UNDEF, UNDEF},
    },
    [267] = {
        .type = INTEGER,
        .name = "readlinkat",
        .types = {INTEGER, STRING, STRING, INTEGER, UNDEF, UNDEF},
    },
    [268] = {
        .type = INTEGER,
        .name = "fchmodat",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [269] = {
        .type = INTEGER,
        .name = "faccessat",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [270] = {
        .type = INTEGER,
        .name = "pselect6",
        .types = {INTEGER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [271] = {
        .type = INTEGER,
        .name = "ppoll",
        .types = {OTHER, INTEGER, OTHER, OTHER, INTEGER, UNDEF},
    },
    [272] = {
        .type = INTEGER,
        .name = "unshare",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [273] = {
        .type = INTEGER,
        .name = "set_robust_list",
        .types = {OTHER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [274] = {
        .type = INTEGER,
        .name = "get_robust_list",
        .types = {INTEGER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [275] = {
        .type = INTEGER,
        .name = "splice",
        .types = {INTEGER, OTHER, INTEGER, OTHER, INTEGER, INTEGER},
    },
    [276] = {
        .type = INTEGER,
        .name = "tee",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [277] = {
        .type = INTEGER,
        .name = "sync_file_range",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [278] = {
        .type = INTEGER,
        .name = "vmsplice",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [279] = {
        .type = INTEGER,
        .name = "move_pages",
        .types = {INTEGER, INTEGER, OTHER, OTHER, OTHER, INTEGER},
    },
    [280] = {
        .type = INTEGER,
        .name = "utimensat",
        .types = {INTEGER, STRING, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [281] = {
        .type = INTEGER,
        .name = "epoll_pwait",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, OTHER, INTEGER},
    },
    [282] = {
        .type = INTEGER,
        .name = "signalfd",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [283] = {
        .type = INTEGER,
        .name = "timerfd_create",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [284] = {
        .type = INTEGER,
        .name = "eventfd",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [285] = {
        .type = INTEGER,
        .name = "fallocate",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [286] = {
        .type = INTEGER,
        .name = "timerfd_settime",
        .types = {INTEGER, INTEGER, OTHER, OTHER, UNDEF, UNDEF},
    },
    [287] = {
        .type = INTEGER,
        .name = "timerfd_gettime",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [288] = {
        .type = INTEGER,
        .name = "accept4",
        .types = {INTEGER, OTHER, OTHER, INTEGER, UNDEF, UNDEF},
    },
    [289] = {
        .type = INTEGER,
        .name = "signalfd4",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [290] = {
        .type = INTEGER,
        .name = "eventfd2",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [291] = {
        .type = INTEGER,
        .name = "epoll_create1",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [292] = {
        .type = INTEGER,
        .name = "dup3",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [293] = {
        .type = INTEGER,
        .name = "pipe2",
        .types = {OTHER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [294] = {
        .type = INTEGER,
        .name = "inotify_init1",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [295] = {
        .type = INTEGER,
        .name = "preadv",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [296] = {
        .type = INTEGER,
        .name = "pwritev",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [297] = {
        .type = INTEGER,
        .name = "rt_tgsigqueueinfo",
        .types = {INTEGER, INTEGER, INTEGER, OTHER, UNDEF, UNDEF},
    },
    [298] = {
        .type = INTEGER,
        .name = "perf_event_open",
        .types = {OTHER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [299] = {
        .type = INTEGER,
        .name = "recvmmsg",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, OTHER, UNDEF},
    },
    [300] = {
        .type = INTEGER,
        .name = "fanotify_init",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [301] = {
        .type = INTEGER,
        .name = "fanotify_mark",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, STRING, UNDEF},
    },
    [302] = {
        .type = INTEGER,
        .name = "prlimit64",
        .types = {INTEGER, INTEGER, OTHER, OTHER, UNDEF, UNDEF},
    },
    [303] = {
        .type = INTEGER,
        .name = "name_to_handle_at",
        .types = {INTEGER, STRING, OTHER, OTHER, INTEGER, UNDEF},
    },
    [304] = {
        .type = INTEGER,
        .name = "open_by_handle_at",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [305] = {
        .type = INTEGER,
        .name = "clock_adjtime",
        .types = {INTEGER, OTHER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [306] = {
        .type = INTEGER,
        .name = "syncfs",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [307] = {
        .type = INTEGER,
        .name = "sendmmsg",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [308] = {
        .type = INTEGER,
        .name = "setns",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [309] = {
        .type = INTEGER,
        .name = "getcpu",
        .types = {OTHER, OTHER, OTHER, UNDEF, UNDEF, UNDEF},
    },
    [310] = {
        .type = INTEGER,
        .name = "process_vm_readv",
        .types = {INTEGER, OTHER, INTEGER, OTHER, INTEGER, INTEGER},
    },
    [311] = {
        .type = INTEGER,
        .name = "process_vm_writev",
        .types = {INTEGER, OTHER, INTEGER, OTHER, INTEGER, INTEGER},
    },
    [312] = {
        .type = INTEGER,
        .name = "kcmp",
        .types = {INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, UNDEF},
    },
    [313] = {
        .type = INTEGER,
        .name = "finit_module",
        .types = {INTEGER, STRING, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [314] = {
        .type = INTEGER,
        .name = "sched_setattr",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [315] = {
        .type = INTEGER,
        .name = "sched_getattr",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, UNDEF, UNDEF},
    },
    [316] = {
        .type = INTEGER,
        .name = "renameat2",
        .types = {INTEGER, STRING, INTEGER, STRING, INTEGER, UNDEF},
    },
    [317] = {
        .type = INTEGER,
        .name = "seccomp",
        .types = {INTEGER, INTEGER, STRING, UNDEF, UNDEF, UNDEF},
    },
    [318] = {
        .type = INTEGER,
        .name = "getrandom",
        .types = {OTHER, OTHER, OTHER, OTHER, OTHER, OTHER},
    },
    [319] = {
        .type = INTEGER,
        .name = "memfd_create",
        .types = {STRING, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [320] = {
        .type = INTEGER,
        .name = "kexec_file_load",
        .types = {INTEGER, INTEGER, INTEGER, STRING, INTEGER, UNDEF},
    },
    [321] = {
        .type = INTEGER,
        .name = "bpf",
        .types = {INTEGER, OTHER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [322] = {
        .type = INTEGER,
        .name = "execveat",
        .types = {INTEGER, STRING, OTHER, OTHER, INTEGER, UNDEF},
    },
    [323] = {
        .type = INTEGER,
        .name = "userfaultfd",
        .types = {INTEGER, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [324] = {
        .type = INTEGER,
        .name = "membarrier",
        .types = {INTEGER, INTEGER, UNDEF, UNDEF, UNDEF, UNDEF},
    },
    [325] = {
        .type = INTEGER,
        .name = "mlock2",
        .types = {INTEGER, INTEGER, INTEGER, UNDEF, UNDEF, UNDEF},
    },
    [326] = {
        .type = INTEGER,
        .name = "copy_file_range",
        .types = {INTEGER, OTHER, INTEGER, OTHER, INTEGER, INTEGER},
    },
    [327] = {
        .type = INTEGER,
        .name = "preadv2",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, INTEGER, INTEGER},
    },
    [328] = {
        .type = INTEGER,
        .name = "pwritev2",
        .types = {INTEGER, OTHER, INTEGER, INTEGER, INTEGER, INTEGER},
    }
};

#endif
