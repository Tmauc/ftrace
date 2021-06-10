/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** sygnal
*/

#ifndef SIGNAL_NAMES_H_
# define SIGNAL_NAMES_H_

static signal_t signals[] = {
    [0] = {
        .signame = "SIGHUP",
        .sig = SIGHUP,
    },
    [1] = {
        .signame = "SIGINT",
        .sig = SIGINT,
    },
    [2] = {
        .signame = "SIGQUIT",
        .sig = SIGQUIT,
    },
    [3] = {
        .signame = "SIGILL",
        .sig = SIGILL,
    },
    [4] = {
        .signame = "SIGTRAP",
        .sig = SIGILL,
    },
    [5] = {
        .signame = "SIGABRT",
        .sig = SIGABRT,
    },
    [6] = {
        .signame = "SIGIOT",
        .sig = SIGIOT,
    },
    [7] = {
        .signame = "SIGBUS",
        .sig = SIGBUS,
    },
    [8] = {
        .signame = "SIGFPE",
        .sig = SIGFPE,
    },
    [9] = {
        .signame = "SIGKILL",
        .sig = SIGKILL,
    },
    [10] = {
        .signame = "SIGUSR1",
        .sig = SIGUSR1,
    },
    [11] = {
        .signame = "SIGUSR2",
        .sig = SIGUSR2,
    },
    [12] = {
        .signame = "SIGSEGV",
        .sig = SIGSEGV,
    },
    [13] = {
        .signame = "SIGPIPE",
        .sig = SIGPIPE,
    },
    [14] = {
        .signame = "SIGALRM",
        .sig = SIGALRM,
    },
    [15] = {
        .signame = "SIGTERM",
        .sig = SIGTERM,
    },
    [16] = {
        .signame = "SIGSTKFLT",
        .sig = SIGSTKFLT,
    },
    [17] = {
        .signame = "SIGCHLD",
        .sig = SIGCHLD,
    },
    [18] = {
        .signame = "SIGCONT",
        .sig = SIGCONT,
    },
    [19] = {
        .signame = "SIGSTOP",
        .sig = SIGSTOP,
    },
    [20] = {
        .signame = "SIGTSTP",
        .sig = SIGTSTP,
    },
    [21] = {
        .signame = "SIGTTIN",
        .sig = SIGTTIN,
    },
    [22] = {
        .signame = "SIGTTOU",
        .sig = SIGTTOU,
    },
    [23] = {
        .signame = "SIGURG",
        .sig = SIGURG,
    },
    [24] = {
        .signame = "SIGXCPU",
        .sig = SIGXCPU,
    },
    [25] = {
        .signame = "SIGXFSZ",
        .sig = SIGXFSZ,
    },
    [26] = {
        .signame = "SIGVTALRM",
        .sig = SIGVTALRM,
    },
    [27] = {
        .signame = "SIGPROF",
        .sig = SIGPROF,
    },
    [28] = {
        .signame = "SIGWINCH",
        .sig = SIGWINCH,
    },
    [29] = {
        .signame = "SIGIO",
        .sig = SIGIO,
    },
    [30] = {
        .signame = "SIGPWR",
        .sig = SIGPWR,
    },
    [31] = {
        .signame = "SIGSYS",
        .sig = SIGSYS,
    },
    [32] = {
        .signame = "NULL",
        .sig = 84,
    },
};

#endif
