/*
** EPITECH PROJECT, 2019
** Ftrace
** File description:
** syscalls
*/

#include "ftrace.h"
#include "syscall_names.h"

char *get_syscall_name(unsigned long long int arg)
{
    if (arg < 329)
        return (syscalls[arg].name);
    return (NULL);
}

long long get_syscall_arg(struct user_regs_struct *user, int i)
{
    if (i == 0)
        return (user->rdi);
    if (i == 1)
        return (user->rsi);
    if (i == 2)
        return (user->rdx);
    if (i == 3)
        return (user->r10);
    if (i == 4)
        return (user->r8);
    if (i == 5)
        return (user->r9);
    return (0);
}

int get_args(struct user_regs_struct *user, long long int end_rax)
{
    int i = -1;
    int nb_args = get_tab_size(syscalls[user->rax].types);
    long long arg_value = 0;

    while (++i < nb_args) {
        arg_value = get_syscall_arg(user, i);
        dprintf(2, "0x%llx", arg_value);
        if (i < nb_args - 1)
            dprintf(2, ", ");
    }
    if (syscalls[user->rax].type != VOID)
        dprintf(2, ") = 0x%llx\n", end_rax);
    else
        dprintf(2, ") = ?\n");
    return (0);
}

int display_syscalls(int status, struct user_regs_struct *user,
long long int end_rax)
{
    if (!get_good_signal(status)) {
        dprintf(2, "Syscall %s(", get_syscall_name(user->rax));
        get_args(user, end_rax);
    } else {
        dprintf(2, "Syscall %s(", get_syscall_name(user->rax));
        get_args(user, end_rax);
        dprintf(2, "+++ exited with %d +++\n", WSTOPSIG(status));
    }
    return (0);
}
