/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** main
*/

#include "ftrace.h"

int get_leave(long long unsigned int peek)
{
    if ((peek & 0xFF) == 0xc2 || (peek & 0xFF) == 0xc3
    || (peek & 0xFF) == 0xca || (peek & 0xFF) == 0xcb)
        return (0);
    return (84);
}

int get_enter(long long unsigned int peek)
{
    if (((peek & 0xFF) == 0xe8) || ((peek & 0xFF) == 0xFF
    && (peek & 0x3800) == 0x1000))
        return (0);
    return (84);
}

int get_father_process(pid_t pid, int status, elf_t *elf_data, char *command)
{
    struct user_regs_struct user;
    struct user_regs_struct user_bis;
    norme_t var;
    list_t *real_list = malloc(sizeof(list_t));

    while (get_good_signal(status) == 0) {
        ptrace(PTRACE_GETREGS, pid, NULL, &user);
        var.peek = ptrace(PTRACE_PEEKTEXT, pid, user.rip, user);
        var.name = strdup(command);
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
            return (ERROR(84));
        ptrace(PTRACE_GETREGS, pid, NULL, &user_bis);
        if ((short)var.peek == 0x050F)
            display_syscalls(status, &user, user_bis.rax);
        else if (get_enter(var.peek) == 0)
            get_func_process(elf_data, real_list, user, var);
        else if (get_leave(var.peek) == 0 && get_func_back(*real_list) != NULL)
            print_del_list(real_list);
        waitpid(pid, &status, 0);
    }
    return (0);
}

int start_ftrace(char **arg, char **env, info_t *info)
{
    int status;
    char *command = NULL;
    elf_t elf_data;

    signal(SIGINT, get_detached_process);
    if ((command = concat_path(arg[1], env)) == NULL)
        return (ERROR(84));
    if (prepare_elf(command, &elf_data) == 84)
        return (84);
    info->command = strdup(command);
    if ((pid = fork()) == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        execve(command, &arg[1], env);
    } else {
        waitpid(pid, &status, 0);
        get_father_process(pid, status, &elf_data, info->command);
    }
    return (0);
}

int main(int ac, char **av, char **env)
{
    info_t info;

    if (ac < 2)
        return (84);
    if (strcmp(av[1], "--help") == 0 || strcmp(av[1], "-h") == 0)
        return (print_usage(av[0]));
    return (start_ftrace(av, env, &info));
}
