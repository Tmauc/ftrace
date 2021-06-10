/*
** EPITECH PROJECT, 2019
** Ftrace
** File description:
** ftrace_utils
*/

#include "ftrace.h"

int get_tab_size(int *tab)
{
    int i = -1;
    int nb = 0;

    while (++i != 6) {
        if (tab[i] != UNDEF)
            nb++;
    }
    return (nb);
}

void get_detached_process(int signum)
{
    (void)signum;
    dprintf(2, "ftrace: Process %d detached\n", pid);
    exit(0);
}
