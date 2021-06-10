/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** signals
*/

#include "ftrace.h"
#include "signal_names.h"

int display_signal(int signal)
{
    int i = -1;

    while (signals[++i].sig != 84) {
        if (signals[i].sig == signal)
            return (dprintf(2, "Reveived signal %s\n", signals[i].signame), 84);
    }
    return (84);
}
