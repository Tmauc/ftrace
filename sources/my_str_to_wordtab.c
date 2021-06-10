/*
** EPITECH PROJECT, 2018
** str to tab
** File description:
** str to wordtab
*/

#include "ftrace.h"

char **create_tab(char *str, char sep)
{
    int i = 0;
    int k = 0;
    char **tab;

    while (str[i] != '\0') {
        if (str[i] == sep)
            k++;
        i++;
    }
    tab = malloc(sizeof(char *) * (k + 2));
    tab[k] = NULL;
    return (tab);
}

int my_wordlen(char *str)
{
    char *keep = str;

    for (; *str; str++);
    return (str - keep);
}

char **my_str_to_wordtab(char *str, char sep)
{
    int i = -1;
    int j = -1;
    int k = 0;
    char **tab = create_tab(str, sep);

    while (str[++i] != '\0') {
        tab[++j] = malloc(sizeof(char) * (my_wordlen(str + i) + 1));
        while (str[i] != '\0' && str[i] != sep) {
            tab[j][k] = str[i];
            k++;
            i++;
        }
        tab[j][k] = '\0';
        if (!str[i]) {
            j++;
            tab[j] = NULL;
            break;
        }
        k = 0;
    }
    return (tab);
}
