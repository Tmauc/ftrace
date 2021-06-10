/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** execute
*/

#include "ftrace.h"

char *my_sepcat(char *dest, char c, char *src)
{
    int i = 0;
    int j = 0;
    int len_1 = strlen(dest);
    int len_2 = strlen(src);
    char *str3 = malloc(sizeof(str3) * (len_1 + len_2 + 1));

    while (dest[i] != '\0') {
        str3[i] = dest[i];
        i = i + 1;
    }
    str3[i++] = c;
    while (src[j] != '\0')
        str3[i++] = src[j++];
    str3[i] = '\0';
    return (str3);
}

char **get_path(char **env)
{
    int i = -1;
    char *path = "PATH=";

    while (env[++i] != NULL)
        if (strncmp(env[i], path, strlen(path)) == 0)
            return (WORDTAB(env[i] + strlen(path), ':'));
    return (NULL);
}

int error_file(const char *str)
{
    if ((str != NULL) && (access(str, X_OK) == 0))
            return (42);
    return (0);
}

char *concat_path(char *command, char **env)
{
    int i = -1;
    char **tab = get_path(env);
    char *concat = NULL;

    while (tab[++i] != NULL) {
        if ((*command == '/' || *command == '.')
        && error_file(command) == 42)
            return (command);
        concat = my_sepcat(tab[i], '/', command);
        if (error_file(concat) == 42)
            return (concat);
        free(concat);
    }
    return (NULL);
}
