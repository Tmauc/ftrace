/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** list
*/

#include "ftrace.h"

int add_func_front(list_t *list, char *name)
{
    list_t new_node = malloc(sizeof(list_t));

    if (new_node == NULL)
        return (84);
    new_node->func_name = strdup(name);
    new_node->next = *list;
    *list = new_node;
    return (0);
}

int add_func_back(list_t *list, char *name)
{
    list_t new_node = malloc(sizeof(list_t));
    list_t tmp_node;

    if (new_node == NULL)
        return (84);
    if (*list == NULL)
        return (add_func_front(list, name));
    new_node->func_name = strdup(name);
    new_node->next = NULL;
    tmp_node = *list;
    while (tmp_node->next != NULL)
        tmp_node = tmp_node->next;
    tmp_node->next = new_node;
    return (0);
}

int del_func_back(list_t *list)
{
    list_t tmp_node;

    if (*list == NULL)
        return (84);
    tmp_node = *list;
    while (tmp_node->next->next != NULL)
        tmp_node = tmp_node->next;
    tmp_node->next = NULL;
    return (0);
}

char *get_func_back(list_t list)
{
    if (list == NULL)
        return (NULL);
    while (list->next != NULL)
        list = list->next;
    return (list->func_name);
}

void print_del_list(list_t *real_list)
{
    dprintf(2, "Leaving function %s\n", get_func_back(*real_list));
    del_func_back(real_list);
}
