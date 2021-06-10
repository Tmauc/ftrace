/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** ftrace
*/

#ifndef FTRACE_H_
# define FTRACE_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <libelf.h>
#include <elf.h>

# define VOID ('?')
# define UNDEF (0)
# define INTEGER (1)
# define STRING (2)
# define OTHER (4)

# define ERROR(x) (dprintf(2, "ftrace: %s\n", strerror(errno)), x)
# define TABSIZE(x) (sizeof(x) / sizeof(*x))
# define WORDTAB (my_str_to_wordtab)

# define NON_PRINTABLE ("execve")
# define MAX_PRINTABLE (32)

pid_t pid;

typedef struct syscall_s
{
    char *name;
    int type;
    int types[6];

} syscall_t;

typedef struct elf_s
{
    Elf *elf;
    Elf_Scn *scn;
    Elf_Data *data;
    int fd;
} elf_t;

typedef struct signal_s
{
    char *signame;
    int sig;
} signal_t;

typedef struct info_s
{
    char **arg;
    char *command;
    long long unsigned int rax;
} info_t;

typedef struct node_s
{
    char *func_name;
    struct node_s *next;
} node_t;


typedef struct norme_s
{
    long long unsigned int peek;
    char *name;
} norme_t;

typedef node_t *list_t;

/*UTILS*/

char **my_str_to_wordtab(char *str, char sep);
char *concat_path(char *command, char **env);
void get_detached_process(int signum);
int get_good_signal(int status);
int get_tab_size(int *tab);
char *cut_command(char *command);
int print_usage(const char *av);

/*SYSCALLS*/

int display_syscalls(int status, struct user_regs_struct *user,
long long int end_rax);

/*ELF*/

int prepare_elf(const char *path, elf_t *elf_data);
char *get_symbol_data(elf_t *elf_data, long long unsigned int addr,
Elf64_Shdr *shdr);
char *get_symbol_tab(elf_t *elf_data, long long unsigned int addr);
int get_func_process(elf_t *elf_data,
list_t *real_list, struct user_regs_struct user_bis, norme_t var);

/*LIST*/

int add_func_front(list_t *list, char *name);
int add_func_back(list_t *list, char *name);
int del_func_back(list_t *list);
char *get_func_back(list_t list);
void print_del_list(list_t *real_list);

/*SIGNALS*/

int display_signal(int signal);

#endif
