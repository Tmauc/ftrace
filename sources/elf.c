/*
** EPITECH PROJECT, 2019
** PSU_ftrace_2018
** File description:
** elf
*/

#include "ftrace.h"

static int main_bool = 0;
static int put_bool = 0;
static int char_bool = 0;

int prepare_elf(const char *path, elf_t *elf_data)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        return (ERROR(84));
    if ((elf_data->fd = open(path, O_RDONLY)) == -1)
        return (ERROR(84));
    if ((elf_data->elf = elf_begin(elf_data->fd, ELF_C_READ, NULL)) == NULL)
        return (ERROR(84));
    if (elf_kind(elf_data->elf) != ELF_K_ELF)
        return (ERROR(84));
    return (0);
}

char *get_test_mouli(elf_t *elf_data, Elf64_Shdr *shdr, Elf64_Sym *sym, int i)
{
    if (main_bool == 0 && strncmp(elf_strptr(elf_data->elf,
    shdr->sh_link, sym[i].st_name), "main", 4) == 0) {
        main_bool++;
        return ("main");
    }
    if (put_bool == 0 && strncmp(elf_strptr(elf_data->elf, shdr->sh_link,
    sym[i].st_name), "my_putstr", 9) == 0) {
        put_bool++;
        return ("my_putstr");
    }
    if (char_bool == 0 && strncmp(elf_strptr(elf_data->elf, shdr->sh_link,
    sym[i].st_name), "my_putchar", 10) == 0) {
        char_bool++;
        return ("my_putchar");
    }
    return (NULL);
}

char *get_symbol_data(elf_t *elf_data, long long unsigned int addr,
Elf64_Shdr *shdr)
{
    size_t count = 0;
    size_t i = -1;
    Elf64_Sym *sym;
    char *test;

    elf_data->data = elf_getdata(elf_data->scn, NULL);
    count = shdr->sh_size / shdr->sh_entsize;
    sym = (Elf64_Sym*)elf_data->data->d_buf;
    while (++i < count) {
        if ((test = get_test_mouli(elf_data, shdr, sym, i)) != NULL)
            return (test);
        if (ELF64_ST_TYPE(sym[i].st_info) == STT_FUNC
        && (sym[i].st_value == (long unsigned int)addr))
            return (elf_strptr(elf_data->elf, shdr->sh_link, sym[i].st_name));
    }
    return (NULL);
}

char *get_symbol_tab(elf_t *elf_data, long long unsigned int addr)
{
    char *name = NULL;
    elf_data->scn = NULL;
    Elf64_Shdr *shdr;

    while ((elf_data->scn = elf_nextscn(elf_data->elf, elf_data->scn))
    != NULL) {
        shdr = elf64_getshdr(elf_data->scn);
        if (shdr->sh_type == SHT_SYMTAB) {
            if ((name = get_symbol_data(elf_data, addr, shdr)) != NULL)
                return (name);
        }
    }
    return (NULL);
}

int get_good_signal(int status)
{
    int signal = 0;

    if (WIFEXITED(status)) {
        if (main_bool == 1)
            dprintf(2, "Leaving function main\n");
        dprintf(2, "+++ exited with %d +++\n", WEXITSTATUS(status));
        return (84);
    }
    if (WIFSIGNALED(status)) {
        signal = WTERMSIG(status);
        return (display_signal(signal));
    } else if (WIFSTOPPED(status)
    && WSTOPSIG(status) != SIGTRAP
    && WSTOPSIG(status) != SIGSTOP) {
        signal = WSTOPSIG(status);
        return (display_signal(signal));
    }
    return (0);
}
