#include <elf.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __i386__
    #define V_ADDR 0x08048000
    #define Elf_class ELFCLASS32
    #define Elf_machine EM_386
    #define ElfN_Ehdr Elf32_Ehdr
    #define ElfN_Phdr Elf32_Phdr
    #define ElfN_Shdr Elf32_Shdr
    #define ElfN_Dyn Elf32_Dyn
#elif defined(__x86_64__)
    #define V_ADDR 0x00400000
    #define Elf_class ELFCLASS64
    #define Elf_machine EM_X86_64
    #define ElfN_Ehdr Elf64_Ehdr
    #define ElfN_Phdr Elf64_Phdr
    #define ElfN_Shdr Elf64_Shdr
    #define ElfN_Dyn Elf64_Dyn
#endif

#define PDYN_NUM 6

unsigned int str_to_ptype(char *str) {
    if( strncmp(str, "exec", sizeof(strlen(str))) >= 0) return ET_EXEC;
    if( strncmp(str, "dyn", sizeof(strlen(str))) >= 0) return ET_DYN;

    return PT_NULL;
}

unsigned char* hexstr_to_char(char* hexstr) {
    int length = strlen(hexstr);
    char *pos = hexstr;

    // Input length should be even
    if (length % 2 != 0) return NULL;
    
    unsigned char *out = calloc(length , sizeof(unsigned char));
    
    for(int i = 0; i < (length / 2); i++) {
        sscanf(pos, "%2hhx", &out[i]);
        pos += 2;
    }
    
    return out;
}

// Create ELF headers
ElfN_Ehdr *ElfN_Ehdr_create(unsigned int e_type, unsigned int phnum) {
    ElfN_Ehdr *e_hdr = calloc(1, sizeof(ElfN_Ehdr));
    e_hdr->e_ident[EI_MAG0] = ELFMAG0;
    e_hdr->e_ident[EI_MAG1] = ELFMAG1;
    e_hdr->e_ident[EI_MAG2] = ELFMAG2;
    e_hdr->e_ident[EI_MAG3] = ELFMAG3;
    e_hdr->e_ident[EI_CLASS] = Elf_class;
    e_hdr->e_ident[EI_DATA] = ELFDATA2LSB;
    e_hdr->e_ident[EI_VERSION] = EV_CURRENT;
    e_hdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    e_hdr->e_ident[EI_ABIVERSION] = 0;
    e_hdr->e_ident[EI_PAD] = 0;
    e_hdr->e_ident[EI_NIDENT] = 9;

    e_hdr->e_type = e_type;
    e_hdr->e_machine = Elf_machine;
    e_hdr->e_version = EV_CURRENT;
    e_hdr->e_entry = V_ADDR + sizeof(ElfN_Ehdr) + phnum * sizeof(ElfN_Phdr);
    e_hdr->e_phoff = sizeof(ElfN_Ehdr);
    e_hdr->e_shoff = 0x00;
    e_hdr->e_flags = 0x00;
    e_hdr->e_ehsize = sizeof(ElfN_Ehdr);
    e_hdr->e_phentsize = sizeof(ElfN_Phdr);
    e_hdr->e_phnum = phnum;
    e_hdr->e_shentsize = sizeof(ElfN_Shdr);
    e_hdr->e_shnum = 0x00;
    e_hdr->e_shstrndx = 0x00;
    return e_hdr;
}

// Create ELF Programs
ElfN_Phdr *ElfN_Phdr_create(unsigned int p_type, unsigned int payload_size) {
    ElfN_Phdr *p_hdr = calloc(1, sizeof(ElfN_Phdr));
    p_hdr->p_type = p_type; 
    p_hdr->p_offset = (p_type == PT_LOAD) 
        ? 0x00
        : ( sizeof(ElfN_Ehdr) + ( 2 * sizeof(ElfN_Phdr) ) + payload_size );
    p_hdr->p_vaddr =(p_type == PT_LOAD) 
        ? V_ADDR 
        : ( V_ADDR + sizeof(ElfN_Ehdr) + ( 2 * sizeof(ElfN_Phdr) ) + payload_size );
    p_hdr->p_paddr = 0x00;
    p_hdr->p_filesz = (p_type == PT_LOAD) 
        ? ( sizeof(ElfN_Ehdr) + 2 * sizeof(ElfN_Phdr) + payload_size + PDYN_NUM * sizeof(ElfN_Dyn) ) 
        : PDYN_NUM * sizeof(ElfN_Dyn);
    p_hdr->p_memsz = (p_type == PT_LOAD) 
        ? ( sizeof(ElfN_Ehdr) + 2 * sizeof(ElfN_Phdr) + payload_size + PDYN_NUM * sizeof(ElfN_Dyn) ) 
        : PDYN_NUM * sizeof(ElfN_Dyn);
    p_hdr->p_flags = PF_R | PF_W | PF_X;
    p_hdr->p_align = (p_type == PT_LOAD) ? 0x1000 : 0X08;
    return p_hdr;
}

ElfN_Dyn **ElfN_Dyn_create(unsigned int dt_init) {
    ElfN_Dyn **p_dyn = calloc(6, sizeof(ElfN_Dyn *));

    p_dyn[0] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[0]->d_tag = DT_STRTAB;
    p_dyn[0]->d_un.d_ptr = 0x00;

    p_dyn[1] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[1]->d_tag = DT_SYMTAB;
    p_dyn[1]->d_un.d_ptr = 0x00;

    p_dyn[2] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[2]->d_tag = DT_STRSZ;
    p_dyn[2]->d_un.d_ptr = 0x00;

    p_dyn[3] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[3]->d_tag = DT_SYMENT;
    p_dyn[3]->d_un.d_ptr = 0x00;

    p_dyn[4] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[4]->d_tag = DT_INIT;
    p_dyn[4]->d_un.d_ptr = dt_init;

    p_dyn[5] = calloc(1, sizeof(ElfN_Dyn));
    p_dyn[5]->d_tag = DT_NULL;
    p_dyn[5]->d_un.d_ptr = 0x00;

    return p_dyn;

}

int main(int argc, char **argv) {

    // Print help
    if(argc != 3) {
        printf("./simplelf [exec,dyn] <shellcode>\n");
        return 1;
    }

    // Parsing arguments
    unsigned int e_type = str_to_ptype(argv[1]);
    unsigned char *payload = hexstr_to_char(argv[2]);

    // Dump ELF to file
    FILE *f = fopen("cpoc", "w");
    if(NULL != f){

        unsigned int phnum = (e_type == ET_DYN) ? 2 : 1;

        // Crafting ELF Header
        ElfN_Ehdr *e_hdr = ElfN_Ehdr_create(e_type, phnum);

        // Crafting Program Headers
        ElfN_Phdr *p_hdr_load = ElfN_Phdr_create(PT_LOAD, strlen(payload));

        ElfN_Phdr *p_hdr_dyn = ElfN_Phdr_create(PT_DYNAMIC, strlen(payload));
        
        // Crafting dynamic segment
        ElfN_Dyn **p_dyn = ElfN_Dyn_create(V_ADDR + sizeof(ElfN_Ehdr) + 2 * sizeof(ElfN_Phdr));

        fwrite(e_hdr, sizeof(ElfN_Ehdr), 1, f);
        fwrite(p_hdr_load, sizeof(ElfN_Phdr), 1, f);
        if(e_type == ET_DYN) fwrite(p_hdr_dyn, sizeof(ElfN_Phdr), 1, f);
        fwrite(payload, strlen(payload), 1, f);
        
        if(e_type == ET_DYN) for(int i = 0; i < PDYN_NUM; i++) fwrite(p_dyn[i], sizeof(**p_dyn), 1, f);

        fclose(f);

        // Free memory
        free(e_hdr);
        free(p_hdr_load);
        free(p_hdr_dyn);
        free(payload);
        free(p_dyn);
    }

}