#include <elf.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LITTLE_ENDIAN
    #define uint16_t_le(x) (x)
    #define uint16_t_be(x) htobe16(x)
    #define uint32_t_le(x) (x)
    #define uint32_t_be(x) htobe32(x)
    #define uint64_t_le(x) (x)
    #define uint64_t_be(x) htobe64(x)
#elif defined(BIG_ENDIAN)
    #define uint16_t_be(x) (x)
    #define uint16_t_le(x) htole16(x)
    #define uint32_t_be(x) (x)
    #define uint32_t_le(x) htole32(x)
    #define uint64_t_be(x) (x)
    #define uint64_t_le(x) htole64(x)
#endif

#ifdef __i386__
    #define V_ADDR 0x08048000
    #define Elf_class ELFCLASS32
    #define Elf_machine EM_386
    #define ElfN_Ehdr Elf32_Ehdr
    #define ElfN_Phdr Elf32_Phdr
    #define ElfN_Shdr Elf32_Shdr
#elif defined(__x86_64__)
    #define V_ADDR 0x00400000
    #define Elf_class ELFCLASS64
    #define Elf_machine EM_X86_64
    #define ElfN_Ehdr Elf64_Ehdr
    #define ElfN_Phdr Elf64_Phdr
    #define ElfN_Shdr Elf64_Shdr
#endif

unsigned char* hexstr_to_char(char* hexstr)
{
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
ElfN_Ehdr *ElfN_Ehdr_create(void) {
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
    e_hdr->e_ident[EI_PAD] = 7;
    e_hdr->e_ident[EI_NIDENT] = 9;

    e_hdr->e_type = ET_EXEC;
    e_hdr->e_machine = Elf_machine;
    e_hdr->e_version = EV_CURRENT;
    e_hdr->e_entry = V_ADDR + sizeof(ElfN_Ehdr) + sizeof(ElfN_Phdr);
    e_hdr->e_phoff = sizeof(ElfN_Ehdr);
    e_hdr->e_shoff = 0x00;
    e_hdr->e_flags = 0x00;
    e_hdr->e_ehsize = sizeof(ElfN_Ehdr);
    e_hdr->e_phentsize = sizeof(ElfN_Phdr);
    e_hdr->e_phnum = 0x01;
    e_hdr->e_shentsize = sizeof(ElfN_Shdr);
    e_hdr->e_shnum = 0x00;
    e_hdr->e_shstrndx = 0x00;
    return e_hdr;
}

// Create ELF Programs
ElfN_Phdr *ElfN_Phdr_create(int payload_size) {
    ElfN_Phdr *p_hdr = calloc(1, sizeof(ElfN_Phdr));
    p_hdr->p_type = 0x01; 
    p_hdr->p_offset = sizeof(ElfN_Ehdr) + sizeof(ElfN_Phdr);
    p_hdr->p_vaddr = V_ADDR + sizeof(ElfN_Ehdr) + sizeof(ElfN_Phdr);
    p_hdr->p_paddr = 0x00;
    p_hdr->p_filesz = payload_size;
    p_hdr->p_memsz = payload_size;
    p_hdr->p_flags = PF_X | PF_R;
    p_hdr->p_align = 0x1000;
    return p_hdr;
}

int main(int argc, char **argv) {

    if(argc != 2) {
        printf("./simplelf <shellcode>\n");
        return 1;
    }

    unsigned char *payload = hexstr_to_char(argv[1]);

    // Dump ELF
    FILE *f = fopen("cpoc", "w");
    if(f != NULL){
        // Crafting ELF Header
        ElfN_Ehdr *e_hdr = ElfN_Ehdr_create();

        // Crafting Program Header
        ElfN_Phdr *p_hdr = ElfN_Phdr_create(sizeof(payload));

        fwrite(e_hdr, sizeof(ElfN_Ehdr), 1, f);
        fwrite(p_hdr, sizeof(ElfN_Phdr), 1, f);
        fwrite(payload, strlen(payload), 1, f);
        fclose(f);

        // Free memory
        free(e_hdr);
        free(p_hdr);
        free(payload);
    }

}