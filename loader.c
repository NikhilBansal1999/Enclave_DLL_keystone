#include <edge_call.h>
#include <errno.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "sha3.h"
#include <sys/mman.h>


typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */

#define EI_NIDENT 16

#define PT_DYNAMIC 2
#define PT_PHDR 6
#define PT_LOAD 1
#define PT_GNU_STACK 0x6474e551

#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_DYNAMIC 6
#define SHT_DYNSYM 11
#define SHT_RELA 4

#define DT_PLTRELSZ 2
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_JMPREL 23

#define R_RISCV_RELATIVE 3
#define R_RISCV_64 2
#define R_RISCV_JUMP_SLOT 5

typedef struct
{
  Elf64_Addr entry;      /*Entry point indicated by ELF header*/
  Elf64_Half phnum;      /*Number of program headers*/
  Elf64_Addr dyn_vaddr;  /*p_vaddr value of dynamic program header*/
  int dyn_num_ents;      /*Number of Dynamic table entries*/
  int dyn_num;           /*Program header number of dynamic program header*/
  Elf64_Addr pht_vaddr;  /*Virtual address of the program header table*/
  Elf64_Word stack_state;  /*Permissions of the stack*/
  Elf64_Addr start_of_mapping;
  Elf64_Addr end_of_mapping;
  Elf64_Addr base_addr;
  Elf64_Addr string_table;
  Elf64_Addr symbol_table;
  int num_sym_entry;
} link_info;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf_header;

typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf_Section_header;

typedef struct
{
  Elf64_Word st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  uint16_t	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf_Symtab_ent;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Program_header;

typedef struct
{
  Elf64_Sxword d_tag;
  union
  {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;

typedef struct
{
  Elf64_Addr mapstart, mapend, dataend, allocend, inc_begin;
  Elf64_Off mapoff;
  int prot;
  int filesize,memsize;
  long int size;
} command;

typedef struct
{
        Elf64_Addr      r_offset;
        Elf64_Xword     r_info;
        Elf64_Sxword    r_addend;
} Elf64_Rela;

#define ELF64_R_SYM(info)             ((info)>>32)
#define ELF64_R_TYPE(info)            ((Elf64_Word)(info))
#define ELF64_R_INFO(sym, type)       (((Elf64_Xword)(sym)<<32)+(Elf64_Xword)(type))

long align_down(long addr, long size)
{
  long ans=addr-(addr%size);
  return ans;
}

long align_up(long addr,long size)
{
  if(addr%size==0)
  {
    return addr;
  }
  else
  {
    long ans=align_down(addr,size)+size;
    return ans;
  }
}

typedef struct file_struct
{
  long block_size;
  long num_blocks;
  long offset;
}file_struct;

void read_from_file(char* read_buffer,long block_size, long num_blocks, char* file,long offset,int *data_read)
{
  file_struct* file_data = (file_struct*)malloc(sizeof(file_struct)+strlen(file)+1);
  file_data->block_size = block_size;
  file_data->num_blocks = num_blocks;
  file_data->offset = offset;
  memcpy((void*)(file_data+1),file,strlen(file));
  void* file_input = malloc(sizeof(int)+num_blocks*block_size);

  ocall(8,file_data,sizeof(file_struct)+strlen(file)+1,file_input,block_size*num_blocks + sizeof(int));

  *data_read = *((int*)file_input);
  memcpy(read_buffer,(char*)((int*)file_input + 1),(*data_read) * block_size);
  free(file_data);
  free(file_input);
  return;
}

int strncmp(char* str1, char* str2, int size)
{
  int ret_val = 0;
  for(int i=0;i<size;i++)
  {
    if(str1[i] == str2[i])
    {
      continue;
    }
    else
    {
      ret_val = 1;
      break;
    }
  }
  return ret_val;
}

void ocall_print_value(long val){

  unsigned long val_ = val;
  ocall(2, &val_, sizeof(long), 0, 0);

  return;
}

unsigned long get_pagesize()
{
  unsigned long ret_val;
  ocall(7,NULL,0,&ret_val,sizeof(ret_val));
  return ret_val;
}

unsigned long ocall_print_buffer(char* data, size_t data_len){

  unsigned long retval;
  ocall(1, data, data_len, &retval ,sizeof(unsigned long));

  return retval;
}

unsigned long ocall_get_number()
{
  unsigned long ret_val;
  ocall(5,0,0,&ret_val,sizeof(unsigned long));
  return ret_val;
}

link_info* map_library(char* lib_name)
{
  Elf_header* header=(Elf_header*)malloc(sizeof(Elf_header));
  link_info* info=(link_info*)malloc(sizeof(link_info));
  long pagesize = (long)get_pagesize();
  int data_read;

  read_from_file((char*)header,sizeof(Elf_header),1,lib_name,0,&data_read);

  if(header->e_type != 3)
  {
    ocall_print_buffer("The given file is not a shared object\n",38);
    return NULL;
  }
  info->entry=header->e_entry;
  info->phnum=header->e_phnum;
  Elf64_Program_header prog_heads[header->e_phnum];
  read_from_file((char*)prog_heads,sizeof(Elf64_Program_header),header->e_phnum,lib_name,header->e_phoff,&data_read);

  command commands[info->phnum];
  int num_commands=0;

  for(int i=0;i<header->e_phnum;i++)
  {
    if(prog_heads[i].p_type==PT_DYNAMIC)  /*Header type PT_DYNAMIC*/
    {
      info->dyn_vaddr=prog_heads[i].p_vaddr;
      info->dyn_num_ents=prog_heads[i].p_memsz/sizeof(Elf64_Dyn);
      info->dyn_num=i+1;
    }
    if(prog_heads[i].p_type==PT_PHDR)  /*Header Type PT_Phdr*/
    {
      info->pht_vaddr=prog_heads[i].p_vaddr;
    }
    if(prog_heads[i].p_type==PT_LOAD)  /*Header Type PT_Load*/
    {
      commands[num_commands].mapstart = align_down(prog_heads[i].p_vaddr,pagesize);
  	  commands[num_commands].mapend = align_up(prog_heads[i].p_vaddr + prog_heads[i].p_filesz,pagesize);
  	  commands[num_commands].dataend = prog_heads[i].p_vaddr + prog_heads[i].p_filesz;
  	  commands[num_commands].allocend = prog_heads[i].p_vaddr + prog_heads[i].p_memsz;
  	  commands[num_commands].mapoff = prog_heads[i].p_offset;
      commands[num_commands].inc_begin = prog_heads[i].p_vaddr;
      commands[num_commands].filesize = prog_heads[i].p_filesz;
      commands[num_commands].memsize = prog_heads[i].p_memsz;

      commands[num_commands].prot=0;
      if(prog_heads[i].p_flags & 4)/*Give read permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_READ;
      }
      if(prog_heads[i].p_flags & 2)/*Give write permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_WRITE;
      }
      if(prog_heads[i].p_flags & 1)/*Give execute permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_EXEC;
      }
      num_commands=num_commands+1;
    }
    if(prog_heads[i].p_type==PT_GNU_STACK) /*Header Type PT_GNU_STACK*/
    {
      info->stack_state=prog_heads[i].p_flags;
    }
   /*PT_NOTE and PT_TLS left out*/
  }
  /*Start mapping of library*/

  long length_of_mapping=commands[num_commands-1].allocend-commands[0].mapstart;
  char* data_buf=(char*)malloc(length_of_mapping);

  info->start_of_mapping=(Elf64_Addr)malloc(length_of_mapping+pagesize);
  if(info->start_of_mapping == (Elf64_Addr)NULL)
  {
    ocall_print_buffer("Allocating memory for library failed\n",37);
    return NULL;
  }

  info->start_of_mapping=align_up(info->start_of_mapping,pagesize);

  info->end_of_mapping=info->start_of_mapping+length_of_mapping;
  info->base_addr=info->start_of_mapping;//-commands[0].mapstart;
  for(int i=0;i<num_commands;i++)
  {
    length_of_mapping = commands[i].filesize;
    read_from_file((char*)data_buf,1,length_of_mapping,lib_name,commands[i].mapoff,&data_read);

    commands[i].size=data_read;
    for(int j=0;j<data_read;j++)
    {
      *((char*)(info->base_addr+commands[i].inc_begin)+j)=data_buf[j];
    }
    if(commands[i].allocend>commands[i].dataend)
    {
      memset((void *)(commands[i].dataend+info->base_addr),'\0',(commands[i].allocend-commands[i].dataend));
    }
  }

  int hash_len = commands[num_commands-1].allocend - commands[0].inc_begin;
  void* hash_start = (void*)(info->base_addr + commands[0].inc_begin);
  long* hash = (long*)malloc(64);
  hash = sha3(hash_start,hash_len,hash,64);

  if(info->dyn_vaddr != (Elf64_Addr)NULL)
  {
    info->dyn_vaddr = info->dyn_vaddr + info->base_addr;
  }
  if(info->pht_vaddr != (Elf64_Addr)NULL)
  {
    info->pht_vaddr = info->pht_vaddr + info->base_addr;
  }
  Elf_Section_header section[header->e_shnum];
  read_from_file((char*)section,sizeof(Elf_Section_header),header->e_shnum,lib_name,header->e_shoff,&data_read);
  Elf64_Addr dynamic;
  int num_dyn_ent;
  int dyn_sym_num;
  Elf64_Addr dyn_sym_offset;
  //Reading section string table
  char* section_string=(char*)malloc(section[header->e_shstrndx].sh_size);
  read_from_file((char*)section_string,1,section[header->e_shstrndx].sh_size,lib_name,section[header->e_shstrndx].sh_offset,&data_read);

  Elf64_Addr relocation_addr;
  Elf64_Addr section_string_table = section[header->e_shstrndx].sh_offset;
  for(int i=0;i < header->e_shnum ;i++)
  {
    if(section[i].sh_type==SHT_STRTAB && i != header->e_shstrndx)   /*String Table entry*/
    {
      char section_name[16];
      read_from_file((char*)section_name,8,1,lib_name,section_string_table+section[i].sh_name,&data_read);
      if(strncmp(section_name,".dyn",4) == 0)
      {
        info->string_table = section[i].sh_offset;
      }
    }
    if(section[i].sh_type==SHT_DYNAMIC)  /* DYNAMIC Section */
    {
      dynamic=section[i].sh_offset;
      num_dyn_ent=section[i].sh_size/section[i].sh_entsize;
    }
    if(section[i].sh_type==SHT_DYNSYM)
    {
      dyn_sym_offset=section[i].sh_offset;
      dyn_sym_num=section[i].sh_size/section[i].sh_entsize;
      info->symbol_table = section[i].sh_offset;
      info->num_sym_entry = section[i].sh_size/section[i].sh_entsize;
    }
  }
  Elf64_Dyn dyn_entries[num_dyn_ent];
  int num_relocations;
  read_from_file((char*)dyn_entries,sizeof(Elf64_Dyn),num_dyn_ent,lib_name,dynamic,&data_read);
  void (*init)();

  int plt_ents;
  Elf64_Addr plt_offset;
  int init_required=0;
  for(int i=0;i<num_dyn_ent;i++)
  {
    if(dyn_entries[i].d_tag==DT_RELA) //DT_RELA
    {
      relocation_addr=dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_RELASZ) /*DT_RELASZ*/
    {
      num_relocations=dyn_entries[i].d_un.d_val/sizeof(Elf64_Rela);
    }
    if(dyn_entries[i].d_tag==DT_INIT)  /*DT_INIT*/
    {
      init_required = 1;
      init = (void*)(info->base_addr+dyn_entries[i].d_un.d_ptr);
    }
    if(dyn_entries[i].d_tag==DT_PLTRELSZ)  /*Size of relocation entries associated with PLT*/
    {
      plt_ents=dyn_entries[i].d_un.d_val;
    }
    if(dyn_entries[i].d_tag==DT_JMPREL) /*DT_JMPREL*/
    {
      plt_offset=dyn_entries[i].d_un.d_ptr;
    }
  }
  for(int i=0;i < header->e_shnum ;i++)
  {
    if(section[i].sh_type==SHT_RELA)
    {
      if(section[i].sh_addr==relocation_addr)
      {
        relocation_addr=section[i].sh_offset;
        break;
      }
    }
  }
  plt_ents=plt_ents/sizeof(Elf64_Rela);

  Elf_Symtab_ent* symbols=(Elf_Symtab_ent*)malloc(info->num_sym_entry*sizeof(Elf_Symtab_ent));
  read_from_file((char*)symbols,sizeof(Elf_Symtab_ent),dyn_sym_num,lib_name,dyn_sym_offset,&data_read);

  Elf64_Rela relocations[num_relocations];
  read_from_file((char*)relocations,sizeof(Elf64_Rela),num_relocations,lib_name,relocation_addr,&data_read);
  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+relocations[i].r_offset);
    if(type==R_RISCV_64)
    {
      *(reloc_addr)=symbols[sym_index].st_value + relocations[i].r_addend + info->base_addr;
    }
    if(type==R_RISCV_RELATIVE)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  Elf64_Rela plt_relocations[plt_ents];
  read_from_file((char*)plt_relocations,sizeof(Elf64_Rela),plt_ents,lib_name,plt_offset,&data_read);
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+plt_relocations[i].r_offset);
    if(type==R_RISCV_JUMP_SLOT)
    {
      *(reloc_addr)=symbols[sym_index].st_value;
    }
  }

  if(init_required)
  {
    (*init)();
  }

  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+relocations[i].r_offset);
    if(type==R_RISCV_64)
    {
      *(reloc_addr)= symbols[sym_index].st_value + relocations[i].r_addend + info->base_addr;
    }
    if(type==R_RISCV_RELATIVE)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+plt_relocations[i].r_offset);
    if(type==R_RISCV_JUMP_SLOT)
    {
      *(reloc_addr)=info->base_addr+symbols[sym_index].st_value;
    }
  }
  return info;
}

void * get_function(char* lib_name,link_info* info,char *func_name)
{
  Elf_Symtab_ent symbols[info->num_sym_entry];
  int data_read;
  read_from_file((char*)symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,lib_name,info->symbol_table,&data_read);
  data_read = data_read;
  char str[strlen(func_name)+1];
  for(int i=0;i < info->num_sym_entry;i++)
  {
    read_from_file((char*)str,strlen(func_name)+1,1,lib_name,info->string_table+symbols[i].st_name,&data_read);
    if(strncmp(str,func_name,strlen(func_name)+1)==0)
    {
      void *addr=(void *)(info->base_addr+symbols[i].st_value);
      return addr;
    }
  }
  return NULL;
}
void EAPP_ENTRY main_loader()
{
  link_info* handle=map_library("./libfibonacci.so");
  if(handle == NULL)
  {
    ocall_print_buffer("Error opening library\n",23);
    return;
  }
  else
  {
    ocall_print_buffer("Library loaded\n",15);
    int (*fibo)(int);
    fibo = (int (*)(int))get_function("./libfibonacci.so",handle, "fibonacci");
    if(fibo == NULL)
    {
      ocall_print_buffer("Function not found\n",19);
    }
    else
    {
      int number = (int)ocall_get_number();
      ocall_print_value((*fibo)(number));
    }
  }
}
