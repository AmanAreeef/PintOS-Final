#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);

//Process Syscalls
void halt();
void sys_exit();
pid_t exec(const char *cmd_line);

//Filesys Syscalls
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char* file);
int fileSize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

int get_fd();
static bool chk(const uint8_t *uaddr);
static int getUsr (const uint8_t *uaddr);

//Struct to hold information about open file_table.
struct file_info
{
  struct file *file;
  int fd;
  struct list_elem elem;
};
//lock to lock filesystem when in use by syscall.
struct lock file_lock;
//list to hold record of all open file_table.
struct list *file_table;


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&file_table);
  lock_init(&file_lock);
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t *p = f -> esp;
  printf("System call number : %d\n",*p);

  //Switch statment to process syscall number, assigns return value to eax.
  switch(*p){

    case SYS_HALT:
        halt();
        break;

    case SYS_EXIT:
        sys_exit();
        break;

    case SYS_CREATE:{
        char *file =  *(char**)(f->esp+4);
        int initial_size = *(int*)(f->esp+8);
        f->eax = create(file,initial_size);
        break;
      }

    case SYS_REMOVE:{
        char *file = *(char**)(f->esp+4);
        f->eax = remove(file);
        break;
      }

    case SYS_OPEN:{
        char *file = *(char**)(f->esp+4);
        f->eax = open(file);
        break;
      }

    case SYS_fileSize:{
        int fd = *(int*)(f->esp+4);
        f->eax = fileSize(fd);
        break;
      }

    case SYS_READ:{
        int fd = *(int *)(f->esp+4);
        void * buffer = *(char**)(f->esp+8);
        unsigned size = *(unsigned *)(f->esp + 12);
        f->eax = read(fd,buffer,size);
        break;
      }

    case SYS_WRITE:{
        int fd = *(int *)(f->esp+4);
        void * buffer = *(char**)(f->esp+8);
        unsigned size = *(unsigned *)(f->esp + 12);
        f->eax = write(fd,buffer, size);
        break;
    }

    case SYS_SEEK:{
        int fd = *(int *)(f->esp+4);
        unsigned position = *(char**)(f->esp+8);
        break;
      }

    case SYS_TELL:{
        int fd = *(int *)(f->esp+4);
        f->eax = tell(fd);
        break;
      }

    case SYS_CLOSE:{
        int fd = *(int *)(f->esp+4);
        close(fd);
        break;
      }

    default:
        printf ("system call!\n",*p);
        thread_exit ();
        break;
      }
}

void
sys_exit(){
  printf("%s:exit(%d)\n",thread_current()->name, thread_current()->status );
  thread_exit();
}

void
halt()
{
  shutdown_power_off();
}

bool
create(const char *file, unsigned initial_size)
{
  if(chk((uint8_t)*file)== false)//If the name is not valid the process is terminated
  {
    sys_exit();
  }
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  bool status = filesys_create(file,initial_size);
  lock_release(&file_lock);//Filesystem released
  return status;
}

bool
remove(const char *file)
{
  if(chk((uint8_t)*file)== false)//If the name is not valid the process is terminated
  {
    sys_exit();
  }
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  bool status = filesys_remove(file);//filesys_remove called
  lock_release(&file_lock);//Filesystem released
  return status;
}

int
open(const char *file)
{
  struct file *f;
  struct file_info *ft;
  if(chk((uint8_t)*file)== false)//If the name is not valid the process is terminated
  {
    sys_exit();
  }
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  f = filesys_open(file);
  if(f)
  {
    ft = malloc(sizeof *ft);//Memory for the file information is allocated
    ft->file=f;
    ft->fd=get_fd();//File descriptor allocated
    list_push_back(&file_table,&ft->elem);//Open files pushed to the file table
  }
  lock_release(&file_lock);//Filesystem released
  return ft->fd;
}

int
fileSize(int fd)
{
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem locked to the thread
  //Searches and chks through the list of open files for the fd
  for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
  {
    ft = list_entry(e,struct file_info, elem);
    if(ft->fd == fd)
    {
      lock_release(&file_lock);//Filesystem released
      return file_length(ft->file);
    }
  }
  sys_exit();
}

int read(int fd, void *buffer, unsigned size)
{
  //If buffer or buffer size is invalid the process is terminated
  if(chk((uint8_t)buffer)== false || chk((uint8_t)size)== false)
  {
    sys_exit();
  }
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem is locked to the thread

  if(fd==STDIN_FILENO)
  {
    int count = *(int*)size;
    uint8_t c = input_getc();
    while(count > 1 & c != 0)
    {
      uint8_t c = input_getc();
      count--;
      buffer += c;
    }
    off_t bytes = size - count;
    lock_release(&file_lock);//Filesystem released
    return bytes;
  }
  //If worng fd is passed the process is terminated
  if(fd == STDOUT_FILENO)
  {
    off_t bytes = -1;
    lock_release(&file_lock);//Filesystem released
    return bytes;
  }
  else
  {
    //Searches and chks through the list of open files for the fd
    for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
    {
      ft = list_entry(e,struct file_info, elem);
      if(ft->fd == fd)
      {
        int bytes = file_read(ft->file,buffer,size);
        lock_release(&file_lock);//Filesystem released
        return bytes;
      }
    }
  }
}

int
write(int fd, const void *buffer, unsigned size)
{
  //If the buffer or buffer size is invalid the process is terminated
  if(chk((uint8_t)buffer)== false || chk((uint8_t)size)== false)
  {
    sys_exit();
  }
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  
  if(fd==STDOUT_FILENO){
    putbuf((const char*)buffer,(unsigned) size);
    lock_release(&file_lock);
    return;
  }
  else{
    if(fd==STDIN_FILENO)
    {
      printf("sys_write does not support fd output\n");
      lock_release(&file_lock);//releases filesystem.
      return -1;
    }
    else{
      //Searches and chks through the list of open files for the fd
      for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
      {
        ft = list_entry(e,struct file_info, elem);
        if(ft->fd == fd)
        {
          off_t bytes;
          bytes = file_write(ft->file,buffer,size);
          lock_release(&file_lock);//releases filesystem.
          return bytes;
        }
      }
    }
  }
}

void
seek(int fd, unsigned position)
{
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  //Open files are searched for descriptor
  for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
  {
    ft = list_entry(e,struct file_info, elem);
    if(ft->fd == fd)
    {
      file_seek(ft->file,position);
      lock_release(&file_lock);//Filesystem released
      return;
    }
  }
  sys_exit();
}

unsigned tell(int fd)
{
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  //Open files are searched for descriptor
  for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
  {
    ft = list_entry(e,struct file_info, elem);
    if(ft->fd == fd)
    {
      off_t offset = file_tell(ft->file);
      lock_release(&file_lock);//Filesystem released
      return;
    }
  }
  sys_exit();
}

void close(int fd)
{
  struct file_info *ft;
  struct list_elem *e;
  lock_acquire(&file_lock);//Filesystem is locked to the thread
  //Open files are searched for descriptor
  for(e = list_begin (&file_table); e != list_end (&file_table);e = list_next (e))
  {
    ft = list_entry(e,struct file_info, elem);
    if(ft->fd == fd)
    {
      file_close(ft->file);
      lock_release(&file_lock);//Filesystem released
      return;
    }
  }
  sys_exit();
}

int get_fd()
{
  size_t count = list_size(&file_table);//Open files are counted
  static int c = 2;
  return c;
}

static bool
chk(const uint8_t *uaddr)
{
  if(getUsr(uaddr) == -1)
  {
    return false;
  }
  else
  {
    return true;
  }
}

static int
getUsr (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return 0;
}


