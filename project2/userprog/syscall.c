#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <devices/shutdown.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
# define max_syscall 20
# define USER_VADDR_BOUND (void*) 0x08048000
struct thread_file * find_file_id(int fd);
/* Our implementation for storing the array of system calls for Task2 and Task3 */
static void (*syscalls[max_syscall])(struct intr_frame *);
static void * check_ptr2(const void *vaddr);
static void exit_special (void);
struct thread_file * find_file_id(int fd);
/* Our implementation for Task2: syscall halt,exec,wait and practice */
void sys_halt(struct intr_frame* f); /* syscall halt. */
void sys_exit(struct intr_frame* f); /* syscall exit. */
void sys_exec(struct intr_frame* f); /* syscall exec. */

/* Our implementation for Task3: syscall create, remove, open, filesize, read, write, seek, tell, and close */
void sys_wait(struct intr_frame* f); /*syscall wait */
void sys_write(struct intr_frame* f); /* syscall write */

static void syscall_handler (struct intr_frame *);
/* New method to check the address and pages to pass test sc-bad-boundary2, execute */
/* Handle the special situation for thread */

void exit_special(void) {
  thread_current()->st_exit = -1;
  thread_exit();
}

/* Phương thức trong tài liệu để xử lý tình huống đặc biệt */
/* Đọc một byte tại địa chỉ ảo UADDR.
   UADDR phải thấp hơn PHYS_BASE.
   Nếu thành công, trả về giá trị byte; nếu xảy ra lỗi đoạn, trả về -1. */

static int 
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

void *check_ptr2(const void *vaddr) {
  /* Kiểm tra địa chỉ */
  if (!is_user_vaddr(vaddr)) {
    exit_special();
  }
  
  /* Kiểm tra trang */
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr) {
    exit_special();
  }

  /* Kiểm tra nội dung của trang */
  uint8_t *check_byteptr = (uint8_t *)vaddr;
  for (uint8_t i = 0; i < 4; i++) {
    if (get_user(check_byteptr + i) == -1) {
      exit_special();
    }
  }

  return ptr;
}





void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    /* Our implementation for Task2: initialize halt,exit,exec */
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
 
  // /* Our implementation for Task3: initialize create, remove, open, filesize, read, write, seek, tell, and close */
  syscalls[SYS_WAIT] = &sys_wait;
  syscalls[SYS_WRITE] = &sys_write;
}

/* Smplify the code to maintain the code more efficiently */
static void syscall_handler(struct intr_frame *f UNUSED) {
  /* Cho Bài tập 2, chỉ cần thêm 1 vào đối số đầu tiên của nó và in ra kết quả */
  int *p = f->esp;
  check_ptr2(p + 1);  // Kiểm tra đối số đầu tiên

  int type = *(int *)f->esp;  // Kiểm tra số hệ thống sys_code có hợp lệ không
  if (type <= 0 || type >= max_syscall) {
    exit_special();
  }
  syscalls[type](f);  // Nếu không có lỗi, thực hiện hàm hệ thống tương ứng
}

/* Our implementation for Task2: halt,exit,exec */
/* Do sytem halt */
void 
sys_halt (struct intr_frame* f)
{
  shutdown_power_off();
}

/* Thực hiện system exit */
void sys_exit(struct intr_frame *f) {
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);  // Kiểm tra địa chỉ của đối số đầu tiên
  *user_ptr++;  // Di chuyển con trỏ đến đối số đầu tiên
  /* Ghi nhận trạng thái thoát của quá trình */
  thread_current()->st_exit = *user_ptr;  // Lưu trạng thái thoát (exit_code)
  thread_exit();
}

/* Thực hiện system exec */
void sys_exec(struct intr_frame *f) {
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);  // Kiểm tra địa chỉ của đối số đầu tiên
  check_ptr2(*(user_ptr + 1));  // Kiểm tra giá trị của đối số đầu tiên, tức là địa chỉ mà const char *file trỏ đến
  *user_ptr++;  // Di chuyển con trỏ đến đối số thứ hai
  f->eax = process_execute((char *)*user_ptr);  // Sử dụng process_execute để thực hiện và trả về tid
}

/* Do sytem wait */
void 
sys_wait (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

/* Find file by the file's ID */
struct thread_file * 
find_file_id (int file_id)
{
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    if (file_id == thread_file_temp->fd)
      return thread_file_temp;
  }
  return false;
}
/* Do system write, Do writing in stdout and write in files */
void 
sys_write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 7);//for tests maybe?
  check_ptr2 (*(user_ptr + 6));
  *user_ptr++;
  int fd = *user_ptr;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (fd == 1) {//writes to the console
    /* Use putbuf to do testing */
    putbuf(buffer,size);
    f->eax = size;//return number written
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();//file operating needs lock
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f ();
    } 
    else
    {
      f->eax = 0;//can't write,return 0
    }
  }
}


/* Check is the user pointer is valid */
bool 
is_valid_pointer (void* esp,uint8_t argc){
  for (uint8_t i = 0; i < argc; ++i)
  {
    if((!is_user_vaddr (esp)) || 
      (pagedir_get_page (thread_current()->pagedir, esp)==NULL)){
      return false;
    }
  }
  return true;
}



