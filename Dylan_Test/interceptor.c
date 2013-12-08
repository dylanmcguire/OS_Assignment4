#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm-generic/syscall.h>

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*ref_sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*original_fork)(struct pt_regs);
asmlinkage long (*ref_sys_close)(unsigned int p);
int num_sys_read_calls = 0;
int num_sys_write_calls = 0;
int num_sys_open_calls = 0;
int num_sys_close_calls = 0;
int num_sys_fork_calls = 0;

asmlinkage long new_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
        
	num_sys_write_calls = num_sys_write_calls + 1;
	printk(KERN_INFO "Write intercepted: %i\n", num_sys_write_calls);
	
	return ref_sys_write(fd, buf, count);
} 

asmlinkage long new_sys_open(const char __user *filename, int flags, umode_t mode)
{
        
	num_sys_open_calls = num_sys_open_calls + 1;
	printk(KERN_INFO "Open intercepted: %i\n", num_sys_open_calls);
	
	return ref_sys_open(filename, flags, mode);
}

asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
        long ret;
        ret = ref_sys_read(fd, buf, count);
	
	num_sys_read_calls = num_sys_read_calls + 1;
	
        if(count == 1 && fd == 0)
                printk(KERN_INFO "Read intercepted: %i\n", num_sys_read_calls);

        return ret;
}

asmlinkage long new_fork(struct pt_regs regs)
{
  
    num_sys_fork_calls = num_sys_fork_calls + 1;
  
    printk(KERN_ALERT "Fork intercepted: %d\n", num_sys_fork_calls);
 
    return original_fork(regs);
}

asmlinkage long new_close(unsigned int p) {
   printk(KERN_ALERT "Intercepted close\n");
   
   num_sys_close_calls = num_sys_close_calls + 1;
   
   return ref_sys_close(p);
}


static unsigned long **aquire_sys_call_table(void)
{
        unsigned long int offset = PAGE_OFFSET;
        unsigned long **sct;

        while (offset < ULLONG_MAX) {
                sct = (unsigned long **)offset;

                if (sct[__NR_close] == (unsigned long *) sys_close) 
                        return sct;

                offset += sizeof(void *);
        }

        return NULL;
}

static void disable_page_protection(void) 
{
        unsigned long value;
        asm volatile("mov %%cr0, %0" : "=r" (value));

        if(!(value & 0x00010000))
                return;

        asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void) 
{
        unsigned long value;
        asm volatile("mov %%cr0, %0" : "=r" (value));

        if((value & 0x00010000))
                return;

        asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static int __init interceptor_start(void) 
{
        if(!(sys_call_table = aquire_sys_call_table()))
                return -1;

        disable_page_protection();
        ref_sys_open = (void *)sys_call_table[__NR_open];
        ref_sys_read = (void *)sys_call_table[__NR_read];
        ref_sys_write = (void *)sys_call_table[__NR_write];
	original_fork = (void *)sys_call_table[__NR_fork];
	ref_sys_close = (void *)sys_call_table[__NR_close];
        sys_call_table[__NR_open] = (unsigned long *)new_sys_open;
        sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
        sys_call_table[__NR_write] = (unsigned long *)new_sys_write;
	sys_call_table[__NR_fork] = (unsigned long *)new_fork;
	sys_call_table[__NR_close] = (unsigned long *)new_close;
        enable_page_protection();

        return 0;
}

static void __exit interceptor_end(void) 
{
        if(!sys_call_table)
                return;

        disable_page_protection();
        sys_call_table[__NR_open] = (unsigned long *)ref_sys_open;
        sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
        sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;
	sys_call_table[__NR_fork] = (unsigned long *)original_fork;
	sys_call_table[__NR_close] = (unsigned long *)ref_sys_close;
        enable_page_protection();
	
	printk(KERN_ALERT "Number of calls to sys_read: %d\n", num_sys_read_calls);
	printk(KERN_ALERT "Number of calls to sys_write: %d\n", num_sys_write_calls);
	printk(KERN_ALERT "Number of calls to sys_open: %d\n", num_sys_open_calls);
	printk(KERN_ALERT "Number of calls to sys_close: %d\n", num_sys_close_calls);
}

module_init(interceptor_start);
module_exit(interceptor_end);
