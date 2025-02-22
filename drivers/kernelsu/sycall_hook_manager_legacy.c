// fn pointers
// sys_reboot
static long (*old_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_reboot(magic1, magic2, cmd, arg);
}

// execve
static long (*old_execve)(const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp);
static long hook_sys_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve_sucompat(NULL, &filename, NULL, NULL, NULL);
	return old_execve(filename, argv, envp);
}

// access
static long (*old_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_sys_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_faccessat(dfd, filename, mode);
}

// stat
static long (*old_newfstatat)(int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(int dfd, const char __user * filename, struct stat __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_newfstatat(dfd, filename, statbuf, flag);
}

#ifdef CONFIG_COMPAT
#define __NR_compat_execve 11
extern const unsigned long compat_sys_call_table[];
static long (*old_compat_execve)(const char __user * filename, const compat_uptr_t __user * argv, const compat_uptr_t __user * envp);
static long hook_compat_execve(const char __user * filename,
				const compat_uptr_t __user * argv,
				const compat_uptr_t __user * envp)
{
	ksu_handle_execve_sucompat(NULL, &filename, NULL, NULL, NULL);
	return old_compat_execve(filename, argv, envp);
}
#endif // CONFIG_COMPAT

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#define __NR_fstatat64 327
static long (*old_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag);
static long hook_sys_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_fstatat64(dfd, filename, statbuf, flag);
}
#endif // STAT64

extern const unsigned long sys_call_table[];
static void read_and_replace_syscall(void **old_ptr, unsigned long table, unsigned long syscall_nr, void *new_ptr)
{
	// *old_ptr = READ_ONCE(*((void **)table + syscall_nr));
	// WRITE_ONCE(*((void **)table + syscall_nr), new_ptr);

	// the one from zx2c4 looks like above, but the issue is that we dont have 
	// READ_ONCE and WRITE_ONCE on 3.x kernels, here we just force volatile everything
	// since those are actually just forced-aligned-volatile-rw

	void **syscall_addr = (void **)(table + syscall_nr);

	barrier();
	*old_ptr = *(volatile typeof(*syscall_addr) *)&(*syscall_addr);

	barrier();
	*(volatile typeof(*syscall_addr) *)&(*syscall_addr) = new_ptr;

	pr_info("syscall_slot: 0x%p syscall_addr: 0x%p \n", (void *)syscall_addr, (void *)*syscall_addr);	

}

void ksu_syscall_table_hook_init()
{
	preempt_disable();

	// reboot
	read_and_replace_syscall((void **)&old_reboot, sys_call_table, __NR_reboot, &hook_sys_reboot);

	// exec
	read_and_replace_syscall((void **)&old_execve, sys_call_table, __NR_execve, &hook_sys_execve);
#ifdef CONFIG_COMPAT
	read_and_replace_syscall((void **)&old_compat_execve, compat_sys_call_table, __NR_compat_execve, &hook_compat_execve);
#endif

	// access
	read_and_replace_syscall((void **)&old_faccessat, sys_call_table, __NR_faccessat, &hook_sys_faccessat);

	// newfstatat
	read_and_replace_syscall((void **)&old_newfstatat, sys_call_table, __NR_newfstatat, &hook_sys_newfstatat);

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	read_and_replace_syscall((void **)&old_fstatat64, sys_call_table, __NR_fstatat64, &hook_sys_fstatat64);
#endif

	preempt_enable();
}
