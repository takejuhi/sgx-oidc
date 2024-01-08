#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_run_session_t {
	sgx_status_t ms_retval;
	int ms_sock_fd;
} ms_run_session_t;

typedef struct ms_t_global_init_ecall_t {
	uint64_t ms_id;
	const uint8_t* ms_path;
	size_t ms_len;
} ms_t_global_init_ecall_t;

typedef struct ms_u_thread_set_event_ocall_t {
	int ms_retval;
	int* ms_error;
	const void* ms_tcs;
} ms_u_thread_set_event_ocall_t;

typedef struct ms_u_thread_wait_event_ocall_t {
	int ms_retval;
	int* ms_error;
	const void* ms_tcs;
	const struct timespec* ms_timeout;
} ms_u_thread_wait_event_ocall_t;

typedef struct ms_u_thread_set_multiple_events_ocall_t {
	int ms_retval;
	int* ms_error;
	const void** ms_tcss;
	int ms_total;
} ms_u_thread_set_multiple_events_ocall_t;

typedef struct ms_u_thread_setwait_events_ocall_t {
	int ms_retval;
	int* ms_error;
	const void* ms_waiter_tcs;
	const void* ms_self_tcs;
	const struct timespec* ms_timeout;
} ms_u_thread_setwait_events_ocall_t;

typedef struct ms_u_clock_gettime_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_clk_id;
	struct timespec* ms_tp;
} ms_u_clock_gettime_ocall_t;

typedef struct ms_u_read_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_read_ocall_t;

typedef struct ms_u_pread64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_pread64_ocall_t;

typedef struct ms_u_readv_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
} ms_u_readv_ocall_t;

typedef struct ms_u_preadv64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
	int64_t ms_offset;
} ms_u_preadv64_ocall_t;

typedef struct ms_u_write_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_u_write_ocall_t;

typedef struct ms_u_pwrite64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_pwrite64_ocall_t;

typedef struct ms_u_writev_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
} ms_u_writev_ocall_t;

typedef struct ms_u_pwritev64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
	int64_t ms_offset;
} ms_u_pwritev64_ocall_t;

typedef struct ms_u_sendfile_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_out_fd;
	int ms_in_fd;
	int64_t* ms_offset;
	size_t ms_count;
} ms_u_sendfile_ocall_t;

typedef struct ms_u_copy_file_range_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd_in;
	int64_t* ms_off_in;
	int ms_fd_out;
	int64_t* ms_off_out;
	size_t ms_len;
	unsigned int ms_flags;
} ms_u_copy_file_range_ocall_t;

typedef struct ms_u_splice_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd_in;
	int64_t* ms_off_in;
	int ms_fd_out;
	int64_t* ms_off_out;
	size_t ms_len;
	unsigned int ms_flags;
} ms_u_splice_ocall_t;

typedef struct ms_u_fcntl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
} ms_u_fcntl_arg0_ocall_t;

typedef struct ms_u_fcntl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_fcntl_arg1_ocall_t;

typedef struct ms_u_ioctl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
} ms_u_ioctl_arg0_ocall_t;

typedef struct ms_u_ioctl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
	int* ms_arg;
} ms_u_ioctl_arg1_ocall_t;

typedef struct ms_u_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_close_ocall_t;

typedef struct ms_u_isatty_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_isatty_ocall_t;

typedef struct ms_u_dup_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_oldfd;
} ms_u_dup_ocall_t;

typedef struct ms_u_eventfd_ocall_t {
	int ms_retval;
	int* ms_error;
	unsigned int ms_initval;
	int ms_flags;
} ms_u_eventfd_ocall_t;

typedef struct ms_u_futimens_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	const struct timespec* ms_times;
} ms_u_futimens_ocall_t;

typedef struct ms_u_malloc_ocall_t {
	void* ms_retval;
	int* ms_error;
	size_t ms_size;
} ms_u_malloc_ocall_t;

typedef struct ms_u_free_ocall_t {
	void* ms_p;
} ms_u_free_ocall_t;

typedef struct ms_u_mmap_ocall_t {
	void* ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
	int ms_prot;
	int ms_flags;
	int ms_fd;
	int64_t ms_offset;
} ms_u_mmap_ocall_t;

typedef struct ms_u_munmap_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
} ms_u_munmap_ocall_t;

typedef struct ms_u_msync_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_addr;
	size_t ms_length;
	int ms_flags;
} ms_u_msync_ocall_t;

typedef struct ms_u_mprotect_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_addr;
	size_t ms_length;
	int ms_prot;
} ms_u_mprotect_ocall_t;

typedef struct ms_u_open_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
	int ms_flags;
} ms_u_open_ocall_t;

typedef struct ms_u_open64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	int ms_oflag;
	int ms_mode;
} ms_u_open64_ocall_t;

typedef struct ms_u_openat_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
} ms_u_openat_ocall_t;

typedef struct ms_u_fstat_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	struct stat_t* ms_buf;
} ms_u_fstat_ocall_t;

typedef struct ms_u_fstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	struct stat64_t* ms_buf;
} ms_u_fstat64_ocall_t;

typedef struct ms_u_stat_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat_t* ms_buf;
} ms_u_stat_ocall_t;

typedef struct ms_u_stat64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_stat64_ocall_t;

typedef struct ms_u_lstat_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat_t* ms_buf;
} ms_u_lstat_ocall_t;

typedef struct ms_u_lstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_lstat64_ocall_t;

typedef struct ms_u_lseek_ocall_t {
	uint64_t ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_offset;
	int ms_whence;
} ms_u_lseek_ocall_t;

typedef struct ms_u_lseek64_ocall_t {
	int64_t ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_offset;
	int ms_whence;
} ms_u_lseek64_ocall_t;

typedef struct ms_u_ftruncate_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_length;
} ms_u_ftruncate_ocall_t;

typedef struct ms_u_ftruncate64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_length;
} ms_u_ftruncate64_ocall_t;

typedef struct ms_u_truncate_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	int64_t ms_length;
} ms_u_truncate_ocall_t;

typedef struct ms_u_truncate64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	int64_t ms_length;
} ms_u_truncate64_ocall_t;

typedef struct ms_u_fsync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fsync_ocall_t;

typedef struct ms_u_fdatasync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fdatasync_ocall_t;

typedef struct ms_u_fchmod_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	uint32_t ms_mode;
} ms_u_fchmod_ocall_t;

typedef struct ms_u_unlink_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_unlink_ocall_t;

typedef struct ms_u_link_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_link_ocall_t;

typedef struct ms_u_unlinkat_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
} ms_u_unlinkat_ocall_t;

typedef struct ms_u_linkat_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_olddirfd;
	const char* ms_oldpath;
	int ms_newdirfd;
	const char* ms_newpath;
	int ms_flags;
} ms_u_linkat_ocall_t;

typedef struct ms_u_rename_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_rename_ocall_t;

typedef struct ms_u_chmod_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	uint32_t ms_mode;
} ms_u_chmod_ocall_t;

typedef struct ms_u_readlink_ocall_t {
	size_t ms_retval;
	int* ms_error;
	const char* ms_path;
	char* ms_buf;
	size_t ms_bufsz;
} ms_u_readlink_ocall_t;

typedef struct ms_u_symlink_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path1;
	const char* ms_path2;
} ms_u_symlink_ocall_t;

typedef struct ms_u_realpath_ocall_t {
	char* ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_realpath_ocall_t;

typedef struct ms_u_mkdir_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
	uint32_t ms_mode;
} ms_u_mkdir_ocall_t;

typedef struct ms_u_rmdir_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_rmdir_ocall_t;

typedef struct ms_u_fdopendir_ocall_t {
	void* ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fdopendir_ocall_t;

typedef struct ms_u_opendir_ocall_t {
	void* ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_opendir_ocall_t;

typedef struct ms_u_readdir64_r_ocall_t {
	int ms_retval;
	void* ms_dirp;
	struct dirent64_t* ms_entry;
	struct dirent64_t** ms_result;
} ms_u_readdir64_r_ocall_t;

typedef struct ms_u_closedir_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_dirp;
} ms_u_closedir_ocall_t;

typedef struct ms_u_dirfd_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_dirp;
} ms_u_dirfd_ocall_t;

typedef struct ms_u_fstatat64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_dirfd;
	const char* ms_pathname;
	struct stat64_t* ms_buf;
	int ms_flags;
} ms_u_fstatat64_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_getaddrinfo_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_node;
	const char* ms_service;
	const struct addrinfo* ms_hints;
	struct addrinfo** ms_res;
} ms_u_getaddrinfo_ocall_t;

typedef struct ms_u_freeaddrinfo_ocall_t {
	struct addrinfo* ms_res;
} ms_u_freeaddrinfo_ocall_t;

typedef struct ms_u_gai_strerror_ocall_t {
	char* ms_retval;
	int ms_errcode;
} ms_u_gai_strerror_ocall_t;

typedef struct ms_u_socket_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_domain;
	int ms_ty;
	int ms_protocol;
} ms_u_socket_ocall_t;

typedef struct ms_u_socketpair_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_domain;
	int ms_ty;
	int ms_protocol;
	int* ms_sv;
} ms_u_socketpair_ocall_t;

typedef struct ms_u_bind_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	const struct sockaddr* ms_addr;
	socklen_t ms_addrlen;
} ms_u_bind_ocall_t;

typedef struct ms_u_listen_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_backlog;
} ms_u_listen_ocall_t;

typedef struct ms_u_accept_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_accept_ocall_t;

typedef struct ms_u_accept4_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
	int ms_flags;
} ms_u_accept4_ocall_t;

typedef struct ms_u_connect_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	const struct sockaddr* ms_addr;
	socklen_t ms_addrlen;
} ms_u_connect_ocall_t;

typedef struct ms_u_recv_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_u_recv_ocall_t;

typedef struct ms_u_recvfrom_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
	struct sockaddr* ms_src_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_recvfrom_ocall_t;

typedef struct ms_u_recvmsg_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	void* ms_msg_name;
	socklen_t ms_msg_namelen;
	socklen_t* ms_msg_namelen_out;
	struct iovec* ms_msg_iov;
	size_t ms_msg_iovlen;
	void* ms_msg_control;
	size_t ms_msg_controllen;
	size_t* ms_msg_controllen_out;
	int* ms_msg_flags;
	int ms_flags;
} ms_u_recvmsg_ocall_t;

typedef struct ms_u_send_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_u_send_ocall_t;

typedef struct ms_u_sendto_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
	const struct sockaddr* ms_dest_addr;
	socklen_t ms_addrlen;
} ms_u_sendto_ocall_t;

typedef struct ms_u_sendmsg_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	const void* ms_msg_name;
	socklen_t ms_msg_namelen;
	const struct iovec* ms_msg_iov;
	size_t ms_msg_iovlen;
	const void* ms_msg_control;
	size_t ms_msg_controllen;
	int ms_flags;
} ms_u_sendmsg_ocall_t;

typedef struct ms_u_getsockopt_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	socklen_t ms_optlen_in;
	socklen_t* ms_optlen_out;
} ms_u_getsockopt_ocall_t;

typedef struct ms_u_setsockopt_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	socklen_t ms_optlen;
} ms_u_setsockopt_ocall_t;

typedef struct ms_u_getsockname_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_getsockname_ocall_t;

typedef struct ms_u_getpeername_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_getpeername_ocall_t;

typedef struct ms_u_shutdown_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_how;
} ms_u_shutdown_ocall_t;

typedef struct ms_u_poll_ocall_t {
	int ms_retval;
	int* ms_error;
	struct pollfd* ms_fds;
	nfds_t ms_nfds;
	int ms_timeout;
} ms_u_poll_ocall_t;

typedef struct ms_u_epoll_create1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_flags;
} ms_u_epoll_create1_ocall_t;

typedef struct ms_u_epoll_ctl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_epfd;
	int ms_op;
	int ms_fd;
	struct epoll_event* ms_event;
} ms_u_epoll_ctl_ocall_t;

typedef struct ms_u_epoll_wait_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_epfd;
	struct epoll_event* ms_events;
	int ms_maxevents;
	int ms_timeout;
} ms_u_epoll_wait_ocall_t;

typedef struct ms_u_environ_ocall_t {
	char** ms_retval;
} ms_u_environ_ocall_t;

typedef struct ms_u_getenv_ocall_t {
	char* ms_retval;
	const char* ms_name;
} ms_u_getenv_ocall_t;

typedef struct ms_u_setenv_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_name;
	const char* ms_value;
	int ms_overwrite;
} ms_u_setenv_ocall_t;

typedef struct ms_u_unsetenv_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_name;
} ms_u_unsetenv_ocall_t;

typedef struct ms_u_chdir_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_dir;
} ms_u_chdir_ocall_t;

typedef struct ms_u_getcwd_ocall_t {
	char* ms_retval;
	int* ms_error;
	char* ms_buf;
	size_t ms_buflen;
} ms_u_getcwd_ocall_t;

typedef struct ms_u_getpwuid_r_ocall_t {
	int ms_retval;
	unsigned int ms_uid;
	struct passwd* ms_pwd;
	char* ms_buf;
	size_t ms_buflen;
	struct passwd** ms_passwd_result;
} ms_u_getpwuid_r_ocall_t;

typedef struct ms_u_getuid_ocall_t {
	unsigned int ms_retval;
} ms_u_getuid_ocall_t;

static sgx_status_t SGX_CDECL sgx_run_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_run_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_run_session_t* ms = SGX_CAST(ms_run_session_t*, pms);
	ms_run_session_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_run_session_t), ms, sizeof(ms_run_session_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = run_session(__in_ms.ms_sock_fd);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_init_ecall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_global_init_ecall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_global_init_ecall_t* ms = SGX_CAST(ms_t_global_init_ecall_t*, pms);
	ms_t_global_init_ecall_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_t_global_init_ecall_t), ms, sizeof(ms_t_global_init_ecall_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_path = __in_ms.ms_path;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_path = _tmp_len;
	uint8_t* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_path != NULL && _len_path != 0) {
		if ( _len_path % sizeof(*_tmp_path) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_path = (uint8_t*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	t_global_init_ecall(__in_ms.ms_id, (const uint8_t*)_in_path, _tmp_len);

err:
	if (_in_path) free(_in_path);
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_exit_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_global_exit_ecall();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_run_session, 0, 0},
		{(void*)(uintptr_t)sgx_t_global_init_ecall, 0, 0},
		{(void*)(uintptr_t)sgx_t_global_exit_ecall, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[104][3];
} g_dyn_entry_table = {
	104,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_thread_set_event_ocall(int* retval, int* error, const void* tcs)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_thread_set_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_thread_set_event_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_thread_set_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_thread_set_event_ocall_t));
	ocalloc_size -= sizeof(ms_u_thread_set_event_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_tcs, sizeof(ms->ms_tcs), &tcs, sizeof(tcs))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_thread_wait_event_ocall(int* retval, int* error, const void* tcs, const struct timespec* timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_timeout = sizeof(struct timespec);

	ms_u_thread_wait_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_thread_wait_event_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(timeout, _len_timeout);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeout != NULL) ? _len_timeout : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_thread_wait_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_thread_wait_event_ocall_t));
	ocalloc_size -= sizeof(ms_u_thread_wait_event_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_tcs, sizeof(ms->ms_tcs), &tcs, sizeof(tcs))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (timeout != NULL) {
		if (memcpy_verw_s(&ms->ms_timeout, sizeof(const struct timespec*), &__tmp, sizeof(const struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, timeout, _len_timeout)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_timeout);
		ocalloc_size -= _len_timeout;
	} else {
		ms->ms_timeout = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_thread_set_multiple_events_ocall(int* retval, int* error, const void** tcss, int total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_tcss = total * sizeof(void*);

	ms_u_thread_set_multiple_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_thread_set_multiple_events_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(tcss, _len_tcss);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tcss != NULL) ? _len_tcss : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_thread_set_multiple_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_thread_set_multiple_events_ocall_t));
	ocalloc_size -= sizeof(ms_u_thread_set_multiple_events_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (tcss != NULL) {
		if (memcpy_verw_s(&ms->ms_tcss, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_tcss % sizeof(*tcss) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, tcss, _len_tcss)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_tcss);
		ocalloc_size -= _len_tcss;
	} else {
		ms->ms_tcss = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_thread_setwait_events_ocall(int* retval, int* error, const void* waiter_tcs, const void* self_tcs, const struct timespec* timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_timeout = sizeof(struct timespec);

	ms_u_thread_setwait_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_thread_setwait_events_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(timeout, _len_timeout);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeout != NULL) ? _len_timeout : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_thread_setwait_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_thread_setwait_events_ocall_t));
	ocalloc_size -= sizeof(ms_u_thread_setwait_events_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_waiter_tcs, sizeof(ms->ms_waiter_tcs), &waiter_tcs, sizeof(waiter_tcs))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self_tcs, sizeof(ms->ms_self_tcs), &self_tcs, sizeof(self_tcs))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (timeout != NULL) {
		if (memcpy_verw_s(&ms->ms_timeout, sizeof(const struct timespec*), &__tmp, sizeof(const struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, timeout, _len_timeout)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_timeout);
		ocalloc_size -= _len_timeout;
	} else {
		ms->ms_timeout = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_clock_gettime_ocall(int* retval, int* error, int clk_id, struct timespec* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_tp = sizeof(struct timespec);

	ms_u_clock_gettime_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_clock_gettime_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_tp = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(tp, _len_tp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tp != NULL) ? _len_tp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_clock_gettime_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_clock_gettime_ocall_t));
	ocalloc_size -= sizeof(ms_u_clock_gettime_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_clk_id, sizeof(ms->ms_clk_id), &clk_id, sizeof(clk_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (tp != NULL) {
		if (memcpy_verw_s(&ms->ms_tp, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_tp = __tmp;
		memset_verw(__tmp_tp, 0, _len_tp);
		__tmp = (void *)((size_t)__tmp + _len_tp);
		ocalloc_size -= _len_tp;
	} else {
		ms->ms_tp = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tp) {
			if (memcpy_s((void*)tp, _len_tp, __tmp_tp, _len_tp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_read_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_read_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_read_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_read_ocall_t));
	ocalloc_size -= sizeof(ms_u_read_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_pread64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pread64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pread64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pread64_ocall_t));
	ocalloc_size -= sizeof(ms_u_pread64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readv_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_iov = iovcnt * sizeof(struct iovec);

	ms_u_readv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readv_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readv_ocall_t));
	ocalloc_size -= sizeof(ms_u_readv_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(const struct iovec*), &__tmp, sizeof(const struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, iov, _len_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_preadv64_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_iov = iovcnt * sizeof(struct iovec);

	ms_u_preadv64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_preadv64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_preadv64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_preadv64_ocall_t));
	ocalloc_size -= sizeof(ms_u_preadv64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(const struct iovec*), &__tmp, sizeof(const struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, iov, _len_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_write_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_write_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_write_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_write_ocall_t));
	ocalloc_size -= sizeof(ms_u_write_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_pwrite64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pwrite64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pwrite64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pwrite64_ocall_t));
	ocalloc_size -= sizeof(ms_u_pwrite64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_writev_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_iov = iovcnt * sizeof(struct iovec);

	ms_u_writev_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_writev_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_writev_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_writev_ocall_t));
	ocalloc_size -= sizeof(ms_u_writev_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(const struct iovec*), &__tmp, sizeof(const struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, iov, _len_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pwritev64_ocall(size_t* retval, int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_iov = iovcnt * sizeof(struct iovec);

	ms_u_pwritev64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pwritev64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pwritev64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pwritev64_ocall_t));
	ocalloc_size -= sizeof(ms_u_pwritev64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(const struct iovec*), &__tmp, sizeof(const struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, iov, _len_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sendfile_ocall(size_t* retval, int* error, int out_fd, int in_fd, int64_t* offset, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_offset = sizeof(int64_t);

	ms_u_sendfile_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sendfile_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_offset = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(offset, _len_offset);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (offset != NULL) ? _len_offset : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sendfile_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sendfile_ocall_t));
	ocalloc_size -= sizeof(ms_u_sendfile_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_out_fd, sizeof(ms->ms_out_fd), &out_fd, sizeof(out_fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_in_fd, sizeof(ms->ms_in_fd), &in_fd, sizeof(in_fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (offset != NULL) {
		if (memcpy_verw_s(&ms->ms_offset, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_offset = __tmp;
		if (_len_offset % sizeof(*offset) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, offset, _len_offset)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_offset);
		ocalloc_size -= _len_offset;
	} else {
		ms->ms_offset = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (offset) {
			if (memcpy_s((void*)offset, _len_offset, __tmp_offset, _len_offset)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_copy_file_range_ocall(size_t* retval, int* error, int fd_in, int64_t* off_in, int fd_out, int64_t* off_out, size_t len, unsigned int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_off_in = sizeof(int64_t);
	size_t _len_off_out = sizeof(int64_t);

	ms_u_copy_file_range_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_copy_file_range_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_off_in = NULL;
	void *__tmp_off_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(off_in, _len_off_in);
	CHECK_ENCLAVE_POINTER(off_out, _len_off_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (off_in != NULL) ? _len_off_in : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (off_out != NULL) ? _len_off_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_copy_file_range_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_copy_file_range_ocall_t));
	ocalloc_size -= sizeof(ms_u_copy_file_range_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd_in, sizeof(ms->ms_fd_in), &fd_in, sizeof(fd_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (off_in != NULL) {
		if (memcpy_verw_s(&ms->ms_off_in, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_off_in = __tmp;
		if (_len_off_in % sizeof(*off_in) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, off_in, _len_off_in)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_off_in);
		ocalloc_size -= _len_off_in;
	} else {
		ms->ms_off_in = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd_out, sizeof(ms->ms_fd_out), &fd_out, sizeof(fd_out))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (off_out != NULL) {
		if (memcpy_verw_s(&ms->ms_off_out, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_off_out = __tmp;
		if (_len_off_out % sizeof(*off_out) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, off_out, _len_off_out)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_off_out);
		ocalloc_size -= _len_off_out;
	} else {
		ms->ms_off_out = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (off_in) {
			if (memcpy_s((void*)off_in, _len_off_in, __tmp_off_in, _len_off_in)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (off_out) {
			if (memcpy_s((void*)off_out, _len_off_out, __tmp_off_out, _len_off_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_splice_ocall(size_t* retval, int* error, int fd_in, int64_t* off_in, int fd_out, int64_t* off_out, size_t len, unsigned int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_off_in = sizeof(int64_t);
	size_t _len_off_out = sizeof(int64_t);

	ms_u_splice_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_splice_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_off_in = NULL;
	void *__tmp_off_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(off_in, _len_off_in);
	CHECK_ENCLAVE_POINTER(off_out, _len_off_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (off_in != NULL) ? _len_off_in : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (off_out != NULL) ? _len_off_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_splice_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_splice_ocall_t));
	ocalloc_size -= sizeof(ms_u_splice_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd_in, sizeof(ms->ms_fd_in), &fd_in, sizeof(fd_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (off_in != NULL) {
		if (memcpy_verw_s(&ms->ms_off_in, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_off_in = __tmp;
		if (_len_off_in % sizeof(*off_in) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, off_in, _len_off_in)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_off_in);
		ocalloc_size -= _len_off_in;
	} else {
		ms->ms_off_in = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd_out, sizeof(ms->ms_fd_out), &fd_out, sizeof(fd_out))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (off_out != NULL) {
		if (memcpy_verw_s(&ms->ms_off_out, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_off_out = __tmp;
		if (_len_off_out % sizeof(*off_out) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, off_out, _len_off_out)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_off_out);
		ocalloc_size -= _len_off_out;
	} else {
		ms->ms_off_out = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (off_in) {
			if (memcpy_s((void*)off_in, _len_off_in, __tmp_off_in, _len_off_in)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (off_out) {
			if (memcpy_s((void*)off_out, _len_off_out, __tmp_off_out, _len_off_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fcntl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fcntl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fcntl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fcntl_arg0_ocall_t));
	ocalloc_size -= sizeof(ms_u_fcntl_arg0_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_cmd, sizeof(ms->ms_cmd), &cmd, sizeof(cmd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fcntl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fcntl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fcntl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fcntl_arg1_ocall_t));
	ocalloc_size -= sizeof(ms_u_fcntl_arg1_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_cmd, sizeof(ms->ms_cmd), &cmd, sizeof(cmd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_arg, sizeof(ms->ms_arg), &arg, sizeof(arg))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ioctl_arg0_ocall(int* retval, int* error, int fd, int request)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_ioctl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ioctl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ioctl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ioctl_arg0_ocall_t));
	ocalloc_size -= sizeof(ms_u_ioctl_arg0_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_request, sizeof(ms->ms_request), &request, sizeof(request))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_arg = sizeof(int);

	ms_u_ioctl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ioctl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_arg = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(arg, _len_arg);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (arg != NULL) ? _len_arg : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ioctl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ioctl_arg1_ocall_t));
	ocalloc_size -= sizeof(ms_u_ioctl_arg1_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_request, sizeof(ms->ms_request), &request, sizeof(request))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (arg != NULL) {
		if (memcpy_verw_s(&ms->ms_arg, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_arg = __tmp;
		if (_len_arg % sizeof(*arg) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, arg, _len_arg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_arg);
		ocalloc_size -= _len_arg;
	} else {
		ms->ms_arg = NULL;
	}

	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (arg) {
			if (memcpy_s((void*)arg, _len_arg, __tmp_arg, _len_arg)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_close_ocall_t));
	ocalloc_size -= sizeof(ms_u_close_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_isatty_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_isatty_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_isatty_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_isatty_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_isatty_ocall_t));
	ocalloc_size -= sizeof(ms_u_isatty_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_dup_ocall(int* retval, int* error, int oldfd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_dup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_dup_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_dup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_dup_ocall_t));
	ocalloc_size -= sizeof(ms_u_dup_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_oldfd, sizeof(ms->ms_oldfd), &oldfd, sizeof(oldfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_eventfd_ocall(int* retval, int* error, unsigned int initval, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_eventfd_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_eventfd_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_eventfd_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_eventfd_ocall_t));
	ocalloc_size -= sizeof(ms_u_eventfd_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_initval, sizeof(ms->ms_initval), &initval, sizeof(initval))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_futimens_ocall(int* retval, int* error, int fd, const struct timespec* times)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_times = 2 * sizeof(struct timespec);

	ms_u_futimens_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_futimens_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(times, _len_times);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (times != NULL) ? _len_times : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_futimens_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_futimens_ocall_t));
	ocalloc_size -= sizeof(ms_u_futimens_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (times != NULL) {
		if (memcpy_verw_s(&ms->ms_times, sizeof(const struct timespec*), &__tmp, sizeof(const struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, times, _len_times)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_times);
		ocalloc_size -= _len_times;
	} else {
		ms->ms_times = NULL;
	}

	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_malloc_ocall(void** retval, int* error, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_malloc_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_malloc_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_malloc_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_malloc_ocall_t));
	ocalloc_size -= sizeof(ms_u_malloc_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_free_ocall(void* p)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_free_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_free_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_free_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_free_ocall_t));
	ocalloc_size -= sizeof(ms_u_free_ocall_t);

	if (memcpy_verw_s(&ms->ms_p, sizeof(ms->ms_p), &p, sizeof(p))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_mmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_mmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_mmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_mmap_ocall_t));
	ocalloc_size -= sizeof(ms_u_mmap_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_start, sizeof(ms->ms_start), &start, sizeof(start))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_prot, sizeof(ms->ms_prot), &prot, sizeof(prot))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_munmap_ocall(int* retval, int* error, void* start, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_munmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_munmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_munmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_munmap_ocall_t));
	ocalloc_size -= sizeof(ms_u_munmap_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_start, sizeof(ms->ms_start), &start, sizeof(start))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_msync_ocall(int* retval, int* error, void* addr, size_t length, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_msync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_msync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_msync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_msync_ocall_t));
	ocalloc_size -= sizeof(ms_u_msync_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addr, sizeof(ms->ms_addr), &addr, sizeof(addr))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_mprotect_ocall(int* retval, int* error, void* addr, size_t length, int prot)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_mprotect_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_mprotect_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_mprotect_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_mprotect_ocall_t));
	ocalloc_size -= sizeof(ms_u_mprotect_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addr, sizeof(ms->ms_addr), &addr, sizeof(addr))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_prot, sizeof(ms->ms_prot), &prot, sizeof(prot))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_open_ocall(int* retval, int* error, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_open_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_open_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_open_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_open_ocall_t));
	ocalloc_size -= sizeof(ms_u_open_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_open64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_open64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_open64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_open64_ocall_t));
	ocalloc_size -= sizeof(ms_u_open64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_oflag, sizeof(ms->ms_oflag), &oflag, sizeof(oflag))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_openat_ocall(int* retval, int* error, int dirfd, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_openat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_openat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_openat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_openat_ocall_t));
	ocalloc_size -= sizeof(ms_u_openat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dirfd, sizeof(ms->ms_dirfd), &dirfd, sizeof(dirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fstat_ocall(int* retval, int* error, int fd, struct stat_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = sizeof(struct stat_t);

	ms_u_fstat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fstat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fstat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fstat_ocall_t));
	ocalloc_size -= sizeof(ms_u_fstat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat_t*), &__tmp, sizeof(struct stat_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_fstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fstat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fstat64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat64_t*), &__tmp, sizeof(struct stat64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stat_ocall(int* retval, int* error, const char* path, struct stat_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat_t);

	ms_u_stat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stat_ocall_t));
	ocalloc_size -= sizeof(ms_u_stat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat_t*), &__tmp, sizeof(struct stat_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_stat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_stat64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat64_t*), &__tmp, sizeof(struct stat64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lstat_ocall(int* retval, int* error, const char* path, struct stat_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat_t);

	ms_u_lstat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lstat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lstat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lstat_ocall_t));
	ocalloc_size -= sizeof(ms_u_lstat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat_t*), &__tmp, sizeof(struct stat_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_lstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lstat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_lstat64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat64_t*), &__tmp, sizeof(struct stat64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lseek_ocall(uint64_t* retval, int* error, int fd, int64_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_lseek_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lseek_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lseek_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lseek_ocall_t));
	ocalloc_size -= sizeof(ms_u_lseek_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_whence, sizeof(ms->ms_whence), &whence, sizeof(whence))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_lseek64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lseek64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lseek64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lseek64_ocall_t));
	ocalloc_size -= sizeof(ms_u_lseek64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_whence, sizeof(ms->ms_whence), &whence, sizeof(whence))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(41, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ftruncate_ocall(int* retval, int* error, int fd, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_ftruncate_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ftruncate_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ftruncate_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ftruncate_ocall_t));
	ocalloc_size -= sizeof(ms_u_ftruncate_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(42, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_ftruncate64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ftruncate64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ftruncate64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ftruncate64_ocall_t));
	ocalloc_size -= sizeof(ms_u_ftruncate64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(43, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_truncate_ocall(int* retval, int* error, const char* path, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_truncate_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_truncate_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_truncate_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_truncate_ocall_t));
	ocalloc_size -= sizeof(ms_u_truncate_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(44, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_truncate64_ocall(int* retval, int* error, const char* path, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_truncate64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_truncate64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_truncate64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_truncate64_ocall_t));
	ocalloc_size -= sizeof(ms_u_truncate64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(45, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fsync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fsync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fsync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fsync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fsync_ocall_t));
	ocalloc_size -= sizeof(ms_u_fsync_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(46, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fdatasync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fdatasync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fdatasync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fdatasync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fdatasync_ocall_t));
	ocalloc_size -= sizeof(ms_u_fdatasync_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(47, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fchmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fchmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fchmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fchmod_ocall_t));
	ocalloc_size -= sizeof(ms_u_fchmod_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(48, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_unlink_ocall(int* retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_unlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_unlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_unlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_unlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_unlink_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(49, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_link_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_link_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_link_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_link_ocall_t));
	ocalloc_size -= sizeof(ms_u_link_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (oldpath != NULL) {
		if (memcpy_verw_s(&ms->ms_oldpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}

	if (newpath != NULL) {
		if (memcpy_verw_s(&ms->ms_newpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}

	status = sgx_ocall(50, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_unlinkat_ocall(int* retval, int* error, int dirfd, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_unlinkat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_unlinkat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_unlinkat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_unlinkat_ocall_t));
	ocalloc_size -= sizeof(ms_u_unlinkat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dirfd, sizeof(ms->ms_dirfd), &dirfd, sizeof(dirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(51, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_linkat_ocall(int* retval, int* error, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_linkat_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_linkat_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_linkat_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_linkat_ocall_t));
	ocalloc_size -= sizeof(ms_u_linkat_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_olddirfd, sizeof(ms->ms_olddirfd), &olddirfd, sizeof(olddirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (oldpath != NULL) {
		if (memcpy_verw_s(&ms->ms_oldpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}

	if (memcpy_verw_s(&ms->ms_newdirfd, sizeof(ms->ms_newdirfd), &newdirfd, sizeof(newdirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (newpath != NULL) {
		if (memcpy_verw_s(&ms->ms_newpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(52, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_rename_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rename_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rename_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rename_ocall_t));
	ocalloc_size -= sizeof(ms_u_rename_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (oldpath != NULL) {
		if (memcpy_verw_s(&ms->ms_oldpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}

	if (newpath != NULL) {
		if (memcpy_verw_s(&ms->ms_newpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}

	status = sgx_ocall(53, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_chmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_chmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_chmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_chmod_ocall_t));
	ocalloc_size -= sizeof(ms_u_chmod_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(54, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = bufsz;

	ms_u_readlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_readlink_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_bufsz, sizeof(ms->ms_bufsz), &bufsz, sizeof(bufsz))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(55, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_symlink_ocall(int* retval, int* error, const char* path1, const char* path2)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path1 = path1 ? strlen(path1) + 1 : 0;
	size_t _len_path2 = path2 ? strlen(path2) + 1 : 0;

	ms_u_symlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_symlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path1, _len_path1);
	CHECK_ENCLAVE_POINTER(path2, _len_path2);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path1 != NULL) ? _len_path1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path2 != NULL) ? _len_path2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_symlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_symlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_symlink_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (path1 != NULL) {
		if (memcpy_verw_s(&ms->ms_path1, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path1 % sizeof(*path1) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path1, _len_path1)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path1);
		ocalloc_size -= _len_path1;
	} else {
		ms->ms_path1 = NULL;
	}

	if (path2 != NULL) {
		if (memcpy_verw_s(&ms->ms_path2, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path2 % sizeof(*path2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path2, _len_path2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path2);
		ocalloc_size -= _len_path2;
	} else {
		ms->ms_path2 = NULL;
	}

	status = sgx_ocall(56, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_realpath_ocall(char** retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_realpath_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_realpath_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_realpath_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_realpath_ocall_t));
	ocalloc_size -= sizeof(ms_u_realpath_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(57, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_mkdir_ocall(int* retval, int* error, const char* pathname, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_mkdir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_mkdir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_mkdir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_mkdir_ocall_t));
	ocalloc_size -= sizeof(ms_u_mkdir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(58, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rmdir_ocall(int* retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_rmdir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rmdir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rmdir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rmdir_ocall_t));
	ocalloc_size -= sizeof(ms_u_rmdir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(59, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fdopendir_ocall(void** retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fdopendir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fdopendir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fdopendir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fdopendir_ocall_t));
	ocalloc_size -= sizeof(ms_u_fdopendir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(60, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_opendir_ocall(void** retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_opendir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_opendir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_opendir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_opendir_ocall_t));
	ocalloc_size -= sizeof(ms_u_opendir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(61, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readdir64_r_ocall(int* retval, void* dirp, struct dirent64_t* entry, struct dirent64_t** result)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_entry = sizeof(struct dirent64_t);
	size_t _len_result = sizeof(struct dirent64_t*);

	ms_u_readdir64_r_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readdir64_r_ocall_t);
	void *__tmp = NULL;

	void *__tmp_entry = NULL;
	void *__tmp_result = NULL;

	CHECK_ENCLAVE_POINTER(entry, _len_entry);
	CHECK_ENCLAVE_POINTER(result, _len_result);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (entry != NULL) ? _len_entry : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (result != NULL) ? _len_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readdir64_r_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readdir64_r_ocall_t));
	ocalloc_size -= sizeof(ms_u_readdir64_r_ocall_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (entry != NULL) {
		if (memcpy_verw_s(&ms->ms_entry, sizeof(struct dirent64_t*), &__tmp, sizeof(struct dirent64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_entry = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, entry, _len_entry)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_entry);
		ocalloc_size -= _len_entry;
	} else {
		ms->ms_entry = NULL;
	}

	if (result != NULL) {
		if (memcpy_verw_s(&ms->ms_result, sizeof(struct dirent64_t**), &__tmp, sizeof(struct dirent64_t**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_result = __tmp;
		if (_len_result % sizeof(*result) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_result, 0, _len_result);
		__tmp = (void *)((size_t)__tmp + _len_result);
		ocalloc_size -= _len_result;
	} else {
		ms->ms_result = NULL;
	}

	status = sgx_ocall(62, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (entry) {
			if (memcpy_s((void*)entry, _len_entry, __tmp_entry, _len_entry)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (result) {
			if (memcpy_s((void*)result, _len_result, __tmp_result, _len_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_closedir_ocall(int* retval, int* error, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_closedir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_closedir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_closedir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_closedir_ocall_t));
	ocalloc_size -= sizeof(ms_u_closedir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(63, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_dirfd_ocall(int* retval, int* error, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_dirfd_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_dirfd_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_dirfd_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_dirfd_ocall_t));
	ocalloc_size -= sizeof(ms_u_dirfd_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(64, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fstatat64_ocall(int* retval, int* error, int dirfd, const char* pathname, struct stat64_t* buf, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_fstatat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fstatat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fstatat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fstatat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fstatat64_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_dirfd, sizeof(ms->ms_dirfd), &dirfd, sizeof(dirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat64_t*), &__tmp, sizeof(struct stat64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(65, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(66, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(67, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(68, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(69, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(70, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getaddrinfo_ocall(int* retval, int* error, const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_node = node ? strlen(node) + 1 : 0;
	size_t _len_service = service ? strlen(service) + 1 : 0;
	size_t _len_hints = sizeof(struct addrinfo);
	size_t _len_res = sizeof(struct addrinfo*);

	ms_u_getaddrinfo_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getaddrinfo_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_res = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(node, _len_node);
	CHECK_ENCLAVE_POINTER(service, _len_service);
	CHECK_ENCLAVE_POINTER(hints, _len_hints);
	CHECK_ENCLAVE_POINTER(res, _len_res);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (node != NULL) ? _len_node : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (service != NULL) ? _len_service : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (hints != NULL) ? _len_hints : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (res != NULL) ? _len_res : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getaddrinfo_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getaddrinfo_ocall_t));
	ocalloc_size -= sizeof(ms_u_getaddrinfo_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (node != NULL) {
		if (memcpy_verw_s(&ms->ms_node, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_node % sizeof(*node) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, node, _len_node)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_node);
		ocalloc_size -= _len_node;
	} else {
		ms->ms_node = NULL;
	}

	if (service != NULL) {
		if (memcpy_verw_s(&ms->ms_service, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_service % sizeof(*service) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, service, _len_service)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_service);
		ocalloc_size -= _len_service;
	} else {
		ms->ms_service = NULL;
	}

	if (hints != NULL) {
		if (memcpy_verw_s(&ms->ms_hints, sizeof(const struct addrinfo*), &__tmp, sizeof(const struct addrinfo*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, hints, _len_hints)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_hints);
		ocalloc_size -= _len_hints;
	} else {
		ms->ms_hints = NULL;
	}

	if (res != NULL) {
		if (memcpy_verw_s(&ms->ms_res, sizeof(struct addrinfo**), &__tmp, sizeof(struct addrinfo**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_res = __tmp;
		if (_len_res % sizeof(*res) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_res, 0, _len_res);
		__tmp = (void *)((size_t)__tmp + _len_res);
		ocalloc_size -= _len_res;
	} else {
		ms->ms_res = NULL;
	}

	status = sgx_ocall(71, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (res) {
			if (memcpy_s((void*)res, _len_res, __tmp_res, _len_res)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_freeaddrinfo_ocall(struct addrinfo* res)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_freeaddrinfo_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_freeaddrinfo_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_freeaddrinfo_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_freeaddrinfo_ocall_t));
	ocalloc_size -= sizeof(ms_u_freeaddrinfo_ocall_t);

	if (memcpy_verw_s(&ms->ms_res, sizeof(ms->ms_res), &res, sizeof(res))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(72, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_gai_strerror_ocall(char** retval, int errcode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_gai_strerror_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_gai_strerror_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_gai_strerror_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_gai_strerror_ocall_t));
	ocalloc_size -= sizeof(ms_u_gai_strerror_ocall_t);

	if (memcpy_verw_s(&ms->ms_errcode, sizeof(ms->ms_errcode), &errcode, sizeof(errcode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(73, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_socket_ocall(int* retval, int* error, int domain, int ty, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_socket_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_socket_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_socket_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_socket_ocall_t));
	ocalloc_size -= sizeof(ms_u_socket_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_domain, sizeof(ms->ms_domain), &domain, sizeof(domain))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_ty, sizeof(ms->ms_ty), &ty, sizeof(ty))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_protocol, sizeof(ms->ms_protocol), &protocol, sizeof(protocol))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(74, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_socketpair_ocall(int* retval, int* error, int domain, int ty, int protocol, int sv[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_sv = 2 * sizeof(int);

	ms_u_socketpair_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_socketpair_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_sv = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(sv, _len_sv);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sv != NULL) ? _len_sv : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_socketpair_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_socketpair_ocall_t));
	ocalloc_size -= sizeof(ms_u_socketpair_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_domain, sizeof(ms->ms_domain), &domain, sizeof(domain))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_ty, sizeof(ms->ms_ty), &ty, sizeof(ty))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_protocol, sizeof(ms->ms_protocol), &protocol, sizeof(protocol))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (sv != NULL) {
		if (memcpy_verw_s(&ms->ms_sv, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sv = __tmp;
		if (_len_sv % sizeof(*sv) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_sv, 0, _len_sv);
		__tmp = (void *)((size_t)__tmp + _len_sv);
		ocalloc_size -= _len_sv;
	} else {
		ms->ms_sv = NULL;
	}

	status = sgx_ocall(75, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (sv) {
			if (memcpy_s((void*)sv, _len_sv, __tmp_sv, _len_sv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_bind_ocall(int* retval, int* error, int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen;

	ms_u_bind_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_bind_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_bind_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_bind_ocall_t));
	ocalloc_size -= sizeof(ms_u_bind_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen, sizeof(ms->ms_addrlen), &addrlen, sizeof(addrlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(76, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_listen_ocall(int* retval, int* error, int sockfd, int backlog)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_listen_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_listen_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_listen_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_listen_ocall_t));
	ocalloc_size -= sizeof(ms_u_listen_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_backlog, sizeof(ms->ms_backlog), &backlog, sizeof(backlog))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(77, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_accept_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_accept_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_accept_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_accept_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_accept_ocall_t));
	ocalloc_size -= sizeof(ms_u_accept_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(78, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_accept4_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_accept4_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_accept4_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_accept4_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_accept4_ocall_t));
	ocalloc_size -= sizeof(ms_u_accept4_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(79, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_connect_ocall(int* retval, int* error, int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen;

	ms_u_connect_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_connect_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_connect_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_connect_ocall_t));
	ocalloc_size -= sizeof(ms_u_connect_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen, sizeof(ms->ms_addrlen), &addrlen, sizeof(addrlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(80, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recv_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_recv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recv_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recv_ocall_t));
	ocalloc_size -= sizeof(ms_u_recv_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(81, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recvfrom_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_src_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_recvfrom_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recvfrom_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_src_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(src_addr, _len_src_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (src_addr != NULL) ? _len_src_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recvfrom_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recvfrom_ocall_t));
	ocalloc_size -= sizeof(ms_u_recvfrom_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (src_addr != NULL) {
		if (memcpy_verw_s(&ms->ms_src_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_src_addr = __tmp;
		memset_verw(__tmp_src_addr, 0, _len_src_addr);
		__tmp = (void *)((size_t)__tmp + _len_src_addr);
		ocalloc_size -= _len_src_addr;
	} else {
		ms->ms_src_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(82, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (src_addr) {
			if (memcpy_s((void*)src_addr, _len_src_addr, __tmp_src_addr, _len_src_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recvmsg_ocall(size_t* retval, int* error, int sockfd, void* msg_name, socklen_t msg_namelen, socklen_t* msg_namelen_out, struct iovec* msg_iov, size_t msg_iovlen, void* msg_control, size_t msg_controllen, size_t* msg_controllen_out, int* msg_flags, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_msg_name = msg_namelen;
	size_t _len_msg_namelen_out = sizeof(socklen_t);
	size_t _len_msg_iov = msg_iovlen * sizeof(struct iovec);
	size_t _len_msg_control = msg_controllen;
	size_t _len_msg_controllen_out = sizeof(size_t);
	size_t _len_msg_flags = sizeof(int);

	ms_u_recvmsg_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recvmsg_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_msg_name = NULL;
	void *__tmp_msg_namelen_out = NULL;
	void *__tmp_msg_control = NULL;
	void *__tmp_msg_controllen_out = NULL;
	void *__tmp_msg_flags = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(msg_name, _len_msg_name);
	CHECK_ENCLAVE_POINTER(msg_namelen_out, _len_msg_namelen_out);
	CHECK_ENCLAVE_POINTER(msg_iov, _len_msg_iov);
	CHECK_ENCLAVE_POINTER(msg_control, _len_msg_control);
	CHECK_ENCLAVE_POINTER(msg_controllen_out, _len_msg_controllen_out);
	CHECK_ENCLAVE_POINTER(msg_flags, _len_msg_flags);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_name != NULL) ? _len_msg_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_namelen_out != NULL) ? _len_msg_namelen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_iov != NULL) ? _len_msg_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_control != NULL) ? _len_msg_control : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_controllen_out != NULL) ? _len_msg_controllen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_flags != NULL) ? _len_msg_flags : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recvmsg_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recvmsg_ocall_t));
	ocalloc_size -= sizeof(ms_u_recvmsg_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_name != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_name, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_msg_name = __tmp;
		memset_verw(__tmp_msg_name, 0, _len_msg_name);
		__tmp = (void *)((size_t)__tmp + _len_msg_name);
		ocalloc_size -= _len_msg_name;
	} else {
		ms->ms_msg_name = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_namelen, sizeof(ms->ms_msg_namelen), &msg_namelen, sizeof(msg_namelen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_namelen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_namelen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_msg_namelen_out = __tmp;
		memset_verw(__tmp_msg_namelen_out, 0, _len_msg_namelen_out);
		__tmp = (void *)((size_t)__tmp + _len_msg_namelen_out);
		ocalloc_size -= _len_msg_namelen_out;
	} else {
		ms->ms_msg_namelen_out = NULL;
	}

	if (msg_iov != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_iov, sizeof(struct iovec*), &__tmp, sizeof(struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, msg_iov, _len_msg_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_iov);
		ocalloc_size -= _len_msg_iov;
	} else {
		ms->ms_msg_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_iovlen, sizeof(ms->ms_msg_iovlen), &msg_iovlen, sizeof(msg_iovlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_control != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_control, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_msg_control = __tmp;
		memset_verw(__tmp_msg_control, 0, _len_msg_control);
		__tmp = (void *)((size_t)__tmp + _len_msg_control);
		ocalloc_size -= _len_msg_control;
	} else {
		ms->ms_msg_control = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_controllen, sizeof(ms->ms_msg_controllen), &msg_controllen, sizeof(msg_controllen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_controllen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_controllen_out, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_msg_controllen_out = __tmp;
		if (_len_msg_controllen_out % sizeof(*msg_controllen_out) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_msg_controllen_out, 0, _len_msg_controllen_out);
		__tmp = (void *)((size_t)__tmp + _len_msg_controllen_out);
		ocalloc_size -= _len_msg_controllen_out;
	} else {
		ms->ms_msg_controllen_out = NULL;
	}

	if (msg_flags != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_flags, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_msg_flags = __tmp;
		if (_len_msg_flags % sizeof(*msg_flags) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_msg_flags, 0, _len_msg_flags);
		__tmp = (void *)((size_t)__tmp + _len_msg_flags);
		ocalloc_size -= _len_msg_flags;
	} else {
		ms->ms_msg_flags = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(83, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (msg_name) {
			if (memcpy_s((void*)msg_name, _len_msg_name, __tmp_msg_name, _len_msg_name)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (msg_namelen_out) {
			if (memcpy_s((void*)msg_namelen_out, _len_msg_namelen_out, __tmp_msg_namelen_out, _len_msg_namelen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (msg_control) {
			if (memcpy_s((void*)msg_control, _len_msg_control, __tmp_msg_control, _len_msg_control)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (msg_controllen_out) {
			if (memcpy_s((void*)msg_controllen_out, _len_msg_controllen_out, __tmp_msg_controllen_out, _len_msg_controllen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (msg_flags) {
			if (memcpy_s((void*)msg_flags, _len_msg_flags, __tmp_msg_flags, _len_msg_flags)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_send_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_send_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_send_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_send_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_send_ocall_t));
	ocalloc_size -= sizeof(ms_u_send_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(84, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sendto_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_dest_addr = addrlen;

	ms_u_sendto_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sendto_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(dest_addr, _len_dest_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dest_addr != NULL) ? _len_dest_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sendto_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sendto_ocall_t));
	ocalloc_size -= sizeof(ms_u_sendto_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dest_addr != NULL) {
		if (memcpy_verw_s(&ms->ms_dest_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, dest_addr, _len_dest_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dest_addr);
		ocalloc_size -= _len_dest_addr;
	} else {
		ms->ms_dest_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen, sizeof(ms->ms_addrlen), &addrlen, sizeof(addrlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(85, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sendmsg_ocall(size_t* retval, int* error, int sockfd, const void* msg_name, socklen_t msg_namelen, const struct iovec* msg_iov, size_t msg_iovlen, const void* msg_control, size_t msg_controllen, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_msg_name = msg_namelen;
	size_t _len_msg_iov = msg_iovlen * sizeof(struct iovec);
	size_t _len_msg_control = msg_controllen;

	ms_u_sendmsg_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sendmsg_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(msg_name, _len_msg_name);
	CHECK_ENCLAVE_POINTER(msg_iov, _len_msg_iov);
	CHECK_ENCLAVE_POINTER(msg_control, _len_msg_control);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_name != NULL) ? _len_msg_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_iov != NULL) ? _len_msg_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg_control != NULL) ? _len_msg_control : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sendmsg_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sendmsg_ocall_t));
	ocalloc_size -= sizeof(ms_u_sendmsg_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_name != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_name, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, msg_name, _len_msg_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_name);
		ocalloc_size -= _len_msg_name;
	} else {
		ms->ms_msg_name = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_namelen, sizeof(ms->ms_msg_namelen), &msg_namelen, sizeof(msg_namelen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_iov != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_iov, sizeof(const struct iovec*), &__tmp, sizeof(const struct iovec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, msg_iov, _len_msg_iov)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_iov);
		ocalloc_size -= _len_msg_iov;
	} else {
		ms->ms_msg_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_iovlen, sizeof(ms->ms_msg_iovlen), &msg_iovlen, sizeof(msg_iovlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (msg_control != NULL) {
		if (memcpy_verw_s(&ms->ms_msg_control, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, msg_control, _len_msg_control)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg_control);
		ocalloc_size -= _len_msg_control;
	} else {
		ms->ms_msg_control = NULL;
	}

	if (memcpy_verw_s(&ms->ms_msg_controllen, sizeof(ms->ms_msg_controllen), &msg_controllen, sizeof(msg_controllen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(86, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, void* optval, socklen_t optlen_in, socklen_t* optlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_optval = optlen_in;
	size_t _len_optlen_out = sizeof(socklen_t);

	ms_u_getsockopt_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getsockopt_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_optval = NULL;
	void *__tmp_optlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(optval, _len_optval);
	CHECK_ENCLAVE_POINTER(optlen_out, _len_optlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optlen_out != NULL) ? _len_optlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getsockopt_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getsockopt_ocall_t));
	ocalloc_size -= sizeof(ms_u_getsockopt_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_level, sizeof(ms->ms_level), &level, sizeof(level))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_optname, sizeof(ms->ms_optname), &optname, sizeof(optname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optval != NULL) {
		if (memcpy_verw_s(&ms->ms_optval, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_optval = __tmp;
		memset_verw(__tmp_optval, 0, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	if (memcpy_verw_s(&ms->ms_optlen_in, sizeof(ms->ms_optlen_in), &optlen_in, sizeof(optlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_optlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_optlen_out = __tmp;
		memset_verw(__tmp_optlen_out, 0, _len_optlen_out);
		__tmp = (void *)((size_t)__tmp + _len_optlen_out);
		ocalloc_size -= _len_optlen_out;
	} else {
		ms->ms_optlen_out = NULL;
	}

	status = sgx_ocall(87, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optval) {
			if (memcpy_s((void*)optval, _len_optval, __tmp_optval, _len_optval)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optlen_out) {
			if (memcpy_s((void*)optlen_out, _len_optlen_out, __tmp_optlen_out, _len_optlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_setsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_optval = optlen;

	ms_u_setsockopt_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_setsockopt_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(optval, _len_optval);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_setsockopt_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_setsockopt_ocall_t));
	ocalloc_size -= sizeof(ms_u_setsockopt_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_level, sizeof(ms->ms_level), &level, sizeof(level))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_optname, sizeof(ms->ms_optname), &optname, sizeof(optname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optval != NULL) {
		if (memcpy_verw_s(&ms->ms_optval, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, optval, _len_optval)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	if (memcpy_verw_s(&ms->ms_optlen, sizeof(ms->ms_optlen), &optlen, sizeof(optlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(88, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getsockname_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_getsockname_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getsockname_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getsockname_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getsockname_ocall_t));
	ocalloc_size -= sizeof(ms_u_getsockname_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(89, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpeername_ocall(int* retval, int* error, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_getpeername_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpeername_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpeername_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpeername_ocall_t));
	ocalloc_size -= sizeof(ms_u_getpeername_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(90, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_shutdown_ocall(int* retval, int* error, int sockfd, int how)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_shutdown_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_shutdown_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_shutdown_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_shutdown_ocall_t));
	ocalloc_size -= sizeof(ms_u_shutdown_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_how, sizeof(ms->ms_how), &how, sizeof(how))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(91, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_poll_ocall(int* retval, int* error, struct pollfd* fds, nfds_t nfds, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_fds = nfds * sizeof(struct pollfd);

	ms_u_poll_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_poll_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_fds = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(fds, _len_fds);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fds != NULL) ? _len_fds : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_poll_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_poll_ocall_t));
	ocalloc_size -= sizeof(ms_u_poll_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (fds != NULL) {
		if (memcpy_verw_s(&ms->ms_fds, sizeof(struct pollfd*), &__tmp, sizeof(struct pollfd*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_fds = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, fds, _len_fds)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fds);
		ocalloc_size -= _len_fds;
	} else {
		ms->ms_fds = NULL;
	}

	if (memcpy_verw_s(&ms->ms_nfds, sizeof(ms->ms_nfds), &nfds, sizeof(nfds))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(92, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (fds) {
			if (memcpy_s((void*)fds, _len_fds, __tmp_fds, _len_fds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_create1_ocall(int* retval, int* error, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_epoll_create1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_create1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_create1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_create1_ocall_t));
	ocalloc_size -= sizeof(ms_u_epoll_create1_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(93, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_ctl_ocall(int* retval, int* error, int epfd, int op, int fd, struct epoll_event* event)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_event = sizeof(struct epoll_event);

	ms_u_epoll_ctl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_ctl_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(event, _len_event);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (event != NULL) ? _len_event : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_ctl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_ctl_ocall_t));
	ocalloc_size -= sizeof(ms_u_epoll_ctl_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_epfd, sizeof(ms->ms_epfd), &epfd, sizeof(epfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_op, sizeof(ms->ms_op), &op, sizeof(op))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (event != NULL) {
		if (memcpy_verw_s(&ms->ms_event, sizeof(struct epoll_event*), &__tmp, sizeof(struct epoll_event*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, event, _len_event)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_event);
		ocalloc_size -= _len_event;
	} else {
		ms->ms_event = NULL;
	}

	status = sgx_ocall(94, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_wait_ocall(int* retval, int* error, int epfd, struct epoll_event* events, int maxevents, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_events = maxevents * sizeof(struct epoll_event);

	ms_u_epoll_wait_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_wait_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_events = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(events, _len_events);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (events != NULL) ? _len_events : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_wait_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_wait_ocall_t));
	ocalloc_size -= sizeof(ms_u_epoll_wait_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (memcpy_verw_s(&ms->ms_epfd, sizeof(ms->ms_epfd), &epfd, sizeof(epfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (events != NULL) {
		if (memcpy_verw_s(&ms->ms_events, sizeof(struct epoll_event*), &__tmp, sizeof(struct epoll_event*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_events = __tmp;
		memset_verw(__tmp_events, 0, _len_events);
		__tmp = (void *)((size_t)__tmp + _len_events);
		ocalloc_size -= _len_events;
	} else {
		ms->ms_events = NULL;
	}

	if (memcpy_verw_s(&ms->ms_maxevents, sizeof(ms->ms_maxevents), &maxevents, sizeof(maxevents))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(95, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (events) {
			if (memcpy_s((void*)events, _len_events, __tmp_events, _len_events)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_environ_ocall(char*** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_environ_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_environ_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_environ_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_environ_ocall_t));
	ocalloc_size -= sizeof(ms_u_environ_ocall_t);

	status = sgx_ocall(96, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getenv_ocall(char** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_u_getenv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getenv_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getenv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getenv_ocall_t));
	ocalloc_size -= sizeof(ms_u_getenv_ocall_t);

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	status = sgx_ocall(97, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_setenv_ocall(int* retval, int* error, const char* name, const char* value, int overwrite)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_name = name ? strlen(name) + 1 : 0;
	size_t _len_value = value ? strlen(value) + 1 : 0;

	ms_u_setenv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_setenv_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(name, _len_name);
	CHECK_ENCLAVE_POINTER(value, _len_value);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_setenv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_setenv_ocall_t));
	ocalloc_size -= sizeof(ms_u_setenv_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	if (value != NULL) {
		if (memcpy_verw_s(&ms->ms_value, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, value, _len_value)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}

	if (memcpy_verw_s(&ms->ms_overwrite, sizeof(ms->ms_overwrite), &overwrite, sizeof(overwrite))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(98, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_unsetenv_ocall(int* retval, int* error, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_u_unsetenv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_unsetenv_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_unsetenv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_unsetenv_ocall_t));
	ocalloc_size -= sizeof(ms_u_unsetenv_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	status = sgx_ocall(99, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_chdir_ocall(int* retval, int* error, const char* dir)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_dir = dir ? strlen(dir) + 1 : 0;

	ms_u_chdir_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_chdir_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(dir, _len_dir);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dir != NULL) ? _len_dir : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_chdir_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_chdir_ocall_t));
	ocalloc_size -= sizeof(ms_u_chdir_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (dir != NULL) {
		if (memcpy_verw_s(&ms->ms_dir, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_dir % sizeof(*dir) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, dir, _len_dir)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dir);
		ocalloc_size -= _len_dir;
	} else {
		ms->ms_dir = NULL;
	}

	status = sgx_ocall(100, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getcwd_ocall(char** retval, int* error, char* buf, size_t buflen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = buflen;

	ms_u_getcwd_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getcwd_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error != NULL) ? _len_error : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getcwd_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getcwd_ocall_t));
	ocalloc_size -= sizeof(ms_u_getcwd_ocall_t);

	if (error != NULL) {
		if (memcpy_verw_s(&ms->ms_error, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error = __tmp;
		if (_len_error % sizeof(*error) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buflen, sizeof(ms->ms_buflen), &buflen, sizeof(buflen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(101, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpwuid_r_ocall(int* retval, unsigned int uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** passwd_result)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pwd = sizeof(struct passwd);
	size_t _len_buf = buflen;
	size_t _len_passwd_result = sizeof(struct passwd*);

	ms_u_getpwuid_r_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpwuid_r_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pwd = NULL;
	void *__tmp_buf = NULL;
	void *__tmp_passwd_result = NULL;

	CHECK_ENCLAVE_POINTER(pwd, _len_pwd);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(passwd_result, _len_passwd_result);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pwd != NULL) ? _len_pwd : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (passwd_result != NULL) ? _len_passwd_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpwuid_r_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpwuid_r_ocall_t));
	ocalloc_size -= sizeof(ms_u_getpwuid_r_ocall_t);

	if (memcpy_verw_s(&ms->ms_uid, sizeof(ms->ms_uid), &uid, sizeof(uid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pwd != NULL) {
		if (memcpy_verw_s(&ms->ms_pwd, sizeof(struct passwd*), &__tmp, sizeof(struct passwd*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_pwd = __tmp;
		memset_verw(__tmp_pwd, 0, _len_pwd);
		__tmp = (void *)((size_t)__tmp + _len_pwd);
		ocalloc_size -= _len_pwd;
	} else {
		ms->ms_pwd = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buflen, sizeof(ms->ms_buflen), &buflen, sizeof(buflen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (passwd_result != NULL) {
		if (memcpy_verw_s(&ms->ms_passwd_result, sizeof(struct passwd**), &__tmp, sizeof(struct passwd**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_passwd_result = __tmp;
		if (_len_passwd_result % sizeof(*passwd_result) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_passwd_result, 0, _len_passwd_result);
		__tmp = (void *)((size_t)__tmp + _len_passwd_result);
		ocalloc_size -= _len_passwd_result;
	} else {
		ms->ms_passwd_result = NULL;
	}

	status = sgx_ocall(102, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (pwd) {
			if (memcpy_s((void*)pwd, _len_pwd, __tmp_pwd, _len_pwd)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (passwd_result) {
			if (memcpy_s((void*)passwd_result, _len_passwd_result, __tmp_passwd_result, _len_passwd_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getuid_ocall(unsigned int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getuid_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getuid_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getuid_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getuid_ocall_t));
	ocalloc_size -= sizeof(ms_u_getuid_ocall_t);

	status = sgx_ocall(103, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

