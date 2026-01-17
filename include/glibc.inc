; GNU C Library (glibc) Interface Definitions for RASM
; NASM-compatible definitions for calling glibc functions from assembly
;
; Usage:
;   extern printf, malloc, free  ; Declare external functions
;   %include "glibc.inc"         ; Include constants
;
; Calling Convention (System V AMD64 ABI):
;   Arguments: rdi, rsi, rdx, rcx, r8, r9, then stack (right-to-left)
;   Return: rax (integer/pointer), xmm0 (float/double)
;   Preserved: rbx, rsp, rbp, r12-r15
;   Scratch: rax, rcx, rdx, rsi, rdi, r8-r11
;   Stack must be 16-byte aligned before call

; ============================================================================
; errno Values
; ============================================================================
%define EPERM           1       ; Operation not permitted
%define ENOENT          2       ; No such file or directory
%define ESRCH           3       ; No such process
%define EINTR           4       ; Interrupted system call
%define EIO             5       ; I/O error
%define ENXIO           6       ; No such device or address
%define E2BIG           7       ; Argument list too long
%define ENOEXEC         8       ; Exec format error
%define EBADF           9       ; Bad file descriptor
%define ECHILD          10      ; No child processes
%define EAGAIN          11      ; Try again
%define ENOMEM          12      ; Out of memory
%define EACCES          13      ; Permission denied
%define EFAULT          14      ; Bad address
%define ENOTBLK         15      ; Block device required
%define EBUSY           16      ; Device or resource busy
%define EEXIST          17      ; File exists
%define EXDEV           18      ; Cross-device link
%define ENODEV          19      ; No such device
%define ENOTDIR         20      ; Not a directory
%define EISDIR          21      ; Is a directory
%define EINVAL          22      ; Invalid argument
%define ENFILE          23      ; File table overflow
%define EMFILE          24      ; Too many open files
%define ENOTTY          25      ; Not a typewriter
%define ETXTBSY         26      ; Text file busy
%define EFBIG           27      ; File too large
%define ENOSPC          28      ; No space left on device
%define ESPIPE          29      ; Illegal seek
%define EROFS           30      ; Read-only file system
%define EMLINK          31      ; Too many links
%define EPIPE           32      ; Broken pipe
%define EDOM            33      ; Math argument out of domain
%define ERANGE          34      ; Math result not representable
%define EDEADLK         35      ; Resource deadlock would occur
%define ENAMETOOLONG    36      ; File name too long
%define ENOLCK          37      ; No record locks available
%define ENOSYS          38      ; Function not implemented
%define ENOTEMPTY       39      ; Directory not empty
%define ELOOP           40      ; Too many symbolic links encountered
%define EWOULDBLOCK     11      ; Operation would block (same as EAGAIN)
%define ENOMSG          42      ; No message of desired type
%define EIDRM           43      ; Identifier removed
%define ENOSTR          60      ; Device not a stream
%define ENODATA         61      ; No data available
%define ETIME           62      ; Timer expired
%define ENOSR           63      ; Out of streams resources
%define ENOLINK         67      ; Link has been severed
%define EPROTO          71      ; Protocol error
%define EMULTIHOP       72      ; Multihop attempted
%define EBADMSG         74      ; Not a data message
%define EOVERFLOW       75      ; Value too large for defined data type
%define EILSEQ          84      ; Illegal byte sequence
%define EUSERS          87      ; Too many users
%define ENOTSOCK        88      ; Socket operation on non-socket
%define EDESTADDRREQ    89      ; Destination address required
%define EMSGSIZE        90      ; Message too long
%define EPROTOTYPE      91      ; Protocol wrong type for socket
%define ENOPROTOOPT     92      ; Protocol not available
%define EPROTONOSUPPORT 93      ; Protocol not supported
%define ESOCKTNOSUPPORT 94      ; Socket type not supported
%define EOPNOTSUPP      95      ; Operation not supported on socket
%define EPFNOSUPPORT    96      ; Protocol family not supported
%define EAFNOSUPPORT    97      ; Address family not supported by protocol
%define EADDRINUSE      98      ; Address already in use
%define EADDRNOTAVAIL   99      ; Cannot assign requested address
%define ENETDOWN        100     ; Network is down
%define ENETUNREACH     101     ; Network is unreachable
%define ENETRESET       102     ; Network dropped connection on reset
%define ECONNABORTED    103     ; Software caused connection abort
%define ECONNRESET      104     ; Connection reset by peer
%define ENOBUFS         105     ; No buffer space available
%define EISCONN         106     ; Transport endpoint is already connected
%define ENOTCONN        107     ; Transport endpoint is not connected
%define ESHUTDOWN       108     ; Cannot send after shutdown
%define ETOOMANYREFS    109     ; Too many references: cannot splice
%define ETIMEDOUT       110     ; Connection timed out
%define ECONNREFUSED    111     ; Connection refused
%define EHOSTDOWN       112     ; Host is down
%define EHOSTUNREACH    113     ; No route to host
%define EALREADY        114     ; Operation already in progress
%define EINPROGRESS     115     ; Operation now in progress
%define ESTALE          116     ; Stale file handle
%define EDQUOT          122     ; Quota exceeded
%define ECANCELED       125     ; Operation canceled

; ============================================================================
; Standard I/O Constants
; ============================================================================
%define EOF             -1
%define SEEK_SET        0
%define SEEK_CUR        1
%define SEEK_END        2

%define BUFSIZ          8192
%define FILENAME_MAX    4096
%define FOPEN_MAX       16

; File mode bits (for fopen, open)
%define S_IFMT          0170000  ; File type mask
%define S_IFSOCK        0140000  ; Socket
%define S_IFLNK         0120000  ; Symbolic link
%define S_IFREG         0100000  ; Regular file
%define S_IFBLK         0060000  ; Block device
%define S_IFDIR         0040000  ; Directory
%define S_IFCHR         0020000  ; Character device
%define S_IFIFO         0010000  ; FIFO

%define S_ISUID         0004000  ; Set UID bit
%define S_ISGID         0002000  ; Set GID bit
%define S_ISVTX         0001000  ; Sticky bit

%define S_IRWXU         0000700  ; User (owner) RWX
%define S_IRUSR         0000400  ; User read
%define S_IWUSR         0000200  ; User write
%define S_IXUSR         0000100  ; User execute

%define S_IRWXG         0000070  ; Group RWX
%define S_IRGRP         0000040  ; Group read
%define S_IWGRP         0000020  ; Group write
%define S_IXGRP         0000010  ; Group execute

%define S_IRWXO         0000007  ; Others RWX
%define S_IROTH         0000004  ; Others read
%define S_IWOTH         0000002  ; Others write
%define S_IXOTH         0000001  ; Others execute

; ============================================================================
; Memory Allocation Constants
; ============================================================================
%define NULL            0

; ============================================================================
; Exit Status Codes
; ============================================================================
%define EXIT_SUCCESS    0
%define EXIT_FAILURE    1

; ============================================================================
; Boolean Values
; ============================================================================
%define TRUE            1
%define FALSE           0

; ============================================================================
; Limits
; ============================================================================
%define CHAR_BIT        8
%define SCHAR_MIN       -128
%define SCHAR_MAX       127
%define UCHAR_MAX       255
%define CHAR_MIN        -128
%define CHAR_MAX        127
%define SHRT_MIN        -32768
%define SHRT_MAX        32767
%define USHRT_MAX       65535
%define INT_MIN         -2147483648
%define INT_MAX         2147483647
%define UINT_MAX        4294967295
%define LONG_MIN        -9223372036854775808
%define LONG_MAX        9223372036854775807
%define ULONG_MAX       18446744073709551615

; ============================================================================
; Signal Handler Constants
; ============================================================================
%define SIG_DFL         0       ; Default action
%define SIG_IGN         1       ; Ignore signal
%define SIG_ERR         -1      ; Error return

; ============================================================================
; Math Constants (approximate as integers, use actual float/double in code)
; ============================================================================
; Use these in data section:
; pi:    dq 3.14159265358979323846
; e:     dq 2.71828182845904523536

; ============================================================================
; Time Constants
; ============================================================================
%define CLOCKS_PER_SEC  1000000

; ============================================================================
; Common glibc Functions (declare with extern)
; ============================================================================
; Memory Management:
;   extern malloc, calloc, realloc, free
;   extern memcpy, memmove, memset, memcmp
;
; String Operations:
;   extern strlen, strcpy, strncpy, strcat, strncat
;   extern strcmp, strncmp, strchr, strrchr, strstr
;   extern strtok, strdup
;
; Standard I/O:
;   extern printf, fprintf, sprintf, snprintf
;   extern scanf, fscanf, sscanf
;   extern puts, fputs, putchar, fputc
;   extern gets, fgets, getchar, fgetc
;   extern fopen, fclose, fread, fwrite, fseek, ftell, rewind
;   extern fflush, ferror, feof, clearerr
;
; File Operations:
;   extern open, close, read, write, lseek
;   extern stat, fstat, lstat, access, chmod, chown
;   extern mkdir, rmdir, unlink, rename
;
; Process Control:
;   extern exit, abort, atexit
;   extern fork, execve, execl, execlp, execv, execvp
;   extern wait, waitpid, getpid, getppid
;   extern signal, kill, raise, pause, alarm, sleep, usleep
;
; Time Functions:
;   extern time, clock, difftime
;   extern localtime, gmtime, mktime, strftime
;   extern gettimeofday, clock_gettime
;
; Math Functions:
;   extern sin, cos, tan, asin, acos, atan, atan2
;   extern sinh, cosh, tanh
;   extern exp, log, log10, log2
;   extern pow, sqrt, cbrt, hypot
;   extern ceil, floor, round, trunc
;   extern fabs, fmod, remainder
;
; Conversion:
;   extern atoi, atol, atoll, atof
;   extern strtol, strtoul, strtoll, strtoull, strtod, strtof
;
; Environment:
;   extern getenv, setenv, unsetenv, putenv
;
; Random Numbers:
;   extern rand, srand, random, srandom
;
; Directory Operations:
;   extern opendir, closedir, readdir, rewinddir
;   extern getcwd, chdir
;
; Network (socket):
;   extern socket, bind, listen, accept, connect
;   extern send, recv, sendto, recvfrom
;   extern setsockopt, getsockopt, shutdown
;   extern inet_addr, inet_ntoa, htons, htonl, ntohs, ntohl
;
; Threading (pthread):
;   extern pthread_create, pthread_join, pthread_exit
;   extern pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock
;   extern pthread_cond_init, pthread_cond_wait, pthread_cond_signal

; ============================================================================
; Structure Size Reference (for stack allocation)
; ============================================================================
; struct stat: 144 bytes
; struct timespec: 16 bytes
; struct timeval: 16 bytes
; struct tm: 56 bytes
; FILE*: 8 bytes (pointer)

; ============================================================================
; Usage Examples
; ============================================================================
;
; Example 1: Call printf
;   section .rodata
;       fmt: db "Hello, %s!", 10, 0
;       name: db "World", 0
;   
;   section .text
;       extern printf
;       lea rdi, [rel fmt]     ; First arg: format string
;       lea rsi, [rel name]    ; Second arg: string to print
;       xor eax, eax          ; No vector args
;       call printf
;
; Example 2: Allocate memory with malloc
;   extern malloc, free
;   mov rdi, 1024             ; Size in bytes
;   call malloc
;   test rax, rax             ; Check for NULL
;   jz .alloc_failed
;   ; Use memory pointed to by rax
;   mov rdi, rax              ; Pointer to free
;   call free
;
; Example 3: String operations
;   extern strlen, strcpy
;   lea rdi, [rel my_string]
;   call strlen               ; Returns length in rax
;   
;   lea rdi, [rel dest]       ; Destination
;   lea rsi, [rel src]        ; Source
;   call strcpy
;
; Example 4: Open and read file
;   extern fopen, fread, fclose
;   lea rdi, [rel filename]
;   lea rsi, [rel mode_r]     ; mode_r: db "r", 0
;   call fopen
;   test rax, rax
;   jz .open_failed
;   mov r12, rax              ; Save FILE*
;   
;   lea rdi, [rel buffer]     ; Buffer
;   mov rsi, 1                ; Element size
;   mov rdx, 1024             ; Element count
;   mov rcx, r12              ; FILE*
;   call fread                ; Returns elements read in rax
;   
;   mov rdi, r12              ; FILE*
;   call fclose
