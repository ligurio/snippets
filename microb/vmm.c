#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __LINUX__
#include <sys/io.h>
#endif
#include <unistd.h>

/* syscall. This test measures round-trip transitions from userlevel to
 * supervisor-level via the syscall and sysret instructions.  The software VMM
 * introduces a layer of code and an extra privilege transition, requiring
 * approximately 2000 more cycles than a native system call. In the hardware
 * VMM, system calls execute without VMM intervention, so as we expect, the
 * hardware VMM executes system calls at native speed.
 */

size_t b_syscall() { return 0; }

/* in. We execute an in instruction from port 0x80, the BIOS POST port. Native
 * execution accesses an off-CPU register in the chipset, requiring 3209
 * cycles. The software VMM, on the other hand, translates the in into a short
 * sequence of instructions that interacts with the virtual chipset model.
 * Thus, the software VMM executes this instruction fifteen times faster than
 * native. The hardware VMM must perform a vmm/guest round trip to complete the
 * I/O operation. This transition causes in to consume 15826 cycles in the
 * tested system.
 */

#ifdef __LINUX__
size_t b_in() {

#define BASEPORT 0x378 /* lp1 */

  uid_t uid = getuid(), euid = geteuid();
  if (euid != 0 || uid != 0) {
    return 0;
  }

  if (ioperm(BASEPORT, 3, 1))
    perror("ioperm");

  /* Set the data signals (D0-7) of the port to all low (0) */
  outb(0, BASEPORT);
  if (ioperm(BASEPORT, 3, 0))
    perror("ioperm");

  return 0;
}
#endif

/* cr8wr. %cr8 is a privileged register that determines which pending
 * interrupts can be delivered. Only %cr8 writes that reduce %cr8 below the
 * priority of the highest pending virtual interrupt cause an exit. Our FrobOS
 * test never takes interrupts so no %cr8 write in the test ever causes an
 * exit. As with syscall, the hardware VMM’s performance is similar to native.
 * The software VMM translates %cr8 writes into a short sequence of simple
 * instructions, completing the %cr8 write in 35 cycles, about four times
 * faster than native.
 */

// https://git.kernel.org/pub/scm/virt/kvm/kvm-unit-tests.git/tree/x86/emulator.c#n177
// https://git.kernel.org/pub/scm/virt/kvm/kvm-unit-tests.git/tree/x86/vmexit.c#n44
size_t b_cr8wr(void) { return 0; }

/* call/ret. BT slows down indirect control flow. We target this overhead by
 * repeatedly calling a subroutine. Since the hardware VMM executes calls and
 * returns without modification, the hardware VMM and native both execute the
 * call/return pair in 11 cycles. The software VMM introduces an average
 * penalty of 40 cycles, requiring 51 cycles.
 */

// https://stackoverflow.com/questions/2842751/call-ret-in-x86-assembly-embedded-in-c
size_t b_callret() { return 0; }

/* pgfault. In both VMMs, the software MMU interposes on both true and hidden
 * page faults. This test targets the overheads for true page faults. While
 * both VMM paths are logically similar, the software VMM (3927 cycles)
 * performs much better than the hardware VMM (11242 cycles). This is due
 * mostly to the shorter path whereby the software VMM receives control; page
 * faults, while by no means cheap natively (1093 cycles on this hardware), are
 * faster than a vmrun/exit round-trip.
 */

size_t b_pgfault() {
  long pagesize = sysconf(_SC_PAGESIZE);
  unsigned char *p = (unsigned char *)malloc(pagesize + 1);
  p[0] = 0;        /* Page fault. */
  p[pagesize] = 1; /* Page fault. */

  return 0;
}

/* divzero. Division by zero has fault semantics similar to those of page
 * faults, but does not invoke the software MMU. While division by zero is
 * uncommon in guest workloads, we include this nanobenchmark to clarify the
 * pgfault results. It allows us to separate out the virtualization overheads
 * caused by faults from the overheads introduced by the virtual MMU. As
 * expected, the hardware VMM (1014 cycles) delivers near native performance
 * (889 cycles), decisively beating the software VMM (3223 cycles).
 *
 * The main idea of this test is to generate hardware "division by zero"
 * exception, and measure how long it will be proceeded.
 */

jmp_buf fpe;

static void sigfpe_sigaction(int signal, siginfo_t *si, void *arg) {
  longjmp(fpe, 1);
}

size_t b_divzero(void) {
  struct sigaction sa;
  int c;

  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = &sigfpe_sigaction;
  sa.sa_flags = SA_NODEFER;
  sigaction(SIGFPE, &sa, NULL);

  if (0 == setjmp(fpe)) {
    c = 1 / 0;
  }

  return 0;
}

/* ptemod. Both VMMs use the shadowing technique described in Section 2.4 to
 * implement guest paging with trace-based coherency. The traces induce
 * significant overheads for PTE writes, causing very high penalties relative
 * to the native single cycle store. The software VMM adaptively discovers the
 * PTE write and translates it into a small program that is cheaper than a trap
 * but still quite costly. This small program consumes 391 cycles on each
 * iteration. The hardware VMM enters and exits guest mode repeatedly, causing
 * it to perform approximately thirty times worse than the software VMM,
 * requiring 12733 cycles.
 */

size_t b_ptemod() { return 0; }

extern __inline__ unsigned long long int rdtsc() {
  unsigned long long int x;
  __asm__ volatile(".byte 0x0f, 0x31" : "=A"(x));
  return x;
}
