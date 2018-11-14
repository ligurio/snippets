/*
 *
 * CPU hotplug state machine (Deadlock freedom, liveness properties)
 * https://lxr.missinglinkelectronics.com/linux/Documentation/core-api/cpu_hotplug.rst
 * https://lxr.missinglinkelectronics.com/linux/kernel/cpu.c
 * https://lxr.missinglinkelectronics.com/linux/include/linux/cpuhotplug.h
 * https://lwn.net/Articles/535764/
 *
 * Page cache page properties
 *	- Safety: not seeing other processes data (e.g. Dirty CoW)
 *	- Liveness: page eventually reaches the block device
 * 
 * https://linuxplumbersconf.org/event/2/contributions/60/attachments/18/42/FormalMethodsPlumbers2018.pdf
 */
