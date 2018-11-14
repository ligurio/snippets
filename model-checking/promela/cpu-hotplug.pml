/*
 *
 * CPU hotplug state machine (Deadlock freedom, liveness properties)
 * Page cache page properties
 *	- Safety: not seeing other processes data (e.g. Dirty CoW)
 *	- Liveness: page eventually reaches the block device
 * 
 * https://linuxplumbersconf.org/event/2/contributions/60/attachments/18/42/FormalMethodsPlumbers2018.pdf
 */
