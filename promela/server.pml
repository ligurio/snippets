#define NUM_CLIENTS 2
#define BUF_LENGTH 3

chan send_q[NUM_CLIENTS + 1] = [0] of { byte };
chan recv_q = [BUF_LENGTH] of { byte };

active [NUM_CLIENTS] proctype client()
{
   printf("started client %d\n", _pid)
   byte req
   do
   :: recv_q!_pid; printf("client %d: send request %d\n", _pid, _pid);
   :: send_q[_pid]?req -> printf("client %d: receive request %d\n", _pid, req);
   od
}

active proctype server()
{
   byte num
   printf("started server %d\n", _pid)
   do
   :: recv_q?num -> send_q[num]!(num + 1);
   		printf("server: send request %d\n", num)
   od
}
