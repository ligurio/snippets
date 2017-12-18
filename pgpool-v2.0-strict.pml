/*
 * pgpool-II:v.2.2で修正されたバグの再現と修正:
 *
 * Copyright (C) 2010  suzuki hironobu _@_ interdb.jp
 */

/*
 * #define SERIALIZABLE
 * $ spin -a pgpool-v2.2-serializable.pml
 * $ gcc -w -o pan -D_POSIX_SOURCE -DMEMLIM=128 -DSAFETY -DNOCLAIM -DXUSAFE -DNOFAIR  pan.c
 * $ ./pan -v -m10000 -w19 -c10
 */

#define SERIALIZABLE
#define OLD_VERSION

/*
 * lock
 */
mtype {LOCKED, UNLOCKED};
mtype master_mutex = UNLOCKED;
mtype slave_mutex = UNLOCKED;

inline lock(m) {atomic{ (m == UNLOCKED) -> m = LOCKED}}
inline unlock(m) {m = UNLOCKED} 

/*
 * chan
 */
mtype {UPDATE, COMMIT, ABORT, ACK};
mtype {OK, NG};
mtype {P0, P1, P_init};
chan to_master[2] = [0] of {mtype, mtype};
chan to_slave[2] = [0] of {mtype, mtype};

/*
 * data
 */
byte master_rowval = P_init;
byte slave_rowval = P_init;

/*
 * operations
 */
inline update (ch, m, rowval) {
#ifdef  SERIALIZABLE
  ch?UPDATE(x) ->
  if
    :: atomic {
      (m == UNLOCKED) -> m = LOCKED  -> ch!ACK(OK)
    }
    :: else -> atomic {
      (m == UNLOCKED) -> m = LOCKED -> ch!ACK(NG)
    }
  fi;
  
#else /* READ_COMMITTED */
  ch?UPDATE(x) ->  lock(m) -> ch!ACK(OK)
#endif
}

inline commit (ch, m, rowval) {
  atomic {
    ch?COMMIT(x) -> rowval = x; unlock(m) -> ch!ACK(OK)
  }
}

inline abort (ch, m) {
  atomic {
    ch?ABORT(x) -> unlock(m) -> ch!ACK(OK);
  }
}

/*
 * watchdog
 */
bool pool_end[2];
proctype watchdog() {
  do
    ::  (pool_end[0] == true && pool_end[1] == true)
       ->
       assert(master_rowval == slave_rowval);
       atomic {
         pool_end[0] = false;    pool_end[1] = false;
         master_rowval = P_init;    slave_rowval = P_init;
       }       
  od
}

/*
 * PostgreSQL
 */
proctype master(int c) {
  local mtype x;
  do
    :: if
         :: update(to_master[c], master_mutex, master_rowval)
         :: commit(to_master[c], master_mutex, master_rowval)
         :: abort(to_master[c], master_mutex)
       fi
  od  
}

proctype slave(int c) {
  local mtype x;
  do
    :: if
         :: update(to_slave[c], slave_mutex, slave_rowval)
         :: commit(to_slave[c], slave_mutex, slave_rowval)
         :: abort(to_slave[c], slave_mutex)
       fi
  od
}


/*
 * pgpool-II
 */
proctype pool(int p; mtype P) {
  local mtype pm, ps;

  do
    :: (pool_end[p] == false) ->

       /* send query to master */
       to_master[p]!UPDATE(P);
       /* wait for response */
       to_master[p]?ACK(pm);

       /* send query to slave */
       to_slave[p]!UPDATE(P);
       /* wait for response */
       to_slave[p]?ACK(ps);

#ifdef OLD_VERSION
       if
         :: (pm == OK) ->  to_master[p]!COMMIT(P);
         :: else ->        to_master[p]!ABORT(P);
       fi;
       if
         :: (ps == OK) ->  to_slave[p]!COMMIT(P);
         :: else ->        to_slave[p]!ABORT(P);
       fi;
       to_master[p]?ACK(pm);     to_slave[p]?ACK(ps);
#else 
       if
         :: (pm == NG || ps == NG); /* abort */
            to_master[p]!ABORT(P0);    to_master[p]?ACK(pm);
            to_slave[p]!ABORT(P0);     to_slave[p]?ACK(ps);
            
         :: else ->
            to_master[p]!COMMIT(P0);    to_master[p]?ACK(pm);
            to_slave[p]!COMMIT(P0);     to_slave[p]?ACK(ps);
       fi;
#endif       
       pool_end[p] = true;
  od
}

/*
 * init
 */
init {
  pool_end[0] = false;  pool_end[1] = false;
  
  atomic {
    run watchdog();
    run master(0);      run master(1);
    run slave(0);       run slave(1);
    run pool(0, P0);    run pool(1, P1);
  }
end:skip
}
