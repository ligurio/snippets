bit boat = 0;
bit wolf = 0;
bit goat = 0;
bit cabbage = 0;

inline canMoveAlone() {
  wolf != goat && goat != cabbage;
}

inline moveAlone() {
  printf("Move alone\n");
  boat = 1 - boat;
}

inline canMoveWolf() {
  wolf == boat && boat != cabbage;
}

inline moveWolf() {
  printf("Move wolf\n");
  assert(wolf == boat);
  boat = 1 - boat;
  wolf = 1 - boat;
}

inline moveGoat() {
  printf("Move goat\n");
  assert(goat == boat);
  boat = 1 - boat;
  goat = 1 - goat;
}

inline canMoveGoat() {
  goat == boat;
}

inline moveCabbage() {
  printf("Move cabbage\n");
  assert(cabbage == boat);
  boat = 1 - boat;
  cabbage = 1 - cabbage;
}

inline canMoveCabbage() {
  cabbage == boat;
  wolf != goat;
}

active proctype man() {
  do
  :: atomic { canMoveAlone() -> moveAlone() };
  :: atomic { canMoveGoat() -> moveGoat() };
  :: atomic { canMoveWolf() -> moveWolf() };
  :: atomic { canMoveCabbage() -> moveCabbage() };
  od
}

ltl neverReachTarget { !<> (boat && wolf && goat && cabbage) }
