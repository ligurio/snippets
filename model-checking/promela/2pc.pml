/*
  Two-phase commit (2PC) is a very simple and elegant protocol that ensures the
  atomic commitment of distributed transactions.

  TLA+ https://muratbuffalo.blogspot.com/2018/12/2-phase-commit-and-beyond.html
  https://en.wikipedia.org/wiki/Two-phase_commit_protocol
  https://www.computer.org/csdl/proceedings/time/2012/2659/00/06311116.pdf
  https://accelazh.github.io/transaction/Distributed-Transaction-ACID-Study
  https://accelazh.github.io/images/distributed_transaction_explained_through_tla_plus.pdf

  2PC in PostgreSQL:
  https://postgrespro.ru/media/2017/02/10/mmtsslides-161110113542.pdf
  https://postgrespro.com/docs/enterprise/9.6/multimaster
*/
