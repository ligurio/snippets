### Tutorials

- Software Foundations --> TAPL
- [A tutorial by Mike Nahas](https://coq.inria.fr/tutorial-nahas)
- [My unusual hobby](https://www.stephanboyer.com/post/134/my-unusual-hobby)
- [Logitext](http://logitext.mit.edu/tutorial)
- [coq-tricks](https://github.com/tchajed/coq-tricks)
- http://www.mi-ras.ru/~sk/lehre/coq/coq_pract.pdf
- https://github.com/xgrommx/coq-ecosystem
- [First impressions of Coq and “Certified Programming with Dependent Types”](http://lambda.jstolarek.com/2015/03/first-impressions-of-coq-and-certified-programming-with-dependent-types/)
- [Coq’Art, CPDT and SF: a review of books on Coq proof assistant](http://lambda.jstolarek.com/2016/06/coqart-cpdt-and-sf-a-review-of-books-on-coq-proof-assistant/)
- https://github.com/coq/coq/wiki/CoqInTheClassroom
- https://github.com/anton-trunov/coq-lecture-notes
- [3110 Coq Tactics Cheatsheet](https://www.cs.cornell.edu/courses/cs3110/2018sp/a5/coq-tactics-cheatsheet.html)

### Examples

- [fscq](https://github.com/mit-pdos/fscq)
- [What does a formal proof look like?](http://ts.data61.csiro.au/projects/TS/l4.verified/sqrt-2-proof.pdf)
- [BPF and formal verification](https://www.sccs.swarthmore.edu/users/16/mmcconv1/pl-reflection.html)

### Notes

https://learnxinyminutes.com/docs/coq/

Можно ещё почитать лекции „Constructive Logic“ от Frank Pfenning. Мне кажется
это самое простое, но строгое изложение (из того, что я видел)
https://t.me/teorkat_msk/1970

Есть достаточно простые лекции по соответствию Карри-Говарда http://www.mathnet.ru/present18230
https://t.me/teorkat_msk/1969

Можно ещё почитать лекции „Constructive Logic“ от Frank Pfenning. Мне кажется
это самое простое, но строгое изложение (из того, что я видел)
https://t.me/teorkat_msk/1970

Еще кто-то спрашивал про туториал по SSReflect. Один из ранних туториалов
https://hal.inria.fr/inria-00407778/document. Он заходит дальше, чем мы
остановились в пятницу.

Можно еще посмотреть вот этот список https://github.com/math-comp/math-comp/wiki/tutorials.
Там можно найти и шпаргалки по тактикам.
https://t.me/teorkat_msk/434

Я могу посоветовать почитать Фрэнка Пфеннинга (http://www.cs.cmu.edu/~fp/). У
него есть курс по конструктивистской логике (я когда-то читал версию от 2008
года http://www.cs.cmu.edu/~fp/courses/15317-f08/, но есть и более свежие
итерации). Он один из ведущих экспертов в теории типов и разных логиках,
например, у него есть работы по модальным логикам.

Одна из черт, которые мне нравятся в его курсах, это четкое разделение
концепций, скажем в стиле Martin-Löf он очень четко разделяет понятия суждения
(judgement) и утверждения (proposition).
https://t.me/teorkat_msk/422

Лекция 1 / Семинар 1

Слайды: https://anton-trunov.github.io/coq-lecture-notes/slides/lecture01.html
Код: https://github.com/anton-trunov/coq-lecture-notes/blob/master/code/lecture01.v

Добавил комментариев в код, добавил в конец слайдов пару интересных общих статей про формальные методы и недавнюю большую обзорную статью про теорем-пруверы:
- "Formal Proof" - T.C. Hales (2008)
- "Position paper: the science of deep specification" - A.W. Appel (2017)
- "QED at Large: A Survey of Engineering of Formally Verified Software" - T. Ringer, K. Palmskog, I. Sergey, M. Gligoric, Z. Tatlock (2019)
https://t.me/teorkat_msk/307

нужно установить себе какое-нибудь псевдоIDE:
- CoqIDE
- ProofGeneral поверх Emacs (https://github.com/ProofGeneral/PG)
- Spacemacs поддерживает coq
- VsCoq (https://github.com/coq-community/vscoq)

```coq
From mathcomp Require Import ssreflect ssrfun ssrbool ssrnat div.
Set Implicit Arguments.
Unset Strict Implicit.
Unset Printing Implicit Defensive.

Lemma foo n m : n + m = m + n. Proof. by apply: addnC. Qed.
```
https://t.me/teorkat_msk/232

Я бы разделил изучение использования Coq вообще и применение Coq в области теории языков программирования (ТЯП).
В первом случае разумный путь новичка выглядит как Logical Foundation (до момента когда начинается ТЯП) -> (пропускаем второй том) -> Verified Functional Algorithms -> (опционально) том про QuickChick + будущий том про сепарационную логику. Потом можно независимо:
- Certified Programming with Dependent Types от A. Chlipala (лучше выборочно, могу потом порекомендовать избранные главы);
- Programs and Proofs от Ильи Сергея -> Mathematical Components book.

Coq’art лучше как учебник не читать, а просмотреть после LF (может параллельно с CPDT / PnP). Там есть некоторые подглавы, материал из которых не особо излагается в других книгах, но он довольно занятный и иллюстрирует всякие нюансы Coq.

Hoare написал хорошие мысли на эту тему в 1996, "How did software get so reliable without proof?" ещё тогда они думали что будущего нет без верификации, но всё пошло в другое русло, цена ошибки оказалась и не такой и большой как все думали для огромного количества софта. https://www.gwern.net/docs/math/1996-hoare.pdf

есть два лагеря TaPL -> SF и SF -> TaPL
https://t.me/c/1121272499/89

https://courses.edx.org/courses/course-v1:KTHx+ID2203.2x+2016T4/course/

кстати, тоже рекомендую https://www.logicomix.com/en/index.html

На курсере есть неплохой начальный курс по логике: https://www.coursera.org/learn/logic-introduction
на эту тему если классный набор упражнений:
https://homes.cs.washington.edu/~jrw12/InductionExercises.html

еще был вот такой саб: https://www.reddit.com/r/DailyProver/

Может, кому пригодится
Gallier:
- Logic For Computer Science
- Foundations of Automatic Theorem Proving

О книге: https://www.amazon.co.uk/gp/aw/d/0486780821/ref=tmm_pap_title_0?ie=UTF8&qid=1518350351&sr=8-36

В Coq-Club пробегала ссылка на веб-приложение для обучения логике: https://www.edukera.com

здесь кмк гораздо лучше сделано (хотя и из немного другой оперы): http://logitext.mit.edu/tutorial

недавно кстати прорешал почти всю логику в http://app.edukera.com/

или вот от Андрея Бауэра туториал: http://math.andrej.com/2011/02/22/video-tutorials-for-the-coq-proof-assistant/

мне понравился курс на Coursera по вычислительной логике несколько лет назад — Майк Генесерет из Стэнфорда его вел

- https://github.com/ejgallego/jscoq
- http://oberon2005.oberoncore.ru/classics/ae1976.pdf
- http://logic.stanford.edu/classes/cs157/current/
- вот, вот здесь можно начать вроде http://intrologic.stanford.edu/lessons/lessons.html
- http://tomasp.net/academic/papers/failures/failures-programming.pdf

В прошедший уикенд я читал лекции в CS-клубе при ПОМИ РАН по выводу типов в системе Хиндли-Милнера и компиляторе GHC (https://compsciclub.ru/courses/types/2019-spring/). Утром второго дня я получил от Amazon'а письмо, начинавшееся со слов «Hello Vitaly Bragilevsky,
Are you looking for something in our Computers & Technology Software Books department? If so, you might be interested in these items».

В теме письма при этом значилось «Types and Programming...», а в списке были настолько близкие к тематике курса книги, что я решил начать лекцию с зачитывания полученного списка. Честно говоря, я был удивлён качеством рекомендации. Разумеется, я все эти книги прекрасно знаю, но получить такую подборку от искусственного интеллекта было очень приятно. Чаще приходится месяцами наблюдать рекомендации относительно покупки чайника сразу после приобретения чайника, ведь всем известно, что люди всегда покупают по два чайника.

Один из слушателей попросил меня продублировать список здесь, что я с удовольствием и делаю.

1) Types and Programming Languages, Benjamin C. Pierce
Азбука нашего дела. Здорово, что есть (замечательный!) русский перевод
(http://newstar.rinet.ru/~goga/tapl/), в котором мне в числе прочих выписана
благодарность, которой я очень горжусь.

2) Purely Functional Data Structures, Chris Okasaki
Приятная книга, помогающая понять все сложности и интересности работы со
структурами данных в чисто функциональном программировании. В книге примеры на
ML, но есть приложение с реализациями на Haskell. Есть и русский перевод, я был
его редактором:
https://dmkpress.com/catalog/computer/programming/functional/978-5-97060-233-1/

3) Basic Category Theory for Computer Scientists, Benjamin C. Pierce
Как признаётся сам автор, ему захотелось изучить теорию категорий, поэтому он и написал эту книжку. Написана она почти 30 лет назад, Пирс тогда был совсем молодым. Книжка очень тонкая (всего 114 страниц), что очень приятно.

4) The Little Typer, Daniel P. Friedman, David Thrane Christiansen
Приятный (несколько игровой) способ изучить зависимые типы. Предисловие от Боба Харпера и послесловие от Коннора МакБрайда говорят сами за себя. Книжка новая, вышла в сентябре 2018 года.

5) Structure and Interpretation of Computer Programs, Harold Abelson, Gerald Jay Sussman, Julie Sussman
Ну, тут всё ясно, классика. Есть русский перевод: http://newstar.rinet.ru/~goga/sicp/sicp.pdf. Кстати, у книг 1, 2, 5 есть один общий переводчик — замечательный Георгий Бронников, мы все должны быть ему благодарны.

6) Practical Foundations for Programming Languages, Robert Harper
Актуальная библия теории типов. Текст сложный: этой осенью я участвовал в
семинаре, в рамках которого делались доклады по этой книге. Так вот студенты
всячески пытались с неё свинтить, заменяя на более простые источники. Ну,
действительно сложно.

7) The Art of Computer Programming, Volumes 1-4A, Donald E. Knuth
Тут искусственный интеллект немного лопухнулся, но книжка всё равно важная!

8) Type Theory and Formal Proof: An Introduction, Rob Nederpelt, Herman Geuvers
Неплохой современный учебник по теории типов (2014 год) от Cambridge University
Press, достаточно высокий уровень, но написано относительно просто.

9) The Little Prover, Daniel P. Friedman, Carl Eastlund
Индуктивные доказательства во всей красе и снова в игровом стиле. Предисловие
от Маттиаса Феллайзена, тоже не последний человек, зря рекомендовать книгу не
будет.

Внезапно оказалось, что я смотрел только часть письма, а внизу была ссылка на
полный список рекомендаций. В полном списке также нашлись Type-driven
Development in Idris от Эдвина Брейди (тоже с благодарностью мне!), Compilers:
Principles, Techniques, and Tools от Ахо, Лэм, Сети и Ульмана, и почему-то
Рефакторинг от Мартина Фаулера. Перестарался искусственный интеллект всё-таки,
зря хвалил.
https://t.me/CompilerDev/20206

нам нужен будет Coq и библиотека mathcomp
