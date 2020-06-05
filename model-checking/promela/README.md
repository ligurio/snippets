### Case Studies:

- [PostgreSQL pgpool](http://d.hatena.ne.jp/interdb/touch/20100815/1281809853)
- [Linux kernel RCU](https://lwn.net/Articles/279077/)
- [Network protocol for real-time sharing between graphical applications](https://github.com/verse/verse/tree/master/misc/promela)
- [Modeling and Formal Verification of DHCP Using SPIN](https://pdfs.semanticscholar.org/6ddd/d0951f9596526f138faa68304485a6a052e2.pdf)

----------

- https://github.com/kaizsv/pikoRT-Spin
- https://github.com/kaizsv/eChronos-Spin
- https://github.com/kaizsv/FreeRTOS-Spin

----------

- [Formal Analysis of a Space Craft Controller using Spin](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.122.6866&rep=rep1&type=pdf)
- [Applications for the Checker – A Survey](http://www.tucs.fi/publications/attachment.php?fname=TR782.pdf) - Ville R. Koskinen | Juha Plosila
- [Comparisons of Alloy and Spin](http://www.pamelazave.com/compare.html)
- [Model Checking Paxos in Spin](https://arxiv.org/abs/1408.5962)
- http://spinroot.com/spin/success.html
- http://www.imm.dtu.dk/~albl/promela.html
- https://github.com/dgryski/modelchecking
- https://swtch.com/spin/
- https://github.com/dgryski/modelchecking/tree/master/spin
- Course: [Model Checking Concurrent Programs](http://cnx.org/content/col10294/1.3)
- [Comparisons of Alloy and Spin](http://www.pamelazave.com/compare.html)
- [Alloy meets TLA+: An exploratory study](https://arxiv.org/pdf/1603.03599.pdf)

[news.ycombinator.com](https://news.ycombinator.com/item?id=10225917):

> Thanks for the link. I read about TLAPS. It seems it relies on SMT solver to uncharge proof obligations,
> and no way for you to manually prove your claim using lower level tactics, like in Coq.
> So you rely on heuristic nature of SMT solver.
>
> About Spin[1]. If you compare the user base of Spin with the user base of TLA+ I bet you will wonder
> how many users out there  were using verification tools all those years. Lamport released his tool
> like 20 years later than SPIN started to spread. He did a great job, but there is no innovation in my opinion.
>
> I think that serious industry players like Intel, Google or NASA are using all spectre of verification tools,
> including self written tools. Intel is using there own tool for some of their chip verification AFAIK.
> My colleague went into Intel to help develop verification scripts using this tool.
>
> TLA+ has been promoted by Amazon with their latest technical report. Yes, it has more
> expressive types (records,tuples,sets), but it comes with a cost of lowering your verification performance rate.
> There are many subtle tradeoffs to make.
> 
> We tried to use several formal verification tools in our latest distributed project. We tried Spin,
> TLA+, mCRL2, Coq. There is its own philosophy, pros and cons behind each tool, but in our case
> Spin made the best job: we had to invest not so much time but found many concurrency bugs in our distributed algorithm.
> Its pros is that it has very basic data types and not very good parallelism support nor in multi thread nor in multi-node form.
>
> [1] http://spinroot.com/spin/whatispin.html
