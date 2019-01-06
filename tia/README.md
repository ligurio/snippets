## Подходы

- Стоимостная модель на основе истории запусков тестов
- Тегирование тесткейсов
- На основе новых изменений

## Кандидаты и мысли:

- postgresql (много платформ)
- CRIU (много платформ и комбинаций тестов) как уменьшить? pairwise + "test impact analysis"
- Linux Kernel
- исходный код продукта это только один из источников багов, есть еще код
установщика, DSL для установочных пакетов
- хранить маппинг в репозитории чтобы для разных веток были разные маппинги
- идея хорошо ложится на git-workflow

## Pitfalls

- privelege separation
- chroot (-fprofile-dir?)
- с негативным тестированием трудно собрать данные о покрытии потому что данные сохраняются только при стандартном exit()

## Реализации

- [NCrunch](https://www.ncrunch.net/) is an automated concurrent testing tool for Visual Studio.
- [VectorCAST/QA](https://www.vectorcast.com/software-testing-products/vectorcast-qa-predictable-quality-embedded-development)
- [Visual Studio](https://docs.microsoft.com/en-us/azure/devops/pipelines/test/test-impact-analysis?view=vsts)
- Java: [Testar](http://google-testar.sourceforge.net/)
- Java: [Protest](https://sourceforge.net/projects/protest/)
- Java: [jtestme](https://bitbucket.org/delitescere/jtestme)
- JavaScript: [wallaby.js](https://wallabyjs.com/)
- Python: [pytest-knows](https://pypi.org/project/pytest-knows/)
- Python: [pytest-imcremental](https://pypi.org/project/pytest-incremental/)
- Python: [pytest-testmon](https://pypi.org/project/pytest-testmon)
- Python: [pytest-picked](https://pypi.org/project/pytest-picked)
- Python: [Smother](https://pypi.org/project/smother/)
- Python: [python-tia](https://github.com/fkromer/python-tia)
- Python: [nose-knows](https://pypi.org/project/nose-knows/)
- Windows: BMAT (Echelon) [BMAT -- A Binary Matching Tool for Stale Profile Propagation](https://www.jilp.org/vol2/v2paper2.pdf)
- Windows: Vulcan [Vulcan: Binary Transformation In A Distributed Environment](https://www.microsoft.com/en-us/research/publication/vulcan-binary-transformation-in-a-distributed-environment/) (Win32)
- Selfection (Samsung)
- TestTube
- Echelon
- CRANE
- THEO
- Pythia
- [whatrequires](http://www.pixelbeat.org/scripts/whatrequires)

## TODO

- python - ```mapfunc-py```
- golang:
   - [callgraph](https://github.com/golang/tools/blob/master/cmd/callgraph/main.go)
   - [go-callvis](https://github.com/TrueFurby/go-callvis)
   - http://saml.rilspace.com/profiling-and-creating-call-graphs-for-go-programs-with-go-tool-pprof
   - ```go tool pprof``` https://blog.golang.org/profiling-go-programs


## Papers

- Diffing C source codes to binaries: [slides](https://2018.zeronights.ru/wp-content/uploads/materials/03-Diffing-C-source-codes-to-binarie.pdf), [video](https://youtu.be/UVIKXxMI_Lg)
- [CRANE: Failure Prediction, Change Analysis and Test Prioritization in Practice – Experiences from Windows](https://www.microsoft.com/en-us/research/publication/crane-failure-prediction-change-analysis-and-test-prioritization-in-practice-experiences-from-windows-2/)
- [Factors Oriented Test Case Prioritization Technique in Regression Testing using Genetic Algorithm](https://pdfs.semanticscholar.org/54e6/fa8fecaf0c338147b2a98f4857af797eaf80.pdf)
- Pythia:
  - [Pythia: A regression test selection tool based on textual differencing](http://cis.poly.edu/~phyllis/papers/Pythia.ps.gz)
  - [Pythia: A regression test selection tool based on textual differencing](http://dslab.konkuk.ac.kr/Class/2012/12SM/Projects/regression_test_%EA%B9%80%EC%9D%98%EC%84%AD.pdf)
- [Prioritizing test cases for regression testing - G. Rothermel; R.H. Untch; Chengyun Chu; M.J. Harrold](https://digitalcommons.unl.edu/cgi/viewcontent.cgi?article=1017&context=csearticles) [PPT](https://www.cc.gatech.edu/~harrold/issta00/cfp/slides/elbaum.issta2000.ppt)
- ATACLx Suds (by Telcordia Technologies) (see "Software Quality Assurance: A Self-Teaching Introduction", Ch. 10)
- [The Rise of Test Impact Analysis](https://martinfowler.com/articles/rise-test-impact-analysis.html)
- [Get Smart about Your Regression Tests Value](https://www.stickyminds.com/article/get-smart-about-your-regression-tests-value)
- [Effectiveness of Testcase Prioritization using APFD Metric: Survey](https://pdfs.semanticscholar.org/d83c/4c5760ea5a938a950a77fae2702985846f22.pdf)
- Echelon: [Effectively Prioritizing Tests in Development Environment](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.65.7730&rep=rep1&type=pdf)
- THEO: [The Art of Testing Less without Sacrificing Quality](https://www.microsoft.com/en-us/research/wp-content/uploads/2015/05/The-Art-of-Testing-Less-without-Sacrificing-Quality.pdf)
- TestTube
  - [TESTTUBE: a system for selective regression testing](https://userweb.cs.txstate.edu/~rp31/papersSQ/ChenRosenblumVo.pdf)
  - [Practical Reusable Unix Software](https://pdfs.semanticscholar.org/8161/12cf55769e75eb0db966886da8b7ac10480a.pdf) (pp. 177, 316)
- Selfection: [Regression Test Selection for TizenRT](http://users.ece.utexas.edu/~gligoric/papers/CelikETAL18Selfection.pdf)
- [The Economic Impacts of Inadequate Infrastructure for Software Testing](https://www.nist.gov/sites/default/files/documents/director/planning/report02-3.pdf)
- [Regression testing minimization, selection and prioritization: a survey](http://www0.cs.ucl.ac.uk/staff/M.Harman/stvr-shin-survey.pdf)
- [Test Faster: How We Cut Our Test Cycle Time in Half](https://www.stickyminds.com/article/test-faster-how-we-cut-our-test-cycle-time-half)
- [Referenced Specifications](https://refspecs.linuxfoundation.org/)
  - Application Programming Interface (API) Standards
  - ELF and ABI Standards
