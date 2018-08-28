# ouroboros [![Build Status](https://travis-ci.org/ligurio/ouroboros.svg?branch=master)](https://travis-ci.org/ligurio/ouroboros)

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/c/c8/Ouroboros-simple.svg/2000px-Ouroboros-simple.svg.png" height="100" style="float:left;">

Ouroboros is a simplistic, modern, and performant job scheduler written in Go.
It lives in a single binary and does not have any dependencies.

## TODO:

+ ~~триггер по времени с поддержкой формата crontab~~
+ ~~история запусков для каждого джоба~~
+ ~~поддержка таргетов~~
+ ~~запуск в контейнере Docker~~
+ ~~запуск команд на таргетах via ssh~~
+ ~~JSON API via HTTP~~
+ ~~использовать SSH agent вместо статических ssh ключей~~
- поддержка lxc?
- обновить документацию по шаблону https://gist.github.com/iros/3426278
- подготовить окружение для выполнения команды (cd, git checkout, etc)
- нотификация с помощью писем
- нотификация с помощью IRC
- ближайшее расписание по запускам
- триггер в зависимости от других джобов с поддержкой параметров
- триггер Github https://github.com/go-playground/webhooks
	https://github.com/docker/leeroy
	https://github.com/vbatts/git-validation
- запуск в Vagrant https://raw.githubusercontent.com/nathany/vagrant-gopher/master/Vagrantfile
- валидация формата новых джобов

- [Sundial](https://github.com/gilt/sundial)
- [GitLab CI](https://github.com/ayufan/gitlab-ci-multi-runner/blob/master/docs/configuration/advanced-configuration.md)
