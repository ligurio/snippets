# Stability test of Travis CI infrastructure

[![Build Status](https://travis-ci.org/ligurio/continuous-trinity.svg?branch=master)](https://travis-ci.org/ligurio/continuous-trinity)

[OpenVZ](openvz.org) containers is very stable technology.
We use a large amount of different tests to confirm that statement.
[Trinity](http://codemonkey.org.uk/projects/trinity/) is a popular and effective
Linux syscall fuzzer. It is often used to find [security flaws in Linux kernel](http://codemonkey.org.uk/projects/trinity/bugs-found.php).

Travis CI infrastructure is based on [OpenVZ](http://openvz.org/)
containers but for unknown reasons they use non latest version of OpenVZ kernel.
Thus [we can kill Travis CI server](https://travis-ci.org/ligurio/continuous-trinity/builds/51795266)
by running Trinity inside container. Just send me pull request to trigger a build. :)

--
[sergeyb@](https://twitter.com/estet)
