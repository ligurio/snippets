#!/bin/sh

# https://github.com/grimoirelab/use_cases/blob/master/documentfoundation/README.md#5-updating-tdf-data-sources
# https://jgbarah.gitbooks.io/grimoirelab-training/content/grimoireelk/producing_kibana_dashboards_with_grimoireelk.html
# GIT blame https://github.com/jgbarah/blameanalysis
#
# pkg_add  elasticsearch kibana git python-3.5.2 py3-pip
# git clone https://github.com/grimoirelab/GrimoireELK
# pip3.4 install perceval
# /etc/rc.d/elasticsearch start
# elasticsearch(ok)
# /etc/rc.d/kibana start
# kibana(ok)
# curl  http://127.0.0.1:9200/
#{
#  "name" : "Red Skull",
#  "cluster_name" : "elasticsearch",
#  "version" : {
#    "number" : "2.3.4",
#    "build_hash" : "e455fd0c13dceca8dbbdbb1665d068ae55dabe3f",
#    "build_timestamp" : "2016-06-30T11:24:31Z",
#    "build_snapshot" : false,
#    "lucene_version" : "5.5.0"
#  },
#  "tagline" : "You Know, for Search"
#}
# git clone https://github.com/ligurio/openbsd-metrics
# cd openbsd-metrics; ./openbsd-activity.sh

set -eu

STORAGE="data"
ES_URL="http://localhost:9200"
GIT_OPT="--raw --numstat --pretty=fuller --decorate=full \
	--parents --topo-order -M -C -c --remotes=origin --all"

GITREPO="https://github.com/openbsd"
REPOS="src ports xenocara www"

GMANE_PREFIX="gmane.os.openbsd."
LISTS="cvs ports tech changes bugs misc pf www french   \
       sparc newbies ppc advocacy arm x11 alpha hppa 	\
       mac68k flashboot ipv6 announce vax smp		\
       ipsec-clients bsdanywhere embedded security	\
       romp mobile elf"

populate_scm ()
{
  # warning: inexact rename detection was skipped due to too many files.
  # warning: you may want to set your diff.renameLimit variable
  # to at least 3413 and retry the command.
  git config diff.renames 3413
  for r in $REPOS; do
    url=$GITREPO/$r
    echo "=== GIT repository $STORAGE/$r ==="
    if [ ! -e $STORAGE/$r ]; then
       git clone $url $STORAGE/$r
       cd $STORAGE/$r
    else
       cd $STORAGE/$r
       git fetch
    fi
    pwd
    if [ ! -e /tmp/$r.log ]; then
       git log $GIT_OPT > /tmp/$r.log
       cd ../..
       python3.4 GrimoireELK/utils/p2o.py -e $ES_URL --no_inc --debug git /tmp/$r.log
       python3.4 GrimoireELK/utils/p2o.py -e $ES_URL --no_inc --debug --enrich_only git /tmp/$r.log
    fi
  done
}

populate_lists ()
{
  for l in $LISTS; do
    ml = $GMANE_PREFIX$l
    echo "=== MAIL list $ml ==="
    perceval gmane --offset 2000 $ml
  done
}

populate_scm
# python3.4 GrimoireELK/utils/kidash.py -e $ES_URL -g --import GrimoireELK/dashboards/generic-git-2y-projects.json
# 2016-11-13 00:28:16,371 Created index http://localhost:9200/git__tmp_www.log_enrich
# python3.4 GrimoireELK/utils/e2k.py -g -e $ES_URL -d "Git" -i git__tmp_www.log_enrich
