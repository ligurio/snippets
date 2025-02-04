#!/bin/sh

# Requirements:
#	- Kibana https://www.elastic.co/guide/en/kibana/current/setup.html
#	- elasticsearch https://www.elastic.co/guide/en/kibana/current/setup.html
#	- perceval
#	- GrimoireELK
#	- git
#	- python

STORAGE="data"
ES_URL="http://localhost:9200"
GIT_OPT="--raw --numstat --pretty=fuller --decorate=full \
	--parents --topo-order -M -C -c --remotes=origin --all"

LISTS="announce debian devel libct users criu"
PIPERMAIL="https://lists.openvz.org/pipermail"

populate_issues() {
	perceval github --owner xemul --repository criu --from-date '2013-01-01' --token XXXX
	perceval jira "https://bugs.openvz.org/" --project CRIU -u sergeyb -p XXXX --from-date '2012-10-26'
	perceval jira "https://bugs.openvz.org/" --project CRIU -u sergeyb -p XXXX --from-date '2012-10-26'
}

populate_scm() {
	url=$1
	project=$(basename $url)
	[ ! -e $STORAGE/$project ] && git clone $url $STORAGE/$project || ( cd $STORAGE/$project && git fetch )
	pwd
	cd $STORAGE/$project
	#git log $GIT_OPT > /tmp/$project.log
	#perceval git /tmp/$project.log
	cd ..
	python3 GrimoireELK/utils/p2o.py -e $ES_URL \
			--no_inc git /tmp/$project.log
	python3 GrimoireELK/utils/p2o.py -e $ES_URL \
			--no_inc --enrich_only git /tmp/$project.log
	python3 GrimoireELK/utils/e2k.py -e $ES_URL \
			-d "Git Activity" -i $INDEX
}

populate_pipermail() {
	for l in $LISTS; do
		perceval pipermail $PIPERMAIL/$l
	done
}

populate_mbox() {
	months="January February March April May June July August September October November December"
	year=`date +%Y`
	for l in $LISTS; do stat $l.mbox > /dev/null 2>&1 && rm $l.mbox; done

	for y in `seq 2005 $year`; do
		for m in $months; do
			for l in $LISTS; do
				url="$PIPERMAIL/$l/$y-$m.txt.gz"
				echo $url
				curl -sfL $url > /dev/zero
				if [ $? == 0 ]; then
					curl -sLO $url && gunzip -f $y-$m.txt.gz && cat $y-$m.txt >> $l.mbox
				fi
			done
		done
	done
}

if [ "$1" ]; then
	urls=$1
else
	urls=$(python list-repos.py)
fi

python3 GrimoireELK/utils/kidash.py -e $ES_URL -g \ --import GrimoireELK/dashboards/git-activity.json
for u in $urls; do
	project=$(basename $u)
	echo -n "=== GIT repository $project - "
	populate_scm $u && echo "Done" || echo "FAIL"
done
populate_pipermail && echo "Done" || echo "FAIL"
populate_issues && echo "Done" || echo "FAIL"
