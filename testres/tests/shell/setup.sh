# This file should be sourced by all test-scripts
#
# Main functions:
#   prepare_tests(description) - setup for testing, i.e. create repos+config
#   run_test(description, script) - run one test, i.e. eval script
#
# Helper functions
#   cgit_query(querystring) - call cgit with the specified querystring
#   cgit_url(url) - call cgit with the specified virtual url
#
# Example script:
#
# . setup.sh
# prepare_tests "html validation"
# run_test 'repo index' 'cgit_url "/" | tidy -e'
# run_test 'repo summary' 'cgit_url "/foo" | tidy -e'

LF='
'
test_argv=

while test $# != 0
do
	case "$1" in
	--va|--val|--valg|--valgr|--valgri|--valgrin|--valgrind)
		cgit_valgrind=t
		test_argv="$test_argv${LF}--verbose"
		;;
	*)
		test_argv="$test_argv$LF$1"
		;;
	esac
	shift
done

OLDIFS=$IFS
IFS=$LF
set -- $test_argv
IFS=$OLDIFS

: ${TEST_DIRECTORY=$(pwd)/../git/t}
: ${TEST_OUTPUT_DIRECTORY=$(pwd)}
. "$TEST_DIRECTORY"/test-lib.sh

mkrepo() {
	name=$1
	count=$2
	test_create_repo "$name"
	(
		cd "$name"
		n=1
		while test $n -le $count
		do
			echo $n >file-$n
			git add file-$n
			git commit -m "commit $n"
			n=$(expr $n + 1)
		done
		if test "$3" = "testplus"
		then
			echo "hello" >a+b
			git add a+b
			git commit -m "add a+b"
			git branch "1+2"
		fi
	)
}

setup_repos()
{
	rm -rf cache
	mkdir -p cache
	mkrepo repos/foo 5 >/dev/null
	mkrepo repos/bar 50 >/dev/null
	mkrepo repos/foo+bar 10 testplus >/dev/null
	mkrepo "repos/with space" 2 >/dev/null
	mkrepo repos/filter 5 testplus >/dev/null
}

cgit_query()
{
	QUERY_STRING="$1" cgit
}

cgit_url()
{
	QUERY_STRING="url=$1" cgit
}

strip_headers() {
	while read -r line
	do
		test -z "$line" && break
	done
	cat
}

setup_repos
