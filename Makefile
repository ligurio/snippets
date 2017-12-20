# $ spin -a pgpool-v2.0-strict.pml
# $ gcc -w -o pan -D_POSIX_SOURCE -DMEMLIM=128 -DSAFETY -DNOCLAIM -DXUSAFE -DNOFAIR  pan.c
# $ ./pan -v -m10000 -w19 -c10

SPIN=${HOME}/source/spin/Src6.4.7/spin
OPTIONS= 
#OPTIONS+= -D_POSIX_SOURCE -DMEMLIM=128 -DSAFETY -DNOCLAIM -DXUSAFE -DNOFAIR
OPTIONS_RUN= 
#OPTIONS_RUN+= -v -m10000 -w19 -c10
FILE?= pgpool-v2.0-strict.pml

all: build
		./pan ${OPTIONS_RUN}

build: pml
		gcc -w -o pan ${OPTIONS} pan.c

pml:
		${SPIN} -a ${FILE}

clean:
		rm -f pan{,.b,.c,.h,.m,.p,.t}
