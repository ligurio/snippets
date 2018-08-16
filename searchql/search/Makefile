GRAMMAR = search

CLEANFILES = $(GRAMMAR).yy.go $(GRAMMAR).y.go $(GRAMMAR).y y.output

all: $(GRAMMAR).yy.go $(GRAMMAR).y $(GRAMMAR).y.go

$(GRAMMAR).yy.go: $(GRAMMAR).l
	golex -t -o $(GRAMMAR).yy.go $(GRAMMAR).l | gofmt > $(GRAMMAR).yy.go

$(GRAMMAR).y.go: $(GRAMMAR).y
	goyacc -p Search -o $(GRAMMAR).y.go $(GRAMMAR).y

$(GRAMMAR).y: $(GRAMMAR).ebnf
	ebnf2y -pkg search -start Search $(GRAMMAR).ebnf > $(GRAMMAR).y

clean:
	rm -f $(CLEANFILES)
