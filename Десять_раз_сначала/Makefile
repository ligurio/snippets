MAKRDOWN_FILES += book.md

CSS_FILE ?= epub.css

PANDOC = pandoc
PANDOC_OPT = -s --toc-depth=3 --toc --self-contained title.txt $(MAKRDOWN_FILES)
NAME = 10times

epub: $(MAKRDOWN_FILES) $(CSS_FILE) title.txt
	$(PANDOC) $(PANDOC_OPT) --epub-cover-image=images/B1.png -c $(CSS_FILE) -o $(NAME).epub	

html: $(MAKRDOWN_FILES) $(CSS_FILE)
	$(PANDOC) $(PANDOC_OPT) -o $(NAME).html

pdf: $(MAKRDOWN_FILES)
	$(PANDOC) $(PANDOC_OPT) -o $(NAME).pdf

release: $(NAME).epub $(NAME).html
	zip $(NAME).zip $(NAME).epub $(NAME).html

clean:
	rm -f $(NAME).html $(NAME).epub $(NAME).zip

.PHONY: clean
