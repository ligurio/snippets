FOSSIL_BIN=/usr/bin/fossil
FOSSIL_REPO=bugs

prepare:
	${FOSSIL_BIN} init ${FOSSIL_REPO}.fossil
	${FOSSIL_BIN} open ${FOSSIL_REPO}.fossil
	${FOSSIL_BIN} import ${FOSSIL_REPO}.conf

import:
	@echo "Convert data archive to tickets in JSON format"
	python convert-scraped2json.py 2>&1 | tee convert.log
	@echo "Import tickets in JSON format to Fossil SCM"
	python import-json2fossil.py 2>&1 | tee import.log

test:
	python -m unittest tests/import_mail.py	

clean:
	@echo "Cleanup Fossil SCM repository"
	@${FOSSIL_BIN} close ${FOSSIL_REPO}
	rm -f ${FOSSIL_REPO}
