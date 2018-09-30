DISTFLAGS = -q -dBATCH -dNOPAUSE -sDEVICE=pdfwrite \
	-sProcessColorModel=DeviceGray -dPDFSETTINGS=/prepress
CRYPT = -sOwnerPassword="`dd if=/dev/random bs=12 count=1 2>/dev/null | \
	md5sum | awk '{ print $$1 }'` " -dEncryptionR=3 \
	-dKeyLength=128 -dPermissions=-300

.SUFFIXES: .tr .ps .pdf .more

.tr.ps:
	rm -f $@; trap "rm -f $$$$.ps" 0 2 3; \
		tbl $< | troff -F/usr/local/share/heirloom-doctools/font/ | dpost -F/usr/local/share/heirloom-doctools/font/ >$$$$.ps && mv $$$$.ps $@

.ps.pdf:
	gs -sOutputFile=$@ $(DISTFLAGS) -f $<

.tr.more:
	tbl -Tlocale $< | nroff -Tlocale | col -x > $@

all: doc.ps

clean:
	rm -f doc.ps doc.pdf doc.more core log *~ fonts.tmac

mrproper: clean

