WML=wml
WMLFLAGS=-DTABLE_BGCOLOR="\#e5d5e5" -DTABLE_HDCOLOR="\#ccdbe2" \
	-DTABLE_BGCOLOR2="\#e0d7d7" -DWHITE="\#ffffff"
COMMON=common.wml bottom.wml head.wml
OUTPUT=../index.html ../download.html ../lists.html	../ncr.html\
 ../news.html ../documentation.html ../authors.html \
 ../comparison.html

all: $(OUTPUT)

../%.html: %.wml $(COMMON)
	$(WML) $(WMLFLAGS) $< > $@

clean:
	rm -f *~ $(OUTPUT)
