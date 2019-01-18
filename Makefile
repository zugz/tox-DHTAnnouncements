%.md : %.md.sed %.md.in
	sed -f $^ > $@

%.tex: %.beamer.md
	pandoc -s -t beamer $< -V colortheme:seagull -o $@

%.pdf: %.beamer.md
	pandoc -t beamer $< -V colortheme:seagull -o $@

%.pdf: %.md
	pandoc $< -o $@ --toc -N

%.html: %.md
	pandoc $< -o $@


#%.pdf: %.tex %.bbl
#	pdflatex $<
#	pdflatex $<

#%.aux: %.tex
#	pdflatex $<

#%.bbl: %.bib %.aux
#	bibtex $(<:%.bib=%)

pdf: DHTAnnouncements.pdf

test: DHTAnnouncements.pdf
	fbpdf $<
