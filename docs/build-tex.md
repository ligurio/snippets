Overview - https://tex.stackexchange.com/a/211392

```
You are linking there to plain.tex which is a file written in TeX not the source of tex-the-program (which is tex.web)

These days if you want to compile from source it is probably best to start with a full download of the texlive build sources.

The sources are at

http://www.tug.org/texlive/svn/

and that page has hints about where to start if you want to compile. See in particular:

http://www.tug.org/texlive/build.html
```

Source: https://tex.stackexchange.com/questions/111332/how-to-compile-the-source-code-of-tex

TeX source code: https://github.com/TeX-Live/texlive-source/blob/trunk/texk/web2c/tex.web



How-To Build: http://www.tug.org/texlive/build.html

Sources: `rsync -a --delete --exclude=.svn tug.org::tldevsrc/Build/source/ /your/dir/`


```
The files in this directory are master files maintained personally by
Donald E. Knuth. Nobody else is authorized to make any changes whatever
to them! If you modify the files for any purpose, you must give your
files a different name, so that installations of TeX throughout the world
will be 100% compatible when they use the official source files.
```
https://ctan.org/tex-archive/macros/plain/base?lang=en
Download: http://mirrors.ctan.org/macros/plain/base.zip

```
The source code for LaTeX and TeX is written in TeX. The original engine was written in Pascal and translated into various other languages (there is a test for validation). You might have better luck running LaTeX as a separate server with a custom driver. – John Kormylo Aug 8 '17 at 12:48
```

```
Note that TeX90, pdfTeX, XeTeX, etc. are written in WEB (a form of specialised Pascal source), and are nowadays built using WEB2C (part of TeX Live); LuaTeX is natively in C. – Joseph Wright♦ Aug 8 '17 at 13:19
```

web2c https://tug.org/svn/texlive/trunk/Build/source/texk/web2c/web2c/

### TeX-GPC

- How-To Build: http://web.archive.org/web/20130605111836/http://wwwlehre.dhbw-stuttgart.de/~helbig/tex-gpc/tex.pdf
- http://mirror.macomnet.net/pub/CTAN/systems/unix/tex-gpc/tex.pdf
- https://www.ctan.org/tex-archive/systems/unix/tex-gpc/
- http://mirrors.ctan.org/systems/unix/tex-gpc.zip
