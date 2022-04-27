" Vim syntax file
" Language:    SubUnit Output
" Maintainer:  Sergey Bronnikov <sergeyb@bronevichok.ru>
" Remark:      Simple syntax highlighting for SubUnit output
" License:
" Copyright (c) 2016 Sergey Bronnikov
" Version: 0.0.1

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

syn match Label '\([[:alnum:]\-\.]*\)'
syn keyword Status test testing
syn keyword Status success successful
syn keyword Status failure
syn keyword Status error
syn keyword Status skip
syn keyword Status xfail
syn keyword Status uxsuccess
syn keyword Status nextgroup=Label skipwhite
syn match ProgressValue '\d\+'
syn match ProgressValue '[-+]\d\+'
syn match ProgressValue '[pop\|push]'
syn keyword Progress progress nextgroup=ProgressValue skipwhite
syn match TagsValue '.*'
syn keyword Tags tags nextgroup=TagsValue skipwhite
syn match TimeValue /\d\{4\}-\d\{2\}-\d\{2\}\s+\d\{2\}:\d\{2\}:\d\{2\}\.\d+Z/
syn keyword Time time nextgroup=TimeValue skipwhite

:if version >= 508 || !exists("did_conf_syntax_inits")
  if version < 508
    let did_conf_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink        Label Identifier
  HiLink        Status Keyword
  HiLink        Progress Keyword
  HiLink        ProgressValue Identifier
  HiLink        Tags Keyword
  HiLink        TagsValue Identifier
  HiLink        Time Keyword
  HiLink        TimeValue Identifier
 delcommand HiLink
endif

let b:current_syntax="subunit"
