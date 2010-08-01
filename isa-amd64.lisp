;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEMBLY; Base: 10 -*-
;;;
;;;  (c) copyright 2010 by
;;;           Samium Gromoff (_deepfire@feelingofgreen.ru)
;;;
;;; This library is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU Library General Public
;;; License as published by the Free Software Foundation; either
;;; version 2 of the License, or (at your option) any later version.
;;;
;;; This library is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Library General Public License for more details.
;;;
;;; You should have received a copy of the GNU Library General Public
;;; License along with this library; if not, write to the
;;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;;; Boston, MA  02111-1307  USA.

(in-package :isa-amd64)

(defclass amd64-isa (isa)
  ()
  (:default-initargs
   :name :amd64
   :nop-insn :nop
   :delay-slots 0
   :insn-defines-format-p nil
   :root-shift 26 :root-mask #x3f))

(defparameter *amd64-isa* (make-instance 'amd64-isa))

(defattrset *amd64-isa* :leg-opersz-over
  (:opersize-over . #x66))
(defattrset *amd64-isa* :leg-addrsz-over
  (:addrsize-over . #x67))
(defattrset *amd64-isa* :leg-segment-over
  (:seg-over-cs .   #x2e)
  (:seg-over-ds .   #x3e)
  (:seg-over-es .   #x26)
  (:seg-over-fs .   #x64)
  (:seg-over-gs .   #x65)
  (:seg-over-ss .   #x36))
(defattrset *amd64-isa* :leg-lock
  (:lock .          #xf0))
(defattrset *amd64-isa* :leg-repeat
  (:repn .          #xf2)
  (:rep .           #xf3))
;; the only "otherwise"-requiring node, so far
;; the only non-slot, so far
;; ...a suspicious amount of only's..
(defattrset *amd64-isa* :rex-preprefix
  (:lock .          #b0100))
(defattrset *amd64-isa* :rex-prefix-w
  (:w .             #b1))
(defattrset *amd64-isa* :rex-prefix-r
  (:r .             #b1))
(defattrset *amd64-isa* :rex-prefix-x
  (:x .             #b1))
(defattrset *amd64-isa* :rex-prefix-b
  (:b .             #b1))
(defattrset *amd64-isa* :xop-prefix
  (:twop-prefix .   #x0f))

(defattrset *amd64-isa* :opcode
  (:op-add .       #x00) (:op-add .     #x01) (:op-add .      #x02) (:op-add .       #x03) (:op-add .       #x04) (:op-add .       #x05)  #|  32-bit mode |#  #|  32-bit mode    |#
  (:op-adc .       #x10) (:op-adc .     #x11) (:op-adc .      #x12) (:op-adc .       #x13) (:op-adc .       #x14) (:op-adc .       #x15)  #|  32-bit mode |#  #|  32-bit mode    |#
  (:op-and .       #x20) (:op-and .     #x21) (:op-and .      #x22) (:op-and .       #x23) (:op-and .       #x24) (:op-and .       #x25)  #|  ES seg      |#  #|  32-bit mode    |#
  (:op-xor .       #x30) (:op-xor .     #x31) (:op-xor .      #x32) (:op-xor .       #x33) (:op-xor .       #x34) (:op-xor .       #x35)  #|  SS seg      |#  #|  32-bit mode    |#
  ;; 4[0-7]: REX prefixes
  (:op-push .      #x50) (:op-push .    #x51) (:op-push .     #x52) (:op-push .      #x53) (:op-push .      #x54) (:op-push .      #x55) (:op-push .    #x56) (:op-push .      #x57)
   #|  32-bit mode   |#   #|  32-bit mode |#   #|  32-bit mode  |#   #|  64-bit mode   |#  #| FS seg         |#   #|  GS seg        |#   #|  oper size   |#   #|  addr size     |#
  (:op-jo .        #x70) (:op-jno .     #x71) (:op-jb .       #x72) (:op-jnb .       #x73) (:op-jz .        #x74) (:op-jnz .       #x75) (:op-jbe .     #x76) (:op-jnbe .      #x77)
  (:op-grp1-80 .   #x80) (:op-grp1-81 . #x81)  #|  32-bit mode  |#  (:op-grp1-83 .   #x83) (:op-test .      #x84) (:op-test .      #x85) (:op-xchg .    #x86) (:op-xchg .      #x87)
  (:op-xchg.       #x90) (:op-xchg .    #x91) (:op-xchg.      #x92) (:op-xchg .      #x93) (:op-xchg .      #x94) (:op-xchg .      #x95) (:op-xchg .    #x96) (:op-xchg .      #x97)
  (:op-mov .       #xa0) (:op-mov .     #xa1) (:op-mov .      #xa2) (:op-mov .       #xa3) (:op-movsb .     #xa4) (:op-movsw/d/q . #xa5) (:op-cmpsb .   #xa6) (:op-cmpsw/d/q . #xa7)
  (:op-mov .       #xb0) (:op-mov .     #xb1) (:op-mov .      #xb2) (:op-mov .       #xb3) (:op-mov .       #xb4) (:op-mov .       #xb5) (:op-mov .     #xb6) (:op-mov .       #xb7)
  (:op-grp2-c0 .   #xc0) (:op-grp2-c1 . #xc1) (:op-ret-near . #xc2) (:op-ret-near .  #xc3)  #|  32-bit mode   |#   #|  32-bit mode   |#  (:op-grp11-c6 . #xc6) (:op-grp11-c7 . #xc7)
  (:op-grp2-d0 .   #xd0) (:op-grp2-d1 . #xd1) (:op-grp2-d2 .  #xd2) (:op-grp2-d3 .   #xd3)  #|  32-bit mode   |#   #|  32-bit mode   |#   #|  32-bit mode |#  (:op-xlat .      #xd7)
  (:op-loopne/nz . #xe0) (:op-loope/z . #xe1) (:op-loop .     #xe2) (:op-jxcxz .     #xe3) (:op-in .        #xe4) (:op-in .        #xe5) (:op-out .     #xe6) (:op-out .       #xe7)
   #|  lock          |#  (:op-int1 .    #xf1)  #|  repn         |#   #|  rep           |#  (:op-hlt .       #xf4) (:op-cmc .       #xf5) (:op-grp3-f6 . #xf6) (:op-grp3-f7 .   #xf7)
  (:op-or .        #x08) (:op-or .      #x09) (:op-or .       #x0a) (:op-or .        #x0b) (:op-or .        #x0c) (:op-or .        #x0d)  #|  32-bit mode |#   #|  twop          |#
  (:op-sbb .       #x18) (:op-sbb .     #x19) (:op-sbb .      #x1a) (:op-sbb .       #x1b) (:op-sbb .       #x1c) (:op-sbb .       #x1d)  #|  32-bit mode |#   #|  32-bit mode   |# 
  (:op-sub .       #x28) (:op-sub .     #x29) (:op-sub .      #x2a) (:op-sub .       #x2b) (:op-sub .       #x2c) (:op-sub .       #x2d)  #|  CS seg      |#   #|  32-bit mode   |# 
  (:op-cmp .       #x38) (:op-cmp .     #x39) (:op-cmp .      #x3a) (:op-cmp .       #x3b) (:op-cmp .       #x3c) (:op-cmp .       #x3d)  #|  DS seg      |#   #|  32-bit mode   |# 
  ;; 4[8-f]: REX prefixes
  (:op-pop .       #x58) (:op-pop .     #x59) (:op-pop .      #x5a) (:op-pop .       #x5b) (:op-pop .       #x5c) (:op-pop .       #x5d) (:op-pop .     #x5e) (:op-pop .       #x5f)
  (:op-push .      #x68) (:op-imul .    #x69) (:op-push .     #x6a) (:op-imul .      #x6b) (:op-insb .      #x6c) (:op-insw/d .    #x6d) (:op-outsb .   #x6e) (:op-outsw/d .   #x6f)
  (:op-js .        #x78) (:op-jns .     #x79) (:op-jp .       #x7a) (:op-jnp .       #x7b) (:op-jl .        #x7c) (:op-jnl .       #x7d) (:op-jle .     #x7e) (:op-jnle .      #x7f)
  (:op-mov .       #x88) (:op-mov .     #x89) (:op-mov .      #x8a) (:op-mov .       #x8b) (:op-mov .       #x8c) (:op-lea .       #x8d) (:op-mov .     #x8e) (:op-grp1-8f .   #x8f)
  (:op-cbwde/qe .  #x98) (:op-cwdqo .   #x99)  #|  32-bit mode  |#  (:op-f/wait .    #x9b) (:op-pushf/d/q . #x9c) (:op-popf/d/q .  #x9d) (:op-sahf .    #x9e) (:op-lahf .      #x9f)
  (:op-test .      #xa8) (:op-test .    #xa9) (:op-stosb .    #xaa) (:op-stosw/d/q . #xab) (:op-lodsb .     #xac) (:op-lodsw/d/q . #xad) (:op-scasb .   #xae) (:op-scasw/d/q . #xaf)
  (:op-mov .       #xb8) (:op-mov .     #xb9) (:op-mov .      #xba) (:op-mov .       #xbb) (:op-mov .       #xbc) (:op-mov .       #xbd) (:op-mov .     #xbe) (:op-mov .       #xbf)
  (:op-enter .     #xc8) (:op-leave .   #xc9) (:op-ret .      #xca) (:op-ret .       #xcb) (:op-int3 .      #xcc) (:op-int .       #xcd)  #|  32-bit mode |#  (:op-iret/d/q .  #xcf)
  ;; d[8-f]: x87
  (:op-call .      #xe8) (:op-jmp .     #xe9)  #|  32-bit mode  |#  (:op-jmp .       #xeb) (:op-in .        #xec) (:op-in .        #xed) (:op-out .     #xee) (:op-out .       #xef)
  (:op-clc .       #xf8) (:op-stc .     #xf9) (:op-cli .      #xfa) (:op-sti .       #xfb) (:op-cld .       #xfc) (:op-std .       #xfd)  #|  64-bit mode |#  (:op-grp5 .      #xff))

(defattrset *amd64-isa* :longmode-only-opcode
   #|  .........              .......              ........     |#  (:op-movsxd .    #x63)  #|  .........              .........              .......              .........     |#
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-grp4 .    #xfe)) #|  .........     |#

(defattrset *amd64-isa* :shortmode-only-opcode
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-push-es . #x06) (:op-pop-es .    #x07)
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-push-ss . #x16) (:op-pop-ss .    #x17)
   #|  .........              .......              ........              .........              .........              .........              .......     |#  (:op-daa .       #x27)
   #|  .........              .......              ........              .........              .........              .........              .......     |#  (:op-aaa .       #x37)
  (:op-inc .       #x40) (:op-inc .     #x41) (:op-inc .      #x42) (:op-inc .       #x43) (:op-inc .       #x44) (:op-inc .       #x45) (:op-inc .     #x46) (:op-inc .       #x47)
  (:op-pusha/d .   #x60) (:op-popa/d .  #x61) (:op-bound .    #x62)  #|  .........              .........              .........              .......              .........     |#
   #|  .........              .......     |#  (:op-grp1-82 .  #x82)  #|  .........              .........              .........              .......              .........     |#
   #|  .........              .......              ........              .........     |#  (:op-les .       #xc4) (:op-lds .       #xc5)
   #|  .........              .......              ........              .........     |#  (:op-aam .       #xd4) (:op-aad .       #xd5) (:op-salc .    #xd6)  #|  .........     |#
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-push .    #x0e)  #|  .........     |#
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-push .    #x1e) (:op-pop .       #x1f)
   #|  .........              .......              ........              .........              .........              .........              .......     |#  (:op-das .       #x2f)
   #|  .........              .......              ........              .........              .........              .........              .......     |#  (:op-aas .       #x3f)
  (:op-dec .       #x48) (:op-dec .     #x49) (:op-dec .      #x4a) (:op-dec .       #x4b) (:op-dec .       #x4c) (:op-dec .       #x4d) (:op-dec .     #x4e) (:op-dec .       #x4f)
   #|  .........              .......     |#  (:op-call .     #x9a)  #|  .........              .........              .........              .......              .........     |#
   #|  .........              .......              ........              .........              .........              .........     |#  (:op-into .    #xce)  #|  .........     |#
   #|  .........              .......     |#  (:op-jmp .      #xea)  #|  .........              .........              .........              .......              .........     |#)

(defattrset *amd64-isa* :extended-opcode
  (:xop-grp6 .      #x00) (:xop-grp7 .      #x01) (:xop-lar .       #x02) (:xop-lsl .      #x03)  #|   invalid      |#  (:xop-syscall .  #x05) (:xop-clts .    #x06) (:xop-sysret .   #x07)
  ;; 1[0-7]: prefixed
  (:xop-mov .       #x20) (:xop-mov .       #x21) (:xop-mov .       #x22) (:xop-mov .      #x23)  #|   invalid      |#   #|   invalid      |#   #|   invalid     |#   #|   invalid      |#
  (:xop-wrmsr .     #x30) (:xop-rstsc .     #x31) (:xop-rdmsr .     #x32) (:xop-rdpmc .    #x33)  #|   32-bit mode  |#   #|   32-bit mode  |#   #|   invalid     |#   #|   invalid      |#
  (:xop-cmovo .     #x40) (:xop-cmovno .    #x41) (:xop-cmovb .     #x42) (:xop-cmovnb .   #x43) (:xop-cmovz .    #x44) (:xop-cmovnz .   #x45) (:xop-cmovbe .  #x46) (:xop-cmovnbe .  #x47)
  ;; 5[0-7]: prefixed
  ;; 6[0-7]: prefixed
  ;; 7[0-7]: prefixed
  (:xop-jo .        #x80) (:xop-jno .       #x81) (:xop-jb .        #x82) (:xop-jnb .      #x83) (:xop-jz .       #x84) (:xop-jnz .      #x85) (:xop-jbe .     #x86) (:xop-jnbe .     #x87)
  (:xop-seto .      #x90) (:xop-setno .     #x91) (:xop-setb .      #x92) (:xop-setnb .    #x93) (:xop-setz .     #x94) (:xop-setnz .    #x95) (:xop-setbe .   #x96) (:xop-setnbe .   #x97)
  (:xop-push .      #xa0) (:xop-pop .       #xa1) (:xop-cpuid .     #xa2) (:xop-bt .       #xa3) (:xop-shld .     #xa4) (:xop-shld .     #xa5)  #|   invalid     |#   #|   invalid      |#
  (:xop-cmpxchg .   #xb0) (:xop-cmpxchg .   #xb1) (:xop-lss .       #xb2) (:xop-btr .      #xb3) (:xop-lfs .      #xb4) (:xop-lgs .      #xb5) (:xop-movzx .   #xb6) (:xop-movzx .    #xb7)
  ;; c[0-7]: prefixed
  ;; d[0-7]: prefixed
  ;; e[0-7]: prefixed
  ;; f[0-7]: prefixed
  (:xop-invd .      #x08) (:xop-wbinvd .    #x09)  #|   invalid       |#  (:xop-ud2 .      #x0b)  #|   invalid      |#  (:xop-grp-p .    #x0d) (:xop-femms .   #x0e) (:xop-grp3dnow . #x0f)
  (:xop-grp16 .     #x18) (:xop-nop .       #x19) (:xop-nop .       #x1a) (:xop-nop .      #x1b) (:xop-nop .      #x1c) (:xop-nop .      #x1d) (:xop-nop .     #x1e) (:xop-nop .      #x1f)
  ;; 2[8-f]: prefixed
  ;; 3[8-f]: invalid
  (:xop-cmovs .     #x48) (:xop-cmovns .    #x49) (:xop-cmovp .     #x4a) (:xop-cmovnp .   #x4b) (:xop-cmovl .    #x4c) (:xop-cmovnl .   #x4d) (:xop-cmovle .  #x4e) (:xop-cmovnle .  #x4f)
  ;; 5[8-f]: prefixed
  ;; 6[8-f]: prefixed
  ;; 7[8-f]: prefixed
  (:xop-js .        #x88) (:xop-jns .       #x89) (:xop-jp .        #x8a) (:xop-jnp .      #x8b) (:xop-jl .       #x8c) (:xop-jnl .      #x8d) (:xop-jle .     #x8e) (:xop-jnle .     #x8f)
  (:xop-sets .      #x98) (:xop-setns .     #x99) (:xop-setp .      #x9a) (:xop-setnp .    #x9b) (:xop-setl .     #x9c) (:xop-setnl .    #x9d) (:xop-setle   . #x9e) (:xop-setnle .   #x9f)
  (:xop-push .      #xa8) (:xop-pop .       #xa9) (:xop-rsm .       #xaa) (:xop-bts .      #xab) (:xop-shrd .     #xac) (:xop-shrd .     #xad) (:xop-grp15 .   #xae) (:xop-imul .     #xaf)
  ;; b[8-f]: prefixed
  (:xop-bswap .     #xc8) (:xop-bswap .     #xc9) (:xop-bswap .     #xca) (:xop-bswap .    #xcb) (:xop-bswap .    #xcc) (:xop-bswap .    #xcd) (:xop-bswap .   #xce) (:xop-bswap .    #xcf)
  ;; d[8-f]: prefixed
  ;; e[8-f]: prefixed
  ;; f[8-f]: prefixed
  )

(defattrset *amd64-isa* :shortmode-only-ext-opcode
  #|    .........               .........               .........               ........     |#  (:xop-sysenter . #x34) (:xop-sysexit .  #x35)  #|   .......               ........     |#)

(defattrset *amd64-isa* :opcode-ext-variant-unprefixed
  (:xop-movups .    #x10) (:xop-movups .    #x11) (:xop-movl/hlps . #x12) (:xop-movlps .    #x13) (:xop-unpcklps .  #x14) (:xop-unpckhps . #x15) (:xop-movh/lhps . #x16) (:xop-movhps .  #x17)
  (:xop-movmskps .  #x50) (:xop-sqrtps .    #x51) (:xop-rsqrtps .   #x52) (:xop-rcpps .     #x53) (:xop-andps .     #x54) (:xop-andnps .   #x55) (:xop-orps .     #x56) (:xop-xorps .    #x57)
  (:xop-punpcklbw . #x60) (:xop-punpcklwd . #x61) (:xop-punpckldq . #x62) (:xop-packsswb .  #x63) (:xop-pcmpgtb .   #x64) (:xop-pcmpgtw .  #x65) (:xop-pcmpgtd .  #x66) (:xop-packuswb . #x67)
  (:xop-pshufw .    #x70) (:xop-grp12-u .   #x71) (:xop-grp13-u .   #x72) (:xop-grp14-u .   #x73) (:xop-pcmpeqb .   #x74) (:xop-pcmpeqw .  #x75) (:xop-pcmpeqd .  #x76) (:xop-emss .     #x77)
  (:xop-xadd .      #xc0) (:xop-xadd .      #xc1) (:xop-cmpps .     #xc2) (:xop-movnti .    #xc3) (:xop-pinsrw .    #xc4) (:xop-pextsrw .  #xc5) (:xop-shufps .   #xc6) (:xop-grp9-u .   #xc7)
   #|   invalid       |#  (:xop-psrlw .     #xd1) (:xop-psrld .     #xd2) (:xop-psrlq .     #xd3) (:xop-paddq .     #xd4) (:xop-pmullw .   #xd5)  #|   invalid      |#  (:xop-pmovmskb . #xd7)
  (:xop-pavgb .     #xe0) (:xop-psraw .     #xe1) (:xop-psrad .     #xe2) (:xop-pavgw .     #xe3) (:xop-pmulhuw .   #xe4) (:xop-pmulhw .   #xe5)  #|   invalid      |#  (:xop-movntq .   #xe7)
   #|   invalid       |#  (:xop-psllw .     #xf1) (:xop-pslld .     #xf2) (:xop-psllq .     #xf3) (:xop-pmuludq .   #xf4) (:xop-pmaddwd .  #xf5) (:xop-psadbw .   #xf6) (:xop-maskmovq . #xf7)
  (:xop-movaps .    #x28) (:xop-movaps .    #x29) (:xop-cvtpi2ps .  #x2a) (:xop-movntps .   #x2b) (:xop-cvttps2pi . #x2c) (:xop-cvtps2pi . #x2d) (:xop-ucomiss .  #x2e) (:xop-comiss .   #x2f)
  (:xop-addps .     #x58) (:xop-mulps .     #x59) (:xop-cvtps2pd .  #x5a) (:xop-cvtdq2ps .  #x5b) (:xop-subps .     #x5c) (:xop-minps .    #x5d) (:xop-divps .    #x5e) (:xop-maxps .    #x5f)
  (:xop-punpckhwb . #x68) (:xop-punpckhwd . #x69) (:xop-punpckhdq . #x6a) (:xop-packssdw .  #x6b)  #|   invalid       |#   #|   invalid      |#  (:xop-movd .     #x6e) (:xop-movq .     #x6f)
   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid      |#  (:xop-movd .     #x7e) (:xop-movq .     #x7f)
   #|   reserved      |#  (:xop-grp10 .     #xb9) (:xop-grp8 .      #xba) (:xop-btc .       #xbb) (:xop-bsf .       #xbc) (:xop-bsr .      #xbd) (:xop-movsx .    #xbe) (:xop-movsx .    #xbf)
  (:xop-psubusb .   #xd8) (:xop-psubusw .   #xd9) (:xop-pminub .    #xda) (:xop-pand .      #xdb) (:xop-paddusb .   #xdc) (:xop-paddusw .  #xdd) (:xop-pmaxub .   #xde) (:xop-pandn .    #xdf)
  (:xop-psubsb .    #xe8) (:xop-psubsw .    #xe9) (:xop-pminsw .    #xea) (:xop-por .       #xeb) (:xop-paddsb .    #xec) (:xop-paddsw .   #xed) (:xop-pmaxsw .   #xee) (:xop-pxor .     #xef)
  (:xop-psubb .     #xf8) (:xop-psubw .     #xf9) (:xop-psubd .     #xfa) (:xop-psubq .     #xfb) (:xop-padb .      #xfc) (:xop-padw .     #xfd) (:xop-padd .     #xfe)  #|   invalid      |#)

(defattrset *amd64-isa* :opcode-ext-variant-f3-prefixed
  (:xop-movss .     #x10) (:xop-movss .     #x11) (:xop-movsldup .  #x12)  #|   invalid       |#   #|   invalid       |#   #|  invalid       |#  (:xop-movshdup . #x16)  #|   invalid      |#
   #|   invalid       |#  (:xop-sqrtss .    #x51) (:xop-rsqrtss .   #x52) (:xop-rcpss .     #x53)  #|   invalid       |#   #|  invalid       |#   #|   invalid      |#   #|   invalid      |#
  ;; 6[0-7]: invalid
  (:xop-pshufhw .   #x70) #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|  invalid       |#   #|   invalid      |#   #|   invalid      |#
  (:xop-xadd .      #xc0) (:xop-xadd .      #xc1) (:xop-cmpss .     #xc2)  #|   invalid       |#   #|   invalid       |#   #|  invalid       |#   #|   invalid      |#  (:xop-grp9 .     #xc7)
   #|   invalid       |#  #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|  invalid       |#  (:xop-movq2dq .  #xd6)  #|   invalid      |#
   #|   invalid       |#  #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|  invalid       |#  (:xop-cvtdq2pd . #xe6)  #|   invalid      |#
  ;; f[0-7]: invalid
   #|   invalid       |#   #|   invalid       |#  (:xop-cvtsi2ss .  #x2a) (:xop-movntss .   #x2b) (:xop-cvttss2si . #x2c) (:xop-cvtss2si . #x2d)  #|   invalid      |#   #|   invalid      |#
  (:xop-addss .     #x58) (:xop-mulss .     #x59) (:xop-cvtss2sd .  #x5a) (:xop-cvttps2dq . #x5b) (:xop-subss       #x5c) (:xop-minss .    #x5d) (:xop-divss .    #x5e) (:xop-maxss .    #x5f)
   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid      |#   #|   invalid      |#  (:xop-movdqu     #x6f)
   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid      |#  (:xop-movq .     #x7e) (:xop-movdqu .   #x7f)
  (:xop-popcnt .    #xb8)  #|   reserved      |#   #|   reserved      |#   #|   reserved      |#   #|   reserved      |#  (:xop-lzcnt .    #xbd)  #|   reserved     |#   #|   reserved     |#
  ;; d[8-f]: invalid
  ;; e[8-f]: invalid
  ;; f[8-f]: invalid
  )

(defattrset *amd64-isa* :opcode-ext-variant-66-prefixed
  (:xop-movupd .    #x10) (:xop-movupd .    #x11) (:xop-movlpd .    #x12) (:xop-movlpd .    #x13) (:xop-unpcklpd .   #x14) (:xop-unpckhpd .   #x15) (:xop-movhpd .   #x16) (:xop-movhpd .   #x17)
  (:xop-movmskpd .  #x50) (:xop-sqrtpd .    #x51)  #|   invalid       |#   #|   invalid       |#  (:xop-andpd .      #x54) (:xop-andnpd .     #x55) (:xop-orpd .     #x56) (:xop-xorpd .    #x57)
  (:xop-punpcklbw . #x60) (:xop-punpcklwd . #x61) (:xop-punpckldq . #x62) (:xop-packsswb .  #x63) (:xop-pcmpgtb .    #x64) (:xop-pcmpgtw .    #x65) (:xop-pcmpgtd .  #x66) (:xop-packuswb . #x67)
  (:xop-pshufd .    #x70) (:xop-grp12-p66 . #x71) (:xop-grp13-p66 . #x72) (:xop-grp14-p66 . #x73) (:xop-pcmpeqb .    #x74) (:xop-pcmpeqw .    #x75) (:xop-pcmpeqd .  #x76)  #|   invalid      |#
  (:xop-xadd .      #xc0) (:xop-xadd .      #xc1) (:xop-cmppd .     #xc2)  #|   invalid       |#  (:xop-pinsrw .     #xc4) (:xop-pextsrw .    #xc5) (:xop-shufpd .   #xc6) (:xop-grp9 .     #xc7)
  (:xop-addsubpd .  #xd0) (:xop-psrlw .     #xd1) (:xop-psrld .     #xd2) (:xop-psrlq .     #xd3) (:xop-paddq .      #xd4) (:xop-pmullw .     #xd5) (:xop-movq .     #xd6) (:xop-pmovmskb . #xd7)
  (:xop-pavgb .     #xe0) (:xop-psraw .     #xe1) (:xop-psrad .     #xe2) (:xop-pavgw .     #xe3) (:xop-pmulhuw .    #xe4) (:xop-pmulhw .     #xe5) (:xop-cvttpd2d . #xe6) (:xop-movntdq .  #xe7)
   #|   invalid       |#  (:xop-psllw .     #xf1) (:xop-pslld .     #xf2) (:xop-psllq .     #xf3) (:xop-pmuludq .    #xf4) (:xop-pmaddwd .    #xf5) (:xop-psadbw .   #xf6) (:xop-maskmovdqu . #xf7)
  (:xop-movapd .    #x28) (:xop-movapd .    #x29) (:xop-cvtpi2pd .  #x2a) (:xop-movntpd .   #x2b) (:xop-cvttpd2pi .  #x2c) (:xop-cvtpd2pi .   #x2d) (:xop-ucomisd .  #x2e) (:xop-comisd .   #x2f)
  (:xop-addpd .     #x58) (:xop-mulpd .     #x59) (:xop-cvtpd2ps .  #x5a) (:xop-cvtps2dq .  #x5b) (:xop-subpd .      #x5c) (:xop-minpd .      #x5d) (:xop-divpd .    #x5e) (:xop-maxpd .    #x5f)
  (:xop-punpckhwb . #x68) (:xop-punpckhwd . #x69) (:xop-punpckhdq . #x6a) (:xop-packssdw .  #x6b) (:xop-punpcklqdq . #x6c) (:xop-punpckhqdq . #x6d) (:xop-movd .     #x6e) (:xop-movdqa .   #x6f)
  (:xop-grp17 .     #x78) (:xop-extrq .     #x79)  #|   invalid       |#   #|   invalid       |#  (:xop-haddpd       #x7c) (:xop-hsubpd .     #x7d)  (:xop-movd .    #x7e) (:xop-movdqa .   #x7f)
  ;; b[8-f]: strange irregularity (heh) -- absence..
  (:xop-psubusb .   #xd8) (:xop-psubusw .   #xd9) (:xop-pminub .    #xda) (:xop-pand .      #xdb) (:xop-paddusb .    #xdc) (:xop-paddusw .    #xdd) (:xop-pmaxub .   #xde) (:xop-pandn .    #xdf)
  (:xop-psubsb .    #xe8) (:xop-psubsw .    #xe9) (:xop-pminsw .    #xea) (:xop-por .       #xeb) (:xop-paddsb .     #xec) (:xop-paddsw .     #xed) (:xop-pmaxsw .   #xee) (:xop-pxor .     #xef)
  (:xop-psubb .     #xf8) (:xop-psubw .     #xf9) (:xop-psubd .     #xfa) (:xop-psubq .     #xfb) (:xop-padb .       #xfc) (:xop-padw .       #xfd) (:xop-padd .     #xfe)  #|   invalid      |#)

(defattrset *amd64-isa* :opcode-ext-variant-f2-prefixed
  (:xop-movsd .     #x10) (:xop-movsd .     #x11) (:xop-movddup .   #x12)  #|   invalid       |#   #|   invalid        |#   #|   invalid        |#   #|   invalid      |#   #|   invalid      |#
   #|   invalid       |#  (:xop-sqrtsd .    #x51)  #|   invalid       |#   #|   invalid       |#   #|   invalid        |#   #|   invalid        |#   #|   invalid      |#   #|   invalid      |#
  ;; 6[0-7]: invalid
  (:xop-pshuflw .   #x70) #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid        |#   #|   invalid        |#   #|   invalid      |#   #|   invalid      |#
  (:xop-xadd .      #xc0) (:xop-xadd .      #xc1) (:xop-cmpsd .     #xc2)  #|   invalid       |#   #|   invalid        |#   #|   invalid        |#   #|   invalid      |#  (:xop-grp9 .     #xc7)
  (:xop-addsubps .  #xd0) #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid        |#   #|   invalid        |#  (:xop-movdq2q .  #xd6)  #|   invalid      |#
   #|   invalid       |#  #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid        |#   #|   invalid        |#  (:xop-cvtpd2dq . #xe6)  #|   invalid      |#
  (:xop-lddqu .     #xf0) #|    invalid       |#   #|   invalid       |#   #|   invalid       |#   #|   invalid        |#   #|   invalid        |#   #|   invalid      |#   #|   invalid      |#
   #|   invalid       |#   #|   invalid       |#  (:xop-cvtsi2sd .  #x2a) (:xop-movntsd .   #x2b) (:xop-cvttsd2si .  #x2c) (:xop-cvtsd2si .   #x2d)  #|   invalid      |#   #|   invalid      |#
  (:xop-addsd .     #x58) (:xop-mulsd .     #x59) (:xop-cvtsd2ss .  #x5a)  #|   invalid       |#  (:xop-subsd        #x5c) (:xop-minsd .      #x5d) (:xop-divsd .    #x5e) (:xop-maxsd .    #x5f)
  ;; 6[8-f]: invalid
  (:xop-insertq .   #x78) (:xop-insertq .   #x79)  #|   invalid       |#   #|   invalid       |#  (:xop-haddps       #x5c) (:xop-hsubps .     #x5d)  #|   invalid      |#   #|   invalid      |#
  ;; b[8-f]: invalid
  ;; d[8-f]: invalid
  ;; e[8-f]: invalid
  ;; f[8-f]: invalid
  )

(defattrset *amd64-isa* modrm-grp1-80
  (:mop-add .    #x0) (:mop-or .     #x1) (:mop-adc .    #x2) (:mop-sbb .    #x3) (:mop-and .    #x4) (:mop-sub .    #x5) (:mop-xor .    #x6) (:mop-cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-81
  (:mop-add .    #x0) (:mop-or .     #x1) (:mop-adc .    #x2) (:mop-sbb .    #x3) (:mop-and .    #x4) (:mop-sub .    #x5) (:mop-xor .    #x6) (:mop-cmp .    #x7))
(defattrset *amd64-isa* shortmode-only-modrm-grp1-82
  (:mop-add .    #x0) (:mop-or .     #x1) (:mop-adc .    #x2) (:mop-sbb .    #x3) (:mop-and .    #x4) (:mop-sub .    #x5) (:mop-xor .    #x6) (:mop-cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-83
  (:mop-add .    #x0) (:mop-or .     #x1) (:mop-adc .    #x2) (:mop-sbb .    #x3) (:mop-and .    #x4) (:mop-sub .    #x5) (:mop-xor .    #x6) (:mop-cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-8f
  (:mop-pop .    #x0)  #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)

(defattrset *amd64-isa* modrm-grp2-c0
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-c1
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d0
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d1
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d2
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d3
  (:mop-rol .    #x0) (:mop-ror .    #x1) (:mop-rcl .    #x2) (:mop-rcr .    #x3) (:mop-shl/sal . #x4) (:mop-shr .   #x5) (:mop-shl/sal . #x6) (:mop-sar .   #x7))

(defattrset *amd64-isa* modrm-grp3-f6
  (:mop-test .   #x0) (:mop-test .   #x1) (:mop-not .    #x2) (:mop-neg .    #x3) (:mop-mul .    #x4) (:mop-imul .   #x5) (:mop-div .     #x6) (:mop-idiv .  #x7))
(defattrset *amd64-isa* modrm-grp3-f7
  (:mop-test .   #x0) (:mop-test .   #x1) (:mop-not .    #x2) (:mop-neg .    #x3) (:mop-mul .    #x4) (:mop-imul .   #x5) (:mop-div .     #x6) (:mop-idiv .  #x7))

(defattrset *amd64-isa* modrm-grp4
  (:mop-inc .    #x0) (:mop-dec .    #x1)  #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid      |#   #| invalid    |#)

(defattrset *amd64-isa* modrm-grp5
  (:mop-inc .    #x0) (:mop-dec .    #x1) (:mop-call .   #x2) (:mop-call .   #x3) (:mop-jmp .    #x4) (:mop-jmp .    #x5) (:mop-push .    #x6)  #| invalid    |#)

(defattrset *amd64-isa* modrm-grp6
  (:mop-sldt .   #x0) (:mop-str .    #x1) (:mop-lldt .   #x2) (:mop-ltr .    #x3) (:mop-verr .   #x4) (:mop-verw .   #x5)  #| invalid      |#   #| invalid    |#)

(defattrset *amd64-isa* modrm-grp7
  (:mop-sgdt .   #x0) (:mop-trik0 .  #x1) (:mop-lgdt .   #x2) (:mop-trik1 .  #x3) (:mop-smsw .   #x4)  #| invalid     |#  (:mop-lmsw .    #x6) (:mop-trik2 . #x7))

(defattrset *amd64-isa* modrm-grp7-nmod11
  (:mop-sidt .     #x1) (:mop-lidt .     #x3) (:mop-invlpg .  #x7))
(defattrset *amd64-isa* modrm-grp7-mod11-trik0
  (:trik-swapgs .  #x0) (:trik-rdtscp .  #x1))
(defattrset *amd64-isa* modrm-grp7-mod11-trik1
  (:trik-vmrun .   #x0) (:trik-vmmcall . #x1) (:trik-vmload . #x2) (:trik-vmsave . #x3) (:trik-stgi . #x4) (:trik-clgi . #x5) (:trik-skinit . #x6) (:trik-invlpga . #x7))
(defattrset *amd64-isa* modrm-grp7-mod11-trik2
  (:trik-monitor . #x0) (:trik-mwait .   #x1))

(defattrset *amd64-isa* modrm-grp8
   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#  (:mop-bt .     #x4) (:mop-bts .    #x5) (:mop-btr .    #x6) (:mop-btc .    #x7))

(defattrset *amd64-isa* modrm-grp9
   #| invalid     |#  (:mop-cmpxchg8b . #x1) #| invalid   |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)

(defattrset *amd64-isa* modrm-grp10 ;; what a genius plan...
   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)

(defattrset *amd64-isa* modrm-grp11-c6
  (:mop-mov .    #x0)  #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)
(defattrset *amd64-isa* modrm-grp11-c7
  (:mop-mov .    #x0)  #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)

(defattrset *amd64-isa* modrm-grp12-u
   #| invalid     |#   #| invalid     |#  (:mop-psrlw .  #x2)  #| invalid     |#  (:mop-psraw .  #x4)  #| invalid     |#  (:mop-psllw .  #x6)  #| invalid     |#)
(defattrset *amd64-isa* modrm-grp12-66
   #| invalid     |#   #| invalid     |#  (:mop-psrlw .  #x2)  #| invalid     |#  (:mop-psraw .  #x4)  #| invalid     |#  (:mop-psllw .  #x6)  #| invalid     |#)

(defattrset *amd64-isa* modrm-grp13-u
   #| invalid     |#   #| invalid     |#  (:mop-psrld .  #x2)  #| invalid     |#  (:mop-psrad .  #x4)  #| invalid     |#  (:mop-pslld .  #x6)  #| invalid     |#)
(defattrset *amd64-isa* modrm-grp13-66
   #| invalid     |#   #| invalid     |#  (:mop-psrld .  #x2)  #| invalid     |#  (:mop-psrad .  #x4)  #| invalid     |#  (:mop-pslld .  #x6)  #| invalid     |#)

(defattrset *amd64-isa* modrm-grp14-u
   #| invalid     |#   #| invalid     |#  (:mop-psrlq .  #x2)  #| invalid     |#   #| invalid     |#   #| invalid     |#  (:mop-psllq .  #x6)  #| invalid     |#)
(defattrset *amd64-isa* modrm-grp14-66
   #| invalid     |#   #| invalid     |#  (:mop-psrlq .  #x2) (:mop-psrldq . #x3)  #| invalid     |#   #| invalid     |#  (:mop-psllq .  #x6) (:mop-pslldq . #x7))

(defattrset *amd64-isa* modrm-grp15
  (:mop-fxsave . #x0) (:mop-fxrstor . #x1) (:mop-ldmxcsr . #x2) (:mop-stmxcsr . #x3) #| invalid   |#   #| trickery    |#   #| trickery    |#   #| trickery    |#)
(defattrset *amd64-isa* modrm-grp15-nmod11
                                                                                                                                              (:mop-clflush . #x7))
(defattrset *amd64-isa* modrm-grp15-mod11
                                                                                                    (:mop-mfence  . #x5) (:mop-lfence  . #x6) (:mop-sfence  . #x7))

(defattrset *amd64-isa* modrm-grp16
  (:mop-prefetch . #x0) (:mop-prefetch . #x1) (:mop-prefetch . #x2) (:mop-prefetch . #x3) (:mop-nop . #x4) (:mop-nop . #x5) (:mop-nop .  #x6) (:mop-nop .    #x7))

(defattrset *amd64-isa* modrm-grp17
  (:mop-extrq .  #x0)  #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)

(defattrset *amd64-isa* modrm-grpp
  (:mop-prefetch . #x0) (:mop-prefetch . #x1) #| reserved |# (:mop-prefetch . #x3) #| invalid     |#   #| invalid     |#   #| invalid     |#   #| invalid     |#)


;;; ModRM
;;;
;; C - reg:control
;; D - reg:debug
;; E - GPR/mem(segreg,sib,disp)
;; G - reg:GPR
;; M - mem
;; N - r/m:MMX64, mod:11
;; P - reg:MMX64
;; Q - 64bit MMX/mem(segreg,sib,disp)
;; R - r/m:GPR, mod:11
;; S - reg:segreg
;; U - r/m:XMM128, mod:11
;; V - reg:XMM128
;; W - 128bit XMM/mem(segreg,sib,disp)

;;; Misc
;;;
;; A - imm farptr
;; F - rflags
;; I - imm
;; J - rip-relative offset
;; O - imm offset, modrm-less, sib-less
;; X - ds.rsi
;; Y - es.rdi
;; a - two consecutive memory operands, used in BOUND
;; b - force byte
;; w - force word
;; d - force dword
;; q - force qword (64 bit)
;; dq - force double qword (128 bit)
;; p - 32/48 bit farptr
;; pi - MMX packed int (64 bit)
;; ps - SP packed FP (128 bit)
;; pd - DP packed FP (128 bit)
;; s - 6/10 byte pseudo-descriptor 
;; si - scalar dword
;; ss - scalar SP FP
;; sd - scalar DP FP
;; v - integer, depending on the EOpS
;; z - { 16 <= EOpS 32, 32 <= EOpS { 32, 64 }}
;; /... - modrm reg/sib base

(defmacro defamd64format (id &rest param-spec)
  `(defformat *amd64-isa* ,id () ,param-spec))

;; Issues:
;;  the correspondence of sources and destinatios to instruction arguments is unclear, and in particular,
;;  whether we have the first argument as source is unclear from our representation
;;
;;  GDTR, IDTR, RPL, DPL, STAR, and, likely, some other system registers are either not accounted for properly, or ignored completely

;; Mnemonics:
;;  > - depends on RFLAGS
;;  < - modifies RFLAGS
;;  @ - modifies RIP and, maybe, CS and/or RSP, implies |
;;  @@ - like @, but modifies more
;;  @@@ - like @, but modifies still more
;;  # - port I/O
;;  $ - system-level crap is going-on
;;;; invert sourceness/destness of first/second/ argument
;;  | - does not modify its first argument
;;  2| - /does/ modify its second argument
;;  ! - does not source its first argument
;;  2! - does not source its second argument

(defamd64format "<>AL"                   (:rflags :al)                    (:rflags :al))                                 ;; AAA, AAS, DAA, DAS
(defamd64format "<AL, AH"                (:rflags :al)                    (:al :ah))                                     ;; AAD
(defamd64format "<2|2!AL, AH"            (:rflags :al :ah)                (:al :imm8))                                   ;; AAM
(defamd64format "<AL, imm8"              (:rflags :al)                    (:al :imm8))                                   ;; ADC, ADD, SBB, SUB
(defamd64format "<AX, imm16"             (:rflags :ax)                    (:ax :imm16))                                  ;; ADC, ADD, SBB, SUB
(defamd64format "<EAX, imm32"            (:rflags :eax)                   (:eax :imm32))                                 ;; ADC, ADD, SBB, SUB
(defamd64format "<RAX, imm32"            (:rflags :rax)                   (:rax :imm32))                                 ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem8, imm8"        (:rflags :reg/mem8)              (:reg/mem8 :imm8))                             ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem16, imm16"      (:rflags :reg/mem16)             (:reg/mem16 :imm16))                           ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem32, imm32"      (:rflags :reg/mem32)             (:reg/mem32 :imm32))                           ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem64, imm32"      (:rflags :reg/mem64)             (:reg/mem64 :imm32))                           ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem16, imm8"       (:rflags :reg/mem16)             (:reg/mem16 :imm8))                            ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg/mem32, imm8"       (:rflags :reg/mem32)             (:reg/mem32 :imm8))                            ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg/mem64, imm8"       (:rflags :reg/mem64)             (:reg/mem64 :imm8))                            ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg/mem8, reg8"        (:rflags :reg/mem8)              (:reg/mem8 :reg8))                             ;; ADC, ADD, SBB, SUB
(defamd64format "<reg/mem16, reg16"      (:rflags :reg/mem16)             (:reg/mem16 :reg16))                           ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg/mem32, reg32"      (:rflags :reg/mem32)             (:reg/mem32 :reg32))                           ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg/mem64, reg64"      (:rflags :reg/mem64)             (:reg/mem64 :reg64))                           ;; ADC, ADD, SBB, SUB, BTC, BTR, BTS
(defamd64format "<reg8, reg/mem8"        (:rflags :reg8)                  (:reg8 :reg/mem8))                             ;; ADC, ADD, SBB, SUB
(defamd64format "<reg16, reg/mem16"      (:rflags :reg16)                 (:reg16 :reg/mem16))                           ;; ADC, ADD, SBB, SUB, BSF, BSR, IMUL
(defamd64format "<reg32, reg/mem32"      (:rflags :reg32)                 (:reg32 :reg/mem32))                           ;; ADC, ADD, SBB, SUB, BSF, BSR, IMUL
(defamd64format "<reg64, reg/mem64"      (:rflags :reg64)                 (:reg64 :reg/mem64))                           ;; ADC, ADD, SBB, SUB, BSF, BSR, IMUL

(defamd64format "AL, imm8"               (:al)                            (:al :imm8))                                   ;; AND, OR, XOR
(defamd64format "AX, imm16"              (:ax)                            (:ax :imm1))                                   ;; AND, OR, XOR
(defamd64format "EAX, imm32"             (:eax)                           (:eax :imm32))                                 ;; AND, OR, XOR
(defamd64format "RAX, imm32"             (:rax)                           (:rax :imm32))                                 ;; AND, OR, XOR
(defamd64format "reg/mem8, imm8"         (:reg/mem8)                      (:reg/mem8 :imm8))                             ;; AND, OR, XOR
(defamd64format "reg/mem16, imm16"       (:reg/mem16)                     (:reg/mem16 :imm16))                           ;; AND, OR, XOR
(defamd64format "reg/mem32, imm32"       (:reg/mem32)                     (:reg/mem32 :imm32))                           ;; AND, OR, XOR
(defamd64format "reg/mem64, imm32"       (:reg/mem64)                     (:reg/mem64 :imm32))                           ;; AND, OR, XOR
(defamd64format "reg/mem16, imm8"        (:reg/mem16)                     (:reg/mem16 :imm8))                            ;; AND, OR, XOR
(defamd64format "reg/mem32, imm8"        (:reg/mem32)                     (:reg/mem32 :imm8))                            ;; AND, OR, XOR
(defamd64format "reg/mem64, imm8"        (:reg/mem64)                     (:reg/mem64 :imm8))                            ;; AND, OR, XOR
(defamd64format "reg/mem8, reg8"         (:reg/mem8)                      (:reg/mem8 :reg8))                             ;; AND, OR, XOR
(defamd64format "reg/mem16, reg16"       (:reg/mem16)                     (:reg/mem16 :reg16))                           ;; AND, OR, XOR
(defamd64format "reg/mem32, reg32"       (:reg/mem32)                     (:reg/mem32 :reg32))                           ;; AND, OR, XOR
(defamd64format "reg/mem64, reg64"       (:reg/mem64)                     (:reg/mem64 :reg64))                           ;; AND, OR, XOR
(defamd64format "reg8, reg/mem8"         (:reg8)                          (:reg8 :reg/mem8))                             ;; AND, OR, XOR
(defamd64format "reg16, reg/mem16"       (:reg16)                         (:reg16 :reg/mem16))                           ;; AND, OR, XOR
(defamd64format "reg32, reg/mem32"       (:reg32)                         (:reg32 :reg/mem32))                           ;; AND, OR, XOR
(defamd64format "reg64, reg/mem64"       (:reg64)                         (:reg64 :reg/mem64))                           ;; AND, OR, XOR

(defamd64format ">!reg/mem8"             (:reg/mem8)                      (:rflags))                                     ;; SETxx
(defamd64format ">reg16, reg/mem16"      (:reg16)                         (:rflags :reg16 :reg/mem16))                   ;; CMOVxx
(defamd64format ">reg32, reg/mem32"      (:reg32)                         (:rflags :reg32 :reg/mem32))                   ;; CMOVxx
(defamd64format ">reg64, reg/mem64"      (:reg64)                         (:rflags :reg64 :reg/mem64))                   ;; CMOVxx

(defamd64format "<|AL, imm8"             (:rflags)                        (:al :imm8))                                   ;; CMP, TEST
(defamd64format "<|AX, imm16"            (:rflags)                        (:ax :imm16))                                  ;; CMP, TEST
(defamd64format "<|EAX, imm32"           (:rflags)                        (:eax :imm32))                                 ;; CMP, TEST
(defamd64format "<|RAX, imm32"           (:rflags)                        (:rax :imm32))                                 ;; CMP, TEST
(defamd64format "<|reg/mem8, imm8"       (:rflags)                        (:reg/mem8 :imm8))                             ;; CMP, TEST
(defamd64format "<|reg/mem16, imm16"     (:rflags)                        (:reg/mem16 :imm16))                           ;; CMP, TEST
(defamd64format "<|reg/mem32, imm32"     (:rflags)                        (:reg/mem32 :imm32))                           ;; CMP, TEST
(defamd64format "<|reg/mem64, imm32"     (:rflags)                        (:reg/mem64 :imm32))                           ;; CMP, TEST
(defamd64format "<|reg/mem16, imm8"      (:rflags)                        (:reg/mem16 :imm8))                            ;; CMP, BT
(defamd64format "<|reg/mem32, imm8"      (:rflags)                        (:reg/mem32 :imm8))                            ;; CMP, BT
(defamd64format "<|reg/mem64, imm8"      (:rflags)                        (:reg/mem64 :imm8))                            ;; CMP, BT
(defamd64format "<|reg/mem8, reg8"       (:rflags)                        (:reg/mem8 :reg8))                             ;; CMP, TEST
(defamd64format "<|reg/mem16, reg16"     (:rflags)                        (:reg/mem16 :reg16))                           ;; CMP, TEST, BT
(defamd64format "<|reg/mem32, reg32"     (:rflags)                        (:reg/mem32 :reg32))                           ;; CMP, TEST, BT
(defamd64format "<|reg/mem64, reg64"     (:rflags)                        (:reg/mem64 :reg64))                           ;; CMP, TEST, BT
(defamd64format "<|reg8, reg/mem8"       (:rflags)                        (:reg8 :reg/mem8))                             ;; CMP
(defamd64format "<|reg16, reg/mem16"     (:rflags)                        (:reg16 :reg/mem16))                           ;; CMP
(defamd64format "<|reg32, reg/mem32"     (:rflags)                        (:reg32 :reg/mem32))                           ;; CMP
(defamd64format "<|reg64, reg/mem64"     (:rflags)                        (:reg64 :reg/mem64))                           ;; CMP

(defamd64format "reg/mem8"               (:reg/mem8)                      (:reg/mem8))                                   ;; NOT
(defamd64format "reg/mem16"              (:reg/mem16)                     (:reg/mem16))                                  ;; NOT
(defamd64format "reg/mem32"              (:reg/mem32)                     (:reg/mem32))                                  ;; NOT
(defamd64format "reg/mem64"              (:reg/mem64)                     (:reg/mem64))                                  ;; NOT

(defamd64format "<reg/mem8"              (:rflags :reg/mem8)              (:reg/mem8))                                   ;; NEG, DEC, INC
(defamd64format "<reg/mem16"             (:rflags :reg/mem16)             (:reg/mem16))                                  ;; NEG, DEC, INC
(defamd64format "<reg/mem32"             (:rflags :reg/mem32)             (:reg/mem32))                                  ;; NEG, DEC, INC
(defamd64format "<reg/mem64"             (:rflags :reg/mem64)             (:reg/mem64))                                  ;; NEG, DEC, INC

(defamd64format "|reg16, mem32"          ()                               (:reg16 :mem32))                               ;; BOUND
(defamd64format "|reg32, mem64"          ()                               (:reg32 :mem64))                               ;; BOUND

(defamd64format "<reg16"                 (:rflags :reg16)                 (:reg16))                                      ;; DEC, INC
(defamd64format "<reg32"                 (:rflags :reg32)                 (:reg32))                                      ;; DEC, INC

(defamd64format "reg32"                  (:reg32)                         (:reg32))                                      ;; BSWAP
(defamd64format "reg64"                  (:reg64)                         (:reg64))                                      ;; BSWAP

;;;;
;;;; Interrupts
;;;;
(defamd64format "$@<>imm8"               (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:rflags :imm8 :rip :rsp :cs :ss :mem)) ;; INT, actually potentially it touches a lot more...
(defamd64format "$@>"                    (:rip :cpl :cs :tss)                       (:rflags))                              ;; INTO, actually potentially it touches a lot more...
(defamd64format "$@<"                    (:rip :rflags)                   ())                                               ;; INT3, actually potentially it touches a lot more...
(defamd64format "$@@<"                   (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:cpl :cs :tss))                        ;; IRET, IRETD, IRETQ

;;;;
;;;; Jumps, calls, returns and branches
;;;;
(defamd64format "@immoff8"               (:rip)                           (:immoff8))                                    ;; JMP
(defamd64format "@immoff16"              (:rip)                           (:immoff16))                                   ;; JMP
(defamd64format "@immoff32"              (:rip)                           (:immoff32))                                   ;; JMP
(defamd64format "@reg/mem16"             (:rip)                           (:reg/mem16))                                  ;; JMP
(defamd64format "@reg/mem32"             (:rip)                           (:reg/mem32))                                  ;; JMP
(defamd64format "@reg/mem64"             (:rip)                           (:reg/mem64))                                  ;; JMP

(defamd64format "@ptr16:16"              (:rip :cs :tss)                  (:ptr16/16))                                   ;; JMP FAR
(defamd64format "@ptr16:32"              (:rip :cs :tss)                  (:ptr16/32))                                   ;; JMP FAR
(defamd64format "@mem32"                 (:rip :cs :tss)                  (:mem32))                                      ;; JMP FAR
(defamd64format "@mem48"                 (:rip :cs :tss)                  (:mem48))                                      ;; JMP FAR

(defamd64format "@@immoff16"             (:rip :rsp :mem16)               (:rip :rbp :rsp :immoff16))                    ;; CALL
(defamd64format "@@immoff32"             (:rip :rsp :mem32)               (:rip :rsp :immoff32))                         ;; CALL
(defamd64format "@@reg/mem16"            (:rip :rsp :mem16)               (:rip :rsp :reg/mem16))                        ;; CALL
(defamd64format "@@reg/mem32"            (:rip :rsp :mem32)               (:rip :rsp :reg/mem32))                        ;; CALL
(defamd64format "@@reg/mem64"            (:rip :rsp :mem64)               (:rip :rsp :reg/mem64))                        ;; CALL

(defamd64format "@@"                     (:rip :rsp)                      (:rip :rsp :mem16))                            ;; RET
(defamd64format "@@imm8"                 (:rip :rsp)                      (:rip :rsp :mem16 :imm8))                      ;; RET

(defamd64format "@>immoff8"              (:rip)                           (:rflags :immoff8))                            ;; Jxx
(defamd64format "@>immoff16"             (:rip)                           (:rflags :immoff16))                           ;; Jxx
(defamd64format "@>immoff32"             (:rip)                           (:rflags :immoff32))                           ;; Jxx

(defamd64format "@CX, immoff8"           (:rip)                           (:cx :immoff8))                                ;; JCXZ
(defamd64format "@ECX, immoff8"          (:rip)                           (:ecx :immoff8))                               ;; JECXZ
(defamd64format "@RCX, immoff8"          (:rip)                           (:rcx :immoff8))                               ;; JRCXZ

(defamd64format "@@@ptr16:16"            (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :ptr16/16))       ;; CALL FAR
(defamd64format "@@@ptr16:32"            (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :ptr16/32))       ;; CALL FAR
(defamd64format "@@@mem32"               (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :mem32))          ;; CALL FAR
(defamd64format "@@@mem48"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :mem48))          ;; CALL FAR
(defamd64format "@@@"                    (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16))               ;; RETF
(defamd64format "@@@imm16"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16 :imm16))        ;; RETF

(defamd64format "!AX, AL"                (:ax)                            (:al))                                         ;; CBW
(defamd64format "!EAX, AX"               (:eax)                           (:ax))                                         ;; CWDE
(defamd64format "!RAX, EAX"              (:rax)                           (:eax))                                        ;; CDQE

(defamd64format "2|AX, DX"               (:ax :dx)                        (:ax))                                         ;; CWD
(defamd64format "2|EAX, EDX"             (:eax :edx)                      (:eax))                                        ;; CDQ
(defamd64format "2|RAX, RDX"             (:rax :rdx)                      (:rax))                                        ;; CQO

(defamd64format "<"                      (:rflags)                        ())                                            ;; CLC, CLD, STC, STD
(defamd64format "$<IF"                   (:rflags)                        (:cpl :cs))                                    ;; CLI, STI
(defamd64format "<>"                     (:rflags)                        (:rflags))                                     ;; CMC

(defamd64format "|mem8"                  ()                               (:mem8))                                       ;; CLFLUSH, INVLPG
(defamd64format "|RAX, ECX"              ()                               (:rax :ecx))                                   ;; INVLPGA

(defamd64format ""                       ()                               ())                                            ;; LFENCE, SFENCE, MFENCE, NOP, PAUSE
(defamd64format "|CPL"                   ()                               (:cpl :cs))                                    ;; INVD, WBINVD, HLT
(defamd64format "|!mem16/32/64"          ()                               ())                                            ;; NOP
(defamd64format "|!mem8"                 ()                               ())                                            ;; PREFETCH{,W,NTA,0,1,2}

;;;;
;;;; String formats
;;;;                                                                    
(defamd64format "<>|mem8, mem8"          (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem8 :mem8))   ;; CMPS, CMPSB
(defamd64format "<>|mem16, mem16"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem16 :mem16)) ;; CMPS, CMPSW
(defamd64format "<>|mem32, mem32"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem32 :mem32)) ;; CMPS, CMPSD
(defamd64format "<>|mem64, mem64"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem64 :mem64)) ;; CMPS, CMPSQ

(defamd64format "!AL, mem8"              (:al  :rsi)                      (:ds :rsi :mem8))                              ;; LODS, LODSB
(defamd64format "!AX, mem16"             (:ax  :rsi)                      (:ds :rsi :mem16))                             ;; LODS, LODSW
(defamd64format "!EAX, mem32"            (:eax :rsi)                      (:ds :rsi :mem32))                             ;; LODS, LODSD
(defamd64format "!RAX, mem64"            (:rax :rsi)                      (:ds :rsi :mem64))                             ;; LODS, LODSQ

(defamd64format "!mem8, mem8"            (:rsi :rdi :mem8)                (:segreg :rsi :es :rdi :mem8))                 ;; MOVS, MOVSB
(defamd64format "!mem16, mem16"          (:rsi :rdi :mem16)               (:segreg :rsi :es :rdi :mem16))                ;; MOVS, MOVSW
(defamd64format "!mem32, mem32"          (:rsi :rdi :mem32)               (:segreg :rsi :es :rdi :mem32))                ;; MOVS, MOVSD
(defamd64format "!mem64, mem64"          (:rsi :rdi :mem64)               (:segreg :rsi :es :rdi :mem64))                ;; MOVS, MOVSQ

(defamd64format "<>|AL, mem8"            (:rflags :rdi)                   (:rflags :es :rdi :al :mem8))                  ;; SCAS, SCASB
(defamd64format "<>|AX, mem16"           (:rflags :rdi)                   (:rflags :es :rdi :ax :mem16))                 ;; SCAS, SCASW
(defamd64format "<>|EAX, mem32"          (:rflags :rdi)                   (:rflags :es :rdi :eax :mem32))                ;; SCAS, SCASD
(defamd64format "<>|RAX, mem64"          (:rflags :rdi)                   (:rflags :es :rdi :rax :mem64))                ;; SCAS, SCASQ

(defamd64format "!mem8, AL"              (:mem8  :rdi)                    (:es :rdi :al))                                ;; STOS, STOSB
(defamd64format "!mem16, AX"             (:mem16 :rdi)                    (:es :rdi :ax))                                ;; STOS, STOSW
(defamd64format "!mem32, EAX"            (:mem32 :rdi)                    (:es :rdi :eax))                               ;; STOS, STOSD
(defamd64format "!mem64, RAX"            (:mem64 :rdi)                    (:es :rdi :rax))                               ;; STOS, STOSQ
;;;;

(defamd64format "<AL, reg/mem8, reg8"    (:rflags :al :reg/mem8)          (:al :reg/mem8 :reg8))                         ;; CMPXCHG
(defamd64format "<AX, reg/mem16, reg16"  (:rflags :al :reg/mem16)         (:al :reg/mem16 :reg16))                       ;; CMPXCHG
(defamd64format "<EAX, reg/mem32, reg32" (:rflags :al :reg/mem32)         (:al :reg/mem32 :reg32))                       ;; CMPXCHG
(defamd64format "<RAX, reg/mem64, reg64" (:rflags :al :reg/mem64)         (:al :reg/mem64 :reg64))                       ;; CMPXCHG

(defamd64format "<EDX:EAX, reg/mem64, ECX:EBX"  (:rflags :edx :eax :reg/mem64)  (:edx :eax :reg/mem64 :ecx :edx))        ;; CMPXCHG8B
(defamd64format "<RDX:RAX, reg/mem128, RCX:RBX" (:rflags :rdx :rax :reg/mem128) (:rdx :rax :reg/mem128 :rcx :rdx))       ;; CMPXCHG16B

(defamd64format "EAX, EBX, ECX, EDX"            (:eax :ebx :ecx :edx)     (:eax))                                        ;; CPUID
                                                                                                                         
(defamd64format "<AL, AH, reg/mem8"             (:rflags :ah :al)         (:ax :reg/mem8))                               ;; DIV, IDIV
(defamd64format "<DX, AX, reg/mem16"            (:rflags :dx :ax)         (:dx :ax :reg/mem16))                          ;; DIV, IDIV
(defamd64format "<EDX, EAX, reg/mem32"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
(defamd64format "<RDX, RAX, reg/mem64"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
(defamd64format "<!AX, AL, reg/mem8"            (:rflags :ax)             (:al :reg/mem8))                               ;; MUL, IMUL
(defamd64format "<!DX, AX, AX, reg/mem16"       (:rflags :dx :ax)         (:ax :reg/mem16))                              ;; MUL, IMUL
(defamd64format "<!EDX, EAX, EAX, reg/mem32"    (:rflags :edx :eax)       (:eax :reg/mem32))                             ;; MUL, IMUL
(defamd64format "<!RDX, RAX, RAX, reg/mem64"    (:rflags :rdx :rax)       (:rax :reg/mem64))                             ;; MUL, IMUL
                                                                                                                         
(defamd64format "imm16, 0"                      (:rsp :rbp)               (:imm16 0 :rsp :rbp :ss))                      ;; ENTER
(defamd64format "imm16, 1"                      (:rsp :rbp)               (:imm16 1 :rsp :rbp :ss))                      ;; ENTER
(defamd64format "imm16, imm8"                   (:rsp :rbp)               (:imm16 :imm8 :rsp :rbp :ss))                  ;; ENTER
                                                                                                                         
(defamd64format "BP, SP"                        (:bp :sp)                 (:bp :mem16))                                  ;; LEAVE 
(defamd64format "EBP, ESP"                      (:ebp :esp)               (:ebp :mem32))                                 ;; LEAVE 
(defamd64format "RBP, RSP"                      (:rbp :rsp)               (:rbp :mem64))                                 ;; LEAVE 
                                                                                                                         
(defamd64format "<!reg16, reg/mem16, imm8"      (:rflags :reg16)          (:reg/mem16 :imm8))                            ;; IMUL
(defamd64format "<!reg32, reg/mem32, imm8"      (:rflags :reg32)          (:reg/mem32 :imm8))                            ;; IMUL
(defamd64format "<!reg64, reg/mem64, imm8"      (:rflags :reg64)          (:reg/mem64 :imm8))                            ;; IMUL
(defamd64format "<!reg16, reg/mem16, imm16"     (:rflags :reg16)          (:reg/mem16 :imm16))                           ;; IMUL
(defamd64format "<!reg32, reg/mem32, imm32"     (:rflags :reg32)          (:reg/mem32 :imm32))                           ;; IMUL
(defamd64format "<!reg64, reg/mem64, imm32"     (:rflags :reg64)          (:reg/mem64 :imm32))                           ;; IMUL
                                                                                                                         
(defamd64format "#!AL, DX"                      (:al)                     (:dx :tss))                                    ;; IN
(defamd64format "#!AX, DX"                      (:ax)                     (:dx :tss))                                    ;; IN
(defamd64format "#!EAX, DX"                     (:eax)                    (:dx :tss))                                    ;; IN
(defamd64format "#!AL, imm8"                    (:al)                     (:imm8 :tss))                                  ;; IN
(defamd64format "#!AX, imm8"                    (:ax)                     (:imm8 :tss))                                  ;; IN
(defamd64format "#!EAX, imm8"                   (:eax)                    (:imm8 :tss))                                  ;; IN
                                                                                                                               
(defamd64format "#|DX, AL"                      ()                        (:dx :al  :tss))                               ;; OUT
(defamd64format "#|DX, AX"                      ()                        (:dx :ax  :tss))                               ;; OUT
(defamd64format "#|DX, EAX"                     ()                        (:dx :eax :tss))                               ;; OUT
(defamd64format "#imm8, AL"                     ()                        (:imm8 :al  :tss))                             ;; OUT
(defamd64format "#imm8, AX"                     ()                        (:imm8 :ax  :tss))                             ;; OUT
(defamd64format "#imm8, EAX"                    ()                        (:imm8 :eax :tss))                             ;; OUT
                                                                                                                               
(defamd64format "#!>mem8, DX"                   (:mem8 :rdi)              (:rflags :es :rdi :dx :tss))                   ;; INS, INSB
(defamd64format "#!>mem16, DX"                  (:mem16 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSW
(defamd64format "#!>mem32, DX"                  (:mem32 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSD
(defamd64format "#|>DX, mem8"                   (:rsi)                    (:rflags :ds :rsi :dx :mem8  :tss))            ;; OUTS, OUTSB
(defamd64format "#|>DX, mem16"                  (:rsi)                    (:rflags :ds :rsi :dx :mem16 :tss))            ;; OUTS, OUTSW
(defamd64format "#|>DX, mem32"                  (:rsi)                    (:rflags :ds :rsi :dx :mem32 :tss))            ;; OUTS, OUTSD
                                                                                                                         
(defamd64format ">!AH"                          (:ah)                     (:rflags))                                     ;; LAHF
(defamd64format "<|!AH"                         (:rflags)                 (:ah))                                         ;; SAHF
                                                                                                                         
(defamd64format "!DS, reg16, mem32"             (:ds :reg16)              (:mem32))                                      ;; LDS
(defamd64format "!DS, reg32, mem48"             (:ds :reg32)              (:mem48))                                      ;; LDS
(defamd64format "!ES, reg16, mem32"             (:es :reg16)              (:mem32))                                      ;; LES
(defamd64format "!ES, reg32, mem48"             (:es :reg32)              (:mem48))                                      ;; LES
(defamd64format "!FS, reg16, mem32"             (:fs :reg16)              (:mem32))                                      ;; LFS
(defamd64format "!FS, reg32, mem48"             (:fs :reg32)              (:mem48))                                      ;; LFS
(defamd64format "!GS, reg16, mem32"             (:gs :reg16)              (:mem32))                                      ;; LGS
(defamd64format "!GS, reg32, mem48"             (:gs :reg32)              (:mem48))                                      ;; LGS
(defamd64format "!SS, reg16, mem32"             (:ss :reg16)              (:mem32))                                      ;; LSS
(defamd64format "!SS, reg32, mem48"             (:ss :reg32)              (:mem48))                                      ;; LSS
                                                                                                                         
(defamd64format "!reg16, mem"                   (:reg16)                  (:mem))                                        ;; LEA
(defamd64format "!reg32, mem"                   (:reg32)                  (:mem))                                        ;; LEA
(defamd64format "!reg64, mem"                   (:reg64)                  (:mem))                                        ;; LEA
                                                                                                                         
(defamd64format "@RCX, immoff8"                 (:rip :rcx)               (:rcx :immoff8))                               ;; LOOP
(defamd64format "@>RCX, immoff8"                (:rip :rcx)               (:rflags :rcx :immoff8))                       ;; LOOPxx
                                                                                                                         
(defamd64format "<!reg16, reg/mem16"            (:rflags :reg16)          (:reg/mem16))                                  ;; LZCNT, POPCNT
(defamd64format "<!reg32, reg/mem32"            (:rflags :reg32)          (:reg/mem32))                                  ;; LZCNT, POPCNT
(defamd64format "<!reg64, reg/mem64"            (:rflags :reg64)          (:reg/mem64))                                  ;; LZCNT, POPCNT
                                                                                                                         
;;;;                                                                                                                     
;;;; load/stores                                                                                                         
;;;;                                                                                                                     
(defamd64format "!reg/mem8, reg8"               (:reg/mem8)               (:reg8))                                       ;; MOV
(defamd64format "!reg/mem16, reg16"             (:reg/mem16)              (:reg16))                                      ;; MOV
(defamd64format "!reg/mem32, reg32"             (:reg/mem32)              (:reg32))                                      ;; MOV
(defamd64format "!reg/mem64, reg64"             (:reg/mem64)              (:reg64))                                      ;; MOV
(defamd64format "!reg8, reg/mem8"               (:reg8)                   (:reg/mem8))                                   ;; MOV
(defamd64format "!reg16, reg/mem16"             (:reg16)                  (:reg/mem16))                                  ;; MOV
(defamd64format "!reg32, reg/mem32"             (:reg32)                  (:reg/mem32))                                  ;; MOV
(defamd64format "!reg64, reg/mem64"             (:reg64)                  (:reg/mem64))                                  ;; MOV

(defamd64format "!reg16, reg/mem8"              (:reg16)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
(defamd64format "!reg32, reg/mem8"              (:reg32)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
(defamd64format "!reg64, reg/mem8"              (:reg64)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
(defamd64format "!reg32, reg/mem16"             (:reg32)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
(defamd64format "!reg64, reg/mem16"             (:reg64)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
(defamd64format "!reg64, reg/mem32"             (:reg64)                  (:reg/mem32))                                  ;; MOVSXD (weird for 16bit op; separate format?)                     
                                                                                                    
(defamd64format "!mem32, reg32"                 (:mem32)                  (:reg32))                                      ;; MOVNTI
(defamd64format "!mem64, reg64"                 (:mem64)                  (:reg64))                                      ;; MOVNTI
                                                                                                                         
;;;;                                                                                                                     
;;;; RIP-relative load/stores                                                                                            
;;;;                                                                                                                     
(defamd64format "!AL, immoff8"                  (:al)                     (:immoff8 :mem8))                              ;; MOV
(defamd64format "!AX, immoff16"                 (:ax)                     (:immoff16 :mem16))                            ;; MOV
(defamd64format "!EAX, immoff32"                (:eax)                    (:immoff32 :mem32))                            ;; MOV
(defamd64format "!RAX, immoff64"                (:rax)                    (:immoff64 :mem64))                            ;; MOV
(defamd64format "immoff8, AL"                   (:mem8)                   (:immoff8 :al))                                ;; MOV
(defamd64format "immoff16, AX"                  (:mem16)                  (:immoff16 :ax))                               ;; MOV
(defamd64format "immoff32, EAX"                 (:mem32)                  (:immoff32 :eax))                              ;; MOV
(defamd64format "immoff64, RAX"                 (:mem64)                  (:immoff64 :rax))                              ;; MOV
                                                                                                                         
;;;;                                                                                                                     
;;;; constant                                                                                                            
;;;;                                                                                                                     
(defamd64format "!reg8, imm8"                   (:reg8)                   (:imm8))                                       ;; MOV
(defamd16format "!reg16, imm16"                 (:reg16)                  (:imm16))                                      ;; MOV
(defamd32format "!reg32, imm32"                 (:reg32)                  (:imm32))                                      ;; MOV
(defamd64format "!reg64, imm64"                 (:reg64)                  (:imm64))                                      ;; MOV
(defamd64format "!reg/mem8, imm8"               (:reg/mem8)               (:imm8))                                       ;; MOV
(defamd64format "!reg/mem16, imm16"             (:reg/mem16)              (:imm16))                                      ;; MOV
(defamd64format "!reg/mem32, imm32"             (:reg/mem32)              (:imm32))                                      ;; MOV
(defamd64format "!reg/mem64, imm32"             (:reg/mem64)              (:imm32))                                      ;; MOV
                                                                                                                         
;;;;                                                                                                                     
;;;; segment register                                                                                                    
;;;;                                                                                                                     
(defamd64format "!reg16/32/64/mem16, segreg"    (:reg16/32/64/mem16)      (:segreg))                                     ;; MOV
(defamd64format "!segreg, reg/mem16"            (:segreg)                 (:reg/mem16))                                  ;; MOV

;;;;                                                                                                                     
;;;; MMX/XMM                                                                                                             
;;;;                                                                                                                     
(defamd64format "!mmx, reg/mem32"               (:mmx)                    (:reg/mem32))                                  ;; MOVD
(defamd64format "!mmx, reg/mem64"               (:mmx)                    (:reg/mem64))                                  ;; MOVD
(defamd64format "!reg/mem32, mmx"               (:reg/mem32)              (:mmx))                                        ;; MOVD
(defamd64format "!reg/mem64, mmx"               (:reg/mem64)              (:mmx))                                        ;; MOVD
(defamd64format "!xmm, reg/mem32"               (:xmm)                    (:reg/mem32))                                  ;; MOVD
(defamd64format "!xmm, reg/mem64"               (:xmm)                    (:reg/mem64))                                  ;; MOVD
(defamd64format "!reg/mem32, xmm"               (:reg/mem32)              (:xmm))                                        ;; MOVD
(defamd64format "!reg/mem64, xmm"               (:reg/mem64)              (:xmm))                                        ;; MOVD
                                                                                                                         
(defamd64format "!reg32, xmm"                   (:reg32)                  (:xmm))                                        ;; MOVMSKPS, MOVMSKPD

;;;;
;;;; system
;;;;                                                                                                                         
(defamd64format "$!crreg, reg32"                (:crreg)                  (:reg32 :cpl :cs))                             ;; MOV
(defamd64format "$!crreg, reg64"                (:crreg)                  (:reg64 :cpl :cs))                             ;; MOV
(defamd64format "!reg32, crreg"                 (:reg32)                  (:crreg :cpl :cs))                             ;; MOV
(defamd64format "!reg64, crreg"                 (:reg64)                  (:crreg :cpl :cs))                             ;; MOV

(defamd64format "$!CR8, reg32"                  (:cr8)                    (:reg32 :cpl :cs))                             ;; MOV
(defamd64format "$!CR8, reg64"                  (:cr8)                    (:reg64 :cpl :cs))                             ;; MOV
(defamd64format "!reg32, CR8"                   (:reg32)                  (:cr8 :cpl :cs))                               ;; MOV
(defamd64format "!reg64, CR8"                   (:reg64)                  (:cr8 :cpl :cs))                               ;; MOV

(defamd64format "$!drreg, reg32"                (:drreg)                  (:reg32 :cpl :cs))                             ;; MOV
(defamd64format "$!drreg, reg64"                (:drreg)                  (:reg64 :cpl :cs))                             ;; MOV
(defamd64format "!reg32, drreg"                 (:reg32)                  (:drreg :cpl :cs))                             ;; MOV
(defamd64format "!reg64, drreg"                 (:reg64)                  (:drreg :cpl :cs))                             ;; MOV

;;;;
;;;; Stack
;;;;
(defamd64format "!reg/mem16, [SS:RSP]"          (:reg/mem16 :rsp)         (:ss :rsp :mem16))                             ;; POP
(defamd64format "!reg/mem32, [SS:RSP]"          (:reg/mem32 :rsp)         (:ss :rsp :mem32))                             ;; POP
(defamd64format "!reg/mem64, [SS:RSP]"          (:reg/mem64 :rsp)         (:ss :rsp :mem64))                             ;; POP
(defamd64format "!reg16, [SS:RSP]"              (:reg16 :rsp)             (:ss :rsp :mem16))                             ;; POP
(defamd64format "!reg32, [SS:RSP]"              (:reg32 :rsp)             (:ss :rsp :mem32))                             ;; POP
(defamd64format "!reg64, [SS:RSP]"              (:reg64 :rsp)             (:ss :rsp :mem64))                             ;; POP
(defamd64format "!DS, [SS:RSP]"                 (:ds :rsp)                (:ss :rsp :mem16))                             ;; POP
(defamd64format "!ES, [SS:RSP]"                 (:es :rsp)                (:ss :rsp :mem16))                             ;; POP
(defamd64format "!SS, [SS:RSP]"                 (:ss :rsp)                (:ss :rsp :mem16))                             ;; POP
(defamd64format "!FS, [SS:RSP]"                 (:fs :rsp)                (:ss :rsp :mem16))                             ;; POP
(defamd64format "!GS, [SS:RSP]"                 (:gs :rsp)                (:ss :rsp :mem16))                             ;; POP

(defamd64format "![SS:RSP], reg/mem16"          (:mem16 :rsp)             (:ss :rsp :reg/mem16))                         ;; PUSH
(defamd64format "![SS:RSP], reg/mem32"          (:mem32 :rsp)             (:ss :rsp :reg/mem32))                         ;; PUSH
(defamd64format "![SS:RSP], reg/mem64"          (:mem64 :rsp)             (:ss :rsp :reg/mem64))                         ;; PUSH
(defamd64format "![SS:RSP], reg16"              (:mem16 :rsp)             (:ss :rsp :reg16))                             ;; PUSH
(defamd64format "![SS:RSP], reg32"              (:mem32 :rsp)             (:ss :rsp :reg32))                             ;; PUSH
(defamd64format "![SS:RSP], reg64"              (:mem64 :rsp)             (:ss :rsp :reg64))                             ;; PUSH
(defamd64format "![SS:RSP], imm8"               (:mem8  :rsp)             (:ss :rsp :imm8))                              ;; PUSH
(defamd64format "![SS:RSP], imm16"              (:mem16 :rsp)             (:ss :rsp :imm16))                             ;; PUSH
(defamd64format "![SS:RSP], imm32"              (:mem32 :rsp)             (:ss :rsp :imm32))                             ;; PUSH
(defamd64format "![SS:RSP], imm64"              (:mem64 :rsp)             (:ss :rsp :imm64))                             ;; PUSH
(defamd64format "![SS:RSP], CS"                 (:mem16 :rsp)             (:ss :rsp :cs))                                ;; PUSH
(defamd64format "![SS:RSP], DS"                 (:mem16 :rsp)             (:ss :rsp :ds))                                ;; PUSH
(defamd64format "![SS:RSP], ES"                 (:mem16 :rsp)             (:ss :rsp :es))                                ;; PUSH
(defamd64format "![SS:RSP], SS"                 (:mem16 :rsp)             (:ss :rsp :ss))                                ;; PUSH
(defamd64format "![SS:RSP], FS"                 (:mem16 :rsp)             (:ss :rsp :fs))                                ;; PUSH
(defamd64format "![SS:RSP], GS"                 (:mem16 :rsp)             (:ss :rsp :gs))                                ;; PUSH

(defamd64format "!DI, SI, BP, SP, BX, DX, CX, AX, [SS:SP]"          (:di :si :bp :sp :bx :dx :cx :ax)         (:ss :rsp :mem128)) ;; POPA
(defamd64format "!EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX, [SS:ESP]" (:edi :esi :ebp :esp :ebx :edx :ecx :eax) (:ss :rsp :mem256)) ;; POPAD

(defamd64format "![SS:SP], AX, CX, DX, BX, SP, BP, SI, DI"          (:ss :rsp :mem128)         (:di :si :bp :sp :bx :dx :cx :ax)) ;; PUSHA
(defamd64format "![SS:ESP], EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI" (:ss :rsp :mem256) (:edi :esi :ebp :esp :ebx :edx :ecx :eax)) ;; PUSHAD

(defamd64format "<>![SS:SP]"                    (:flags  :rsp)            (:flags  :cpl :cs :ss :rsp :mem16))            ;; POPF
(defamd64format "<>![SS:ESP]"                   (:eflags :rsp)            (:eflags :cpl :cs :ss :rsp :mem32))            ;; POPFD
(defamd64format "<>![SS:RSP]"                   (:rflags :rsp)            (:rflags :cpl :cs :ss :rsp :mem64))            ;; POPFQ

(defamd64format ">![SS:SP]"                     (:mem16 :rsp)             (:flags  :ss :rsp))                            ;; PUSHF
(defamd64format ">![SS:ESP]"                    (:mem32 :rsp)             (:eflags :ss :rsp))                            ;; PUSHFD
(defamd64format ">![SS:RSP]"                    (:mem64 :rsp)             (:rflags :ss :rsp))                            ;; PUSHFQ

(defamd64format "<>reg/mem8, 1"                 (:rflags :reg/mem8)       (:rflags :reg/mem8  1))                        ;; RCL, RCR
(defamd64format "<>reg/mem16, 1"                (:rflags :reg/mem16)      (:rflags :reg/mem16 1))                        ;; RCL, RCR
(defamd64format "<>reg/mem32, 1"                (:rflags :reg/mem32)      (:rflags :reg/mem32 1))                        ;; RCL, RCR
(defamd64format "<>reg/mem64, 1"                (:rflags :reg/mem64)      (:rflags :reg/mem64 1))                        ;; RCL, RCR
(defamd64format "<>reg/mem8, CL"                (:rflags :reg/mem8)       (:rflags :reg/mem8  :cl))                      ;; RCL, RCR
(defamd64format "<>reg/mem16, CL"               (:rflags :reg/mem16)      (:rflags :reg/mem16 :cl))                      ;; RCL, RCR
(defamd64format "<>reg/mem32, CL"               (:rflags :reg/mem32)      (:rflags :reg/mem32 :cl))                      ;; RCL, RCR
(defamd64format "<>reg/mem64, CL"               (:rflags :reg/mem64)      (:rflags :reg/mem64 :cl))                      ;; RCL, RCR
(defamd64format "<>reg/mem8, imm8"              (:rflags :reg/mem8)       (:rflags :reg/mem8  :imm8))                    ;; RCL, RCR
(defamd64format "<>reg/mem16, imm8"             (:rflags :reg/mem16)      (:rflags :reg/mem16 :imm8))                    ;; RCL, RCR
(defamd64format "<>reg/mem32, imm8"             (:rflags :reg/mem32)      (:rflags :reg/mem32 :imm8))                    ;; RCL, RCR
(defamd64format "<>reg/mem64, imm8"             (:rflags :reg/mem64)      (:rflags :reg/mem64 :imm8))                    ;; RCL, RCR

(defamd64format "<reg/mem8, 1"                  (:rflags :reg/mem8)       (:reg/mem8 1))                                 ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem16, 1"                 (:rflags :reg/mem16)      (:reg/mem16 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem32, 1"                 (:rflags :reg/mem32)      (:reg/mem32 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem64, 1"                 (:rflags :reg/mem64)      (:reg/mem64 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem8, CL"                 (:rflags :reg/mem8)       (:reg/mem8 :cl))                               ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem16, CL"                (:rflags :reg/mem16)      (:reg/mem16 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem32, CL"                (:rflags :reg/mem32)      (:reg/mem32 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem64, CL"                (:rflags :reg/mem64)      (:reg/mem64 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem8, imm8"               (:rflags :reg/mem8)       (:reg/mem8 :imm8))                             ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem16, imm8"              (:rflags :reg/mem16)      (:reg/mem16 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem32, imm8"              (:rflags :reg/mem32)      (:reg/mem32 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
(defamd64format "<reg/mem64, imm8"              (:rflags :reg/mem64)      (:reg/mem64 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR

(defamd64format "<reg/mem16, reg16, CL"         (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :cl))                     ;; SHLD, SHRD
(defamd64format "<reg/mem32, reg32, CL"         (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :cl))                     ;; SHLD, SHRD
(defamd64format "<reg/mem64, reg64, CL"         (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :cl))                     ;; SHLD, SHRD
(defamd64format "<reg/mem16, reg16, imm8"       (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :imm8))                   ;; SHLD, SHRD
(defamd64format "<reg/mem32, reg32, imm8"       (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :imm8))                   ;; SHLD, SHRD
(defamd64format "<reg/mem64, reg64, imm8"       (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :imm8))                   ;; SHLD, SHRD

(defamd64format "2|reg/mem8,  reg8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XADD, XCHG
(defamd64format "2|reg/mem16, reg16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XADD, XCHG
(defamd64format "2|reg/mem32, reg32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XADD, XCHG
(defamd64format "2|reg/mem64, reg64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XADD, XCHG

(defamd64format "2|AX,  reg16"                  (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
(defamd64format "2|EAX, reg32"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
(defamd64format "2|RAX, reg64"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;;;;
;;;; XCHG's identicalities
;;;;
(defamd64format "2|reg8,  reg/mem8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XCHG
(defamd64format "2|reg16, reg/mem16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XCHG
(defamd64format "2|reg32, reg/mem32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XCHG
(defamd64format "2|reg64, reg/mem64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XCHG
(defamd64format "2|reg16, AX"                   (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
(defamd64format "2|reg32, EAX"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
(defamd64format "2|reg64, RAX"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;;;;
;;;; assorted system stuff
;;;;
(defamd64format "AL, seg:[RBX + AL]"            (:al)                     (:segreg :rbx :al))                            ;; XLAT, XLATB

(defamd64format "<$reg/mem16, reg16"            (:segreg)                 (:segreg :reg16))                              ;; ARPL
(defamd64format "$!GIF"                         (:gif)                    ())                                            ;; CLGI, STGI

(defamd64format "$CR0"                          (:cr0)                    ())                                            ;; CLTS

(defamd64format "<!$reg16, reg/mem16"           (:rflags :reg16)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
(defamd64format "<!$reg32, reg/mem16"           (:rflags :reg32)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
(defamd64format "<!$reg64, reg/mem16"           (:rflags :reg64)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL

(defamd64format "|$mem48"                       ()                        (:mem48 :cpl :cs))                             ;; LGDT, LIDT
(defamd64format "|$mem80"                       ()                        (:mem80 :cpl :cs))                             ;; LGDT, LIDT

(defamd64format "!mem48"                        (:mem48)                  ())                                            ;; SGDT, SIDT
(defamd64format "!mem80"                        (:mem80)                  ())                                            ;; SGDT, SIDT

(defamd64format "!$sysreg16, reg/mem16"         (:sysreg16)               (:reg/mem16 :cpl :cs))                         ;; LIDT, LMSW, LTR

(defamd64format "$segreg:[EAX], ECX, EDX"       ()                        (:segreg :eax :ecx :edx :cpl :cs))             ;; MONITOR
(defamd64format "$EAX, ECX"                     ()                        (:eax :ecx :cpl :cs))                          ;; MWAIT

(defamd64format "2!2|EDX:EAX, ECX, sysreg64"    (:eax :edx)               (:ecx :sysreg64 :cpl :cs))                     ;; RDMSR, RDPMC
(defamd64format "2!2|EDX:EAX, sysreg64"         (:eax :edx)               (:sysreg64 :cpl :cs :cr4))                     ;; RDTSC
(defamd64format "2!2|3!3|EDX:EAX:ECX, sysreg64, sysreg32" (:eax :edx :ecx)(:sysreg64 :sysreg32 :cpl :cs :cr4))           ;; RDTSCP

(defamd64format "$!sysreg64, EDX:EAX, ECX"      (:sysreg64)               (:eax :edx :ecx :cpl :cs))                     ;; RDMSR, RDPMC

(defamd64format "!reg16, sysreg16"              (:reg16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
(defamd64format "!reg32, sysreg16"              (:reg32)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
(defamd64format "!reg64, sysreg16"              (:reg64)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
(defamd64format "!mem16, sysreg16"              (:mem16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
(defamd64format "2|sysreg16, GS"                (:gs :sysreg16)           (:gs :sysreg16 :cpl :cs))                      ;; SWAPGS

(defamd64format "$@<!CX"                        (:eflags :eip :cpl :cs :ss :cx)       (:star))                           ;; SYSCALL (short mode)
(defamd64format "$@<!2|RCX, R11"                (:rflags :rip :cpl :cs :ss :rcx :r11) (:cstar))                          ;; SYSCALL (long mode)
(defamd64format "$@<|CX"                        (:eflags :eip :cpl :cs :ss)           (:efer :cpl :cs :star :ecx))       ;; SYSRET (short mode)
(defamd64format "$@<|RCX, R11"                  (:rflags :rip :cpl :cs :ss)           (:efer :cpl :cs :cstar :rcx :r11)) ;; SYSRET (long mode)

(defamd64format "$@<SS:ESP"                     (:eflags :eip :cpl :cs :ss :esp)      ())                                ;; SYSENTER
(defamd64format "$@<SS:ESP, CX, DX"             (:eflags :eip :cpl :cs :ss :esp)      (:cx :dx))                         ;; SYSEXIT

(defamd64format "$@"                            (:rip)                                ())                                ;; UD2, VMMCALL

(defamd64format "<$reg/mem16"                   (:rflags)                             (:reg/mem16 :cpl :cs))             ;; VERR, VERW

(defamd64format "$<"                            (:rflags :cr0 :cr3 :cr4 :cr6 :cr7 :efer) (:cr0 :cr3 :cr4 :cr6 :cr7 :efer))                          ;; RSM
(defamd64format "<|$[EAX]"                      (:rflags :cr0 :cs :ss :eax :edx :esp :ebx :ecx :edx :esi :edi :rgpr :efer :gif) (:eax :efer :cppl)) ;; SKINIT

(defamd64format "$!2|FS, GS, CS, [RAX]"         (:fs :gs :tr :star :lstar :cstar :sfmask) (:rax :mem :cpl :cs :efer))                               ;; VMLOAD
(defamd64format "$![RAX], CS, FS, GS"           (:mem)                                    (:rax :cpl :cs :efer :fs :gs :tr :star :lstar :cstar))    ;; VMSAVE
(defamd64format "$<>@![RAX]"                    (:rflags :es :cs :ss :ds :efer :cr0 :cr4 :cr3 :cr2 :rip :rsp :rax :dr6 :dr7 :cpl :mem :gif) 
                                                (:rflags :rip :rsp :rax :mem :cpl :cs :efer :sysreg64 :es :cs :ss :ds :cr0 :cr4 :cr3))              ;; VMRUN

;;;;
;;;; Total of 483 instruction formats
;;;;

;;;;
;;;; Not an instruction
;;;;
;; (defamd64format "$<>@"                       (:gif :efer :cr0 :cr4 :cr3 :rflags :rip :rsp :rax :dr7 :cpl :es :cs :ss :ds)
;;                                              (:es :cs :ss :ds :efer :cr4 :cr3 :cr2 :cr0 :rflags :rip :rsp :rax :dr7 :dr6 :cpl))                  ;; #VMEXIT
