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
  (:add .       #x00) (:add .     #x01) (:add .      #x02) (:add .       #x03) (:add .       #x04) (:add .       #x05)  #| 32bit mode|#  #| 32bit mode   |#
  (:adc .       #x10) (:adc .     #x11) (:adc .      #x12) (:adc .       #x13) (:adc .       #x14) (:adc .       #x15)  #| 32bit mode|#  #| 32bit mode   |#
  (:and .       #x20) (:and .     #x21) (:and .      #x22) (:and .       #x23) (:and .       #x24) (:and .       #x25)  #| ES seg    |#  #| 32bit mode   |#
  (:xor .       #x30) (:xor .     #x31) (:xor .      #x32) (:xor .       #x33) (:xor .       #x34) (:xor .       #x35)  #| SS seg    |#  #| 32bit mode   |#
  ;; 4[0-7]: REX prefixes
  (:push .      #x50) (:push .    #x51) (:push .     #x52) (:push .      #x53) (:push .      #x54) (:push .      #x55) (:push .    #x56) (:push .      #x57)
   #| 32bit mode  |#   #| 32bit mode|#   #| 32bit mode |#   #| 64bit mode  |#   #| FS seg      |#   #|  GS seg     |#   #| oper size |#   #| addr size   |#
  (:jo .        #x70) (:jno .     #x71) (:jb .       #x72) (:jnb .       #x73) (:jz .        #x74) (:jnz .       #x75) (:jbe .     #x76) (:jnbe .      #x77)
  (:grp1-80 .   #x80) (:grp1-81 . #x81)  #| 32bit mode |#  (:grp1-83 .   #x83) (:test .      #x84) (:test .      #x85) (:xchg .    #x86) (:xchg .      #x87)
  (:xchg.       #x90) (:xchg .    #x91) (:xchg.      #x92) (:xchg .      #x93) (:xchg .      #x94) (:xchg .      #x95) (:xchg .    #x96) (:xchg .      #x97)
  (:mov .       #xa0) (:mov .     #xa1) (:mov .      #xa2) (:mov .       #xa3) (:movsb .     #xa4) (:movsw/d/q . #xa5) (:cmpsb .   #xa6) (:cmpsw/d/q . #xa7)
  (:mov .       #xb0) (:mov .     #xb1) (:mov .      #xb2) (:mov .       #xb3) (:mov .       #xb4) (:mov .       #xb5) (:mov .     #xb6) (:mov .       #xb7)
  (:grp2-c0 .   #xc0) (:grp2-c1 . #xc1) (:ret-near . #xc2) (:ret-near .  #xc3)  #| 32bit mode  |#   #| 32bit mode  |#  (:grp11-c6 . #xc6) (:grp11-c7 . #xc7)
  (:grp2-d0 .   #xd0) (:grp2-d1 . #xd1) (:grp2-d2 .  #xd2) (:grp2-d3 .   #xd3)  #| 32bit mode  |#   #| 32bit mode  |#   #| 32bit mode|#  (:xlat .      #xd7)
  (:loopne/nz . #xe0) (:loope/z . #xe1) (:loop .     #xe2) (:jxcxz .     #xe3) (:in .        #xe4) (:in .        #xe5) (:out .     #xe6) (:out .       #xe7)
   #|  lock       |#  (:int1 .    #xf1)  #|  repn      |#   #|  rep        |#  (:hlt .       #xf4) (:cmc .       #xf5) (:grp3-f6 . #xf6) (:grp3-f7 .   #xf7)
  (:or .        #x08) (:or .      #x09) (:or .       #x0a) (:or .        #x0b) (:or .        #x0c) (:or .        #x0d)  #| 32bit mode|#   #| twop        |#
  (:sbb .       #x18) (:sbb .     #x19) (:sbb .      #x1a) (:sbb .       #x1b) (:sbb .       #x1c) (:sbb .       #x1d)  #| 32bit mode|#   #| 32bit mode  |# 
  (:sub .       #x28) (:sub .     #x29) (:sub .      #x2a) (:sub .       #x2b) (:sub .       #x2c) (:sub .       #x2d)  #| CS seg    |#   #| 32bit mode  |# 
  (:cmp .       #x38) (:cmp .     #x39) (:cmp .      #x3a) (:cmp .       #x3b) (:cmp .       #x3c) (:cmp .       #x3d)  #| DS seg    |#   #| 32bit mode  |# 
  ;; 4[8-f]: REX prefixes
  (:pop .       #x58) (:pop .     #x59) (:pop .      #x5a) (:pop .       #x5b) (:pop .       #x5c) (:pop .       #x5d) (:pop .     #x5e) (:pop .       #x5f)
  (:push .      #x68) (:imul .    #x69) (:push .     #x6a) (:imul .      #x6b) (:insb .      #x6c) (:insw/d .    #x6d) (:outsb .   #x6e) (:outsw/d .   #x6f)
  (:js .        #x78) (:jns .     #x79) (:jp .       #x7a) (:jnp .       #x7b) (:jl .        #x7c) (:jnl .       #x7d) (:jle .     #x7e) (:jnle .      #x7f)
  (:mov .       #x88) (:mov .     #x89) (:mov .      #x8a) (:mov .       #x8b) (:mov .       #x8c) (:lea .       #x8d) (:mov .     #x8e) (:grp1-8f .   #x8f)
  (:cbwde/qe .  #x98) (:cwdqo .   #x99)  #| 32bit mode |#  (:f/wait .    #x9b) (:pushf/d/q . #x9c) (:popf/d/q .  #x9d) (:sahf .    #x9e) (:lahf .      #x9f)
  (:test .      #xa8) (:test .    #xa9) (:stosb .    #xaa) (:stosw/d/q . #xab) (:lodsb .     #xac) (:lodsw/d/q . #xad) (:scasb .   #xae) (:scasw/d/q . #xaf)
  (:mov .       #xb8) (:mov .     #xb9) (:mov .      #xba) (:mov .       #xbb) (:mov .       #xbc) (:mov .       #xbd) (:mov .     #xbe) (:mov .       #xbf)
  (:enter .     #xc8) (:leave .   #xc9) (:ret .      #xca) (:ret .       #xcb) (:int3 .      #xcc) (:int .       #xcd)  #| 32bit mode|#  (:iret/d/q .  #xcf)
  ;; d[8-f]: x87
  (:call .      #xe8) (:jmp .     #xe9)  #| 32bit mode |#  (:jmp .       #xeb) (:in .        #xec) (:in .        #xed) (:out .     #xee) (:out .       #xef)
  (:clc .       #xf8) (:stc .     #xf9) (:cli .      #xfa) (:sti .       #xfb) (:cld .       #xfc) (:std .       #xfd)  #| 64bit mode|#  (:grp5 .      #xff))

(defattrset *amd64-isa* :longmode-only-opcode
   #|  .........           .......           ........  |#  (:movsxd .    #x63)  #|  .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:grp4 .    #xfe)) #|  .........  |#

(defattrset *amd64-isa* :shortmode-only-opcode
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-es . #x06) (:pop-es .    #x07)
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ss . #x16) (:pop-ss .    #x17)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:daa .       #x27)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aaa .       #x37)
  (:inc .       #x40) (:inc .     #x41) (:inc .      #x42) (:inc .       #x43) (:inc .       #x44) (:inc .       #x45) (:inc .     #x46) (:inc .       #x47)
  (:pusha/d .   #x60) (:popa/d .  #x61) (:bound .    #x62)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......  |#  (:grp1-82 .  #x82)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:les .       #xc4) (:lds .       #xc5)
   #|  .........           .......           ........           .........  |#  (:aam .       #xd4) (:aad .       #xd5) (:salc .    #xd6)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push .    #x0e)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push .    #x1e) (:pop .       #x1f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:das .       #x2f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aas .       #x3f)
  (:dec .       #x48) (:dec .     #x49) (:dec .      #x4a) (:dec .       #x4b) (:dec .       #x4c) (:dec .       #x4d) (:dec .     #x4e) (:dec .       #x4f)
   #|  .........           .......  |#  (:call .     #x9a)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:into .    #xce)  #|  .........  |#
   #|  .........           .......  |#  (:jmp .      #xea)  #|  .........           .........           .........           .......           .........  |#)

(defattrset *amd64-isa* :extended-opcode
  (:grp6 .      #x00) (:grp7 .      #x01) (:lar .       #x02) (:lsl .      #x03)  #|   invalid  |#  (:syscall .  #x05) (:clts .    #x06) (:sysret .   #x07)
  ;; 1[0-7]: prefixed
  (:mov .       #x20) (:mov .       #x21) (:mov .       #x22) (:mov .      #x23)  #|   invalid  |#   #|   invalid  |#   #|   invalid |#   #|   invalid  |#
  (:wrmsr .     #x30) (:rstsc .     #x31) (:rdmsr .     #x32) (:rdpmc .    #x33)  #| 32bit mode |#   #| 32bit mode |#   #|   invalid |#   #|   invalid  |#
  (:cmovo .     #x40) (:cmovno .    #x41) (:cmovb .     #x42) (:cmovnb .   #x43) (:cmovz .    #x44) (:cmovnz .   #x45) (:cmovbe .  #x46) (:cmovnbe .  #x47)
  ;; 5[0-7]: prefixed
  ;; 6[0-7]: prefixed
  ;; 7[0-7]: prefixed
  (:jo .        #x80) (:jno .       #x81) (:jb .        #x82) (:jnb .      #x83) (:jz .       #x84) (:jnz .      #x85) (:jbe .     #x86) (:jnbe .     #x87)
  (:seto .      #x90) (:setno .     #x91) (:setb .      #x92) (:setnb .    #x93) (:setz .     #x94) (:setnz .    #x95) (:setbe .   #x96) (:setnbe .   #x97)
  (:push .      #xa0) (:pop .       #xa1) (:cpuid .     #xa2) (:bt .       #xa3) (:shld .     #xa4) (:shld .     #xa5)  #|   invalid |#   #|   invalid  |#
  (:cmpxchg .   #xb0) (:cmpxchg .   #xb1) (:lss .       #xb2) (:btr .      #xb3) (:lfs .      #xb4) (:lgs .      #xb5) (:movzx .   #xb6) (:movzx .    #xb7)
  ;; c[0-7]: prefixed
  ;; d[0-7]: prefixed
  ;; e[0-7]: prefixed
  ;; f[0-7]: prefixed
  (:invd .      #x08) (:wbinvd .    #x09)  #|   invalid   |#  (:ud2 .      #x0b)  #|   invalid  |#  (:grp-p .    #x0d) (:femms .   #x0e) (:grp3dnow . #x0f)
  (:grp16 .     #x18) (:nop .       #x19) (:nop .       #x1a) (:nop .      #x1b) (:nop .      #x1c) (:nop .      #x1d) (:nop .     #x1e) (:nop .      #x1f)
  ;; 2[8-f]: prefixed
  ;; 3[8-f]: invalid
  (:cmovs .     #x48) (:cmovns .    #x49) (:cmovp .     #x4a) (:cmovnp .   #x4b) (:cmovl .    #x4c) (:cmovnl .   #x4d) (:cmovle .  #x4e) (:cmovnle .  #x4f)
  ;; 5[8-f]: prefixed
  ;; 6[8-f]: prefixed
  ;; 7[8-f]: prefixed
  (:js .        #x88) (:jns .       #x89) (:jp .        #x8a) (:jnp .      #x8b) (:jl .       #x8c) (:jnl .      #x8d) (:jle .     #x8e) (:jnle .     #x8f)
  (:sets .      #x98) (:setns .     #x99) (:setp .      #x9a) (:setnp .    #x9b) (:setl .     #x9c) (:setnl .    #x9d) (:setle   . #x9e) (:setnle .   #x9f)
  (:push .      #xa8) (:pop .       #xa9) (:rsm .       #xaa) (:bts .      #xab) (:shrd .     #xac) (:shrd .     #xad) (:grp15 .   #xae) (:imul .     #xaf)
  ;; b[8-f]: prefixed
  (:bswap .     #xc8) (:bswap .     #xc9) (:bswap .     #xca) (:bswap .    #xcb) (:bswap .    #xcc) (:bswap .    #xcd) (:bswap .   #xce) (:bswap .    #xcf)
  ;; d[8-f]: prefixed
  ;; e[8-f]: prefixed
  ;; f[8-f]: prefixed
  )

(defattrset *amd64-isa* :shortmode-only-ext-opcode
  #|    .........           .........           .........            ........ |#  (:sysenter .  #x34) (:sysexit .  #x35)  #|   .......            ........ |#)

(defattrset *amd64-isa* :opcode-ext-variant-unprefixed
  (:movups .    #x10) (:movups .    #x11) (:movl/hlps . #x12) (:movlps .    #x13) (:unpcklps .  #x14) (:unpckhps . #x15) (:movh/lhps . #x16) (:movhps .  #x17)
  (:movmskps .  #x50) (:sqrtps .    #x51) (:rsqrtps .   #x52) (:rcpps .     #x53) (:andps .     #x54) (:andnps .   #x55) (:orps .     #x56) (:xorps .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .   #x64) (:pcmpgtw .  #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufw .    #x70) (:grp12-u .   #x71) (:grp13-u .   #x72) (:grp14-u .   #x73) (:pcmpeqb .   #x74) (:pcmpeqw .  #x75) (:pcmpeqd .  #x76) (:emss .     #x77)
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpps .     #xc2) (:movnti .    #xc3) (:pinsrw .    #xc4) (:pextsrw .  #xc5) (:shufps .   #xc6) (:grp9-u .   #xc7)
   #|   invalid   |#  (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .     #xd4) (:pmullw .   #xd5)  #|   invalid  |#  (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .   #xe4) (:pmulhw .   #xe5)  #|   invalid  |#  (:movntq .   #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .   #xf4) (:pmaddwd .  #xf5) (:psadbw .   #xf6) (:maskmovq . #xf7)
  (:movaps .    #x28) (:movaps .    #x29) (:cvtpi2ps .  #x2a) (:movntps .   #x2b) (:cvttps2pi . #x2c) (:cvtps2pi . #x2d) (:ucomiss .  #x2e) (:comiss .   #x2f)
  (:addps .     #x58) (:mulps .     #x59) (:cvtps2pd .  #x5a) (:cvtdq2ps .  #x5b) (:subps .     #x5c) (:minps .    #x5d) (:divps .    #x5e) (:maxps .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b)  #|   invalid   |#   #|   invalid  |#  (:movd .     #x6e) (:movq .     #x6f)
   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movd .     #x7e) (:movq .     #x7f)
   #|   reserved  |#  (:grp10 .     #xb9) (:grp8 .      #xba) (:btc .       #xbb) (:bsf .       #xbc) (:bsr .      #xbd) (:movsx .    #xbe) (:movsx .    #xbf)
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .   #xdc) (:paddusw .  #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .    #xec) (:paddsw .   #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .      #xfc) (:padw .     #xfd) (:padd .     #xfe)  #|   invalid  |#)

(defattrset *amd64-isa* :opcode-ext-variant-f3-prefixed
  (:movss .     #x10) (:movss .     #x11) (:movsldup .  #x12)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movshdup . #x16)  #|   invalid  |#
   #|   invalid   |#  (:sqrtss .    #x51) (:rsqrtss .   #x52) (:rcpss .     #x53)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  ;; 6[0-7]: invalid
  (:pshufhw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpss .     #xc2)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#  (:grp9 .     #xc7)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movq2dq .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:cvtdq2pd . #xe6)  #|   invalid  |#
  ;; f[0-7]: invalid
   #|   invalid   |#   #|   invalid   |#  (:cvtsi2ss .  #x2a) (:movntss .   #x2b) (:cvttss2si . #x2c) (:cvtss2si . #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addss .     #x58) (:mulss .     #x59) (:cvtss2sd .  #x5a) (:cvttps2dq . #x5b) (:subss       #x5c) (:minss .    #x5d) (:divss .    #x5e) (:maxss .    #x5f)
   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#   #|   invalid  |#  (:movdqu     #x6f)
   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movq .     #x7e) (:movdqu .   #x7f)
  (:popcnt .    #xb8)  #|   reserved  |#   #|   reserved  |#   #|   reserved  |#   #|   reserved  |#  (:lzcnt .    #xbd)  #|   reserved |#   #|   reserved |#
  ;; d[8-f]: invalid
  ;; e[8-f]: invalid
  ;; f[8-f]: invalid
  )

(defattrset *amd64-isa* :opcode-ext-variant-66-prefixed
  (:movupd .    #x10) (:movupd .    #x11) (:movlpd .    #x12) (:movlpd .    #x13) (:unpcklpd .   #x14) (:unpckhpd .   #x15) (:movhpd .   #x16) (:movhpd .   #x17)
  (:movmskpd .  #x50) (:sqrtpd .    #x51)  #|   invalid   |#   #|   invalid   |#  (:andpd .      #x54) (:andnpd .     #x55) (:orpd .     #x56) (:xorpd .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .    #x64) (:pcmpgtw .    #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufd .    #x70) (:grp12-p66 . #x71) (:grp13-p66 . #x72) (:grp14-p66 . #x73) (:pcmpeqb .    #x74) (:pcmpeqw .    #x75) (:pcmpeqd .  #x76)  #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmppd .     #xc2)  #|   invalid   |#  (:pinsrw .     #xc4) (:pextsrw .    #xc5) (:shufpd .   #xc6) (:grp9 .     #xc7)
  (:addsubpd .  #xd0) (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .      #xd4) (:pmullw .     #xd5) (:movq .     #xd6) (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .    #xe4) (:pmulhw .     #xe5) (:cvttpd2d . #xe6) (:movntdq .  #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .    #xf4) (:pmaddwd .    #xf5) (:psadbw .   #xf6) (:maskmovdqu . #xf7)
  (:movapd .    #x28) (:movapd .    #x29) (:cvtpi2pd .  #x2a) (:movntpd .   #x2b) (:cvttpd2pi .  #x2c) (:cvtpd2pi .   #x2d) (:ucomisd .  #x2e) (:comisd .   #x2f)
  (:addpd .     #x58) (:mulpd .     #x59) (:cvtpd2ps .  #x5a) (:cvtps2dq .  #x5b) (:subpd .      #x5c) (:minpd .      #x5d) (:divpd .    #x5e) (:maxpd .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b) (:punpcklqdq . #x6c) (:punpckhqdq . #x6d) (:movd .     #x6e) (:movdqa .   #x6f)
  (:grp17 .     #x78) (:extrq .     #x79)  #|   invalid   |#   #|   invalid   |#  (:haddpd       #x7c) (:hsubpd .     #x7d)  (:movd .    #x7e) (:movdqa .   #x7f)
  ;; b[8-f]: strange irregularity (heh) -- absence..
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .    #xdc) (:paddusw .    #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .     #xec) (:paddsw .     #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .       #xfc) (:padw .       #xfd) (:padd .     #xfe)  #|   invalid  |#)

(defattrset *amd64-isa* :opcode-ext-variant-f2-prefixed
  (:movsd .     #x10) (:movsd .     #x11) (:movddup .   #x12)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  (:sqrtsd .    #x51)  #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  ;; 6[0-7]: invalid
  (:pshuflw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpsd .     #xc2)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#  (:grp9 .     #xc7)
  (:addsubps .  #xd0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:movdq2q .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:cvtpd2dq . #xe6)  #|   invalid  |#
  (:lddqu .     #xf0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#   #|   invalid   |#  (:cvtsi2sd .  #x2a) (:movntsd .   #x2b) (:cvttsd2si .  #x2c) (:cvtsd2si .   #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addsd .     #x58) (:mulsd .     #x59) (:cvtsd2ss .  #x5a)  #|   invalid   |#  (:subsd        #x5c) (:minsd .      #x5d) (:divsd .    #x5e) (:maxsd .    #x5f)
  ;; 6[8-f]: invalid
  (:insertq .   #x78) (:insertq .   #x79)  #|   invalid   |#   #|   invalid   |#  (:haddps       #x5c) (:hsubps .     #x5d)  #|   invalid  |#   #|   invalid  |#
  ;; b[8-f]: invalid
  ;; d[8-f]: invalid
  ;; e[8-f]: invalid
  ;; f[8-f]: invalid
  )

(defattrset *amd64-isa* modrm-grp1-80
  (:add .    #x0) (:or .     #x1) (:adc .    #x2) (:sbb .    #x3) (:and .    #x4) (:sub .    #x5) (:xor .    #x6) (:cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-81
  (:add .    #x0) (:or .     #x1) (:adc .    #x2) (:sbb .    #x3) (:and .    #x4) (:sub .    #x5) (:xor .    #x6) (:cmp .    #x7))
(defattrset *amd64-isa* shortmode-only-modrm-grp1-82
  (:add .    #x0) (:or .     #x1) (:adc .    #x2) (:sbb .    #x3) (:and .    #x4) (:sub .    #x5) (:xor .    #x6) (:cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-83
  (:add .    #x0) (:or .     #x1) (:adc .    #x2) (:sbb .    #x3) (:and .    #x4) (:sub .    #x5) (:xor .    #x6) (:cmp .    #x7))
(defattrset *amd64-isa* modrm-grp1-8f
  (:pop .    #x0)  #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp2-c0
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-c1
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d0
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d1
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d2
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))
(defattrset *amd64-isa* modrm-grp2-d3
  (:rol .    #x0) (:ror .    #x1) (:rcl .    #x2) (:rcr .    #x3) (:shl/sal . #x4) (:shr .   #x5) (:shl/sal . #x6) (:sar .   #x7))

(defattrset *amd64-isa* modrm-grp3-f6
  (:test .   #x0) (:test .   #x1) (:not .    #x2) (:neg .    #x3) (:mul .    #x4) (:imul .   #x5) (:div .     #x6) (:idiv .  #x7))
(defattrset *amd64-isa* modrm-grp3-f7
  (:test .   #x0) (:test .   #x1) (:not .    #x2) (:neg .    #x3) (:mul .    #x4) (:imul .   #x5) (:div .     #x6) (:idiv .  #x7))

(defattrset *amd64-isa* modrm-grp4
  (:inc .    #x0) (:dec .    #x1)  #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp5
  (:inc .    #x0) (:dec .    #x1) (:call .   #x2) (:call .   #x3) (:jmp .    #x4) (:jmp .    #x5) (:push .   #x6)  #| invalid |#)

(defattrset *amd64-isa* modrm-grp6
  (:sldt .   #x0) (:str .    #x1) (:lldt .   #x2) (:ltr .    #x3) (:verr .   #x4) (:verw .   #x5)  #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp7
  (:sgdt .   #x0) (:trik0 .  #x1) (:lgdt .   #x2) (:trik1 .  #x3) (:smsw .   #x4)  #| invalid |#  (:lmsw .   #x6) (:trik2 .  #x7))

(defattrset *amd64-isa* modrm-grp7-nmod11
  (:mop-sidt .     #x1) (:mop-lidt .     #x3) (:mop-invlpg .  #x7))
(defattrset *amd64-isa* modrm-grp7-mod11-trik0
  (:trik-swapgs .  #x0) (:trik-rdtscp .  #x1))
(defattrset *amd64-isa* modrm-grp7-mod11-trik1
  (:trik-vmrun .   #x0) (:trik-vmmcall . #x1) (:trik-vmload . #x2) (:trik-vmsave . #x3) (:trik-stgi . #x4) (:trik-clgi . #x5) (:trik-skinit . #x6) (:trik-invlpga . #x7))
(defattrset *amd64-isa* modrm-grp7-mod11-trik2
  (:trik-monitor . #x0) (:trik-mwait .   #x1))

(defattrset *amd64-isa* modrm-grp8
   #| invalid     |#   #| invalid     |#   #| invalid   |#   #| invalid   |#  (:bt .     #x4) (:bts .    #x5) (:btr .    #x6) (:btc .    #x7))

(defattrset *amd64-isa* modrm-grp9 
   #| invalid     |#  (:cmpxchg8/16b . #x1) #| invalid  |#   #| invalid   |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp10 ;; what a genius plan...
   #| invalid     |#   #| invalid     |#   #| invalid   |#   #| invalid   |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp11-c6
  (:mov .        #x0)  #| invalid     |#   #| invalid   |#   #| invalid   |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)
(defattrset *amd64-isa* modrm-grp11-c7
  (:mov .        #x0)  #| invalid     |#   #| invalid   |#   #| invalid   |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grp12-u
   #| invalid     |#   #| invalid     |#  (:psrlw .    #x2)  #| invalid   |#  (:psraw .  #x4)  #| invalid |#  (:psllw .  #x6)  #| invalid |#)
(defattrset *amd64-isa* modrm-grp12-66
   #| invalid     |#   #| invalid     |#  (:psrlw .    #x2)  #| invalid   |#  (:psraw .  #x4)  #| invalid |#  (:psllw .  #x6)  #| invalid |#)

(defattrset *amd64-isa* modrm-grp13-u
   #| invalid     |#   #| invalid     |#  (:psrld .    #x2)  #| invalid   |#  (:psrad .  #x4)  #| invalid |#  (:pslld .  #x6)  #| invalid |#)
(defattrset *amd64-isa* modrm-grp13-66
   #| invalid     |#   #| invalid     |#  (:psrld .    #x2)  #| invalid   |#  (:psrad .  #x4)  #| invalid |#  (:pslld .  #x6)  #| invalid |#)

(defattrset *amd64-isa* modrm-grp14-u
   #| invalid     |#   #| invalid     |#  (:psrlq .    #x2)  #| invalid   |#   #| invalid |#   #| invalid |#  (:psllq .  #x6)  #| invalid |#)
(defattrset *amd64-isa* modrm-grp14-66
   #| invalid     |#   #| invalid     |#  (:psrlq .    #x2) (:psrldq .   #x3)  #| invalid |#   #| invalid |#  (:psllq .  #x6) (:pslldq . #x7))

(defattrset *amd64-isa* modrm-grp15
  (:fxsave .     #x0) (:fxrstor .    #x1) (:ldmxcsr .  #x2) (:stmxcsr .  #x3)  #| invalid |#   #| trickery|#   #| trickery|#   #| trickery|#)
(defattrset *amd64-isa* modrm-grp15-nmod11
                                                                                                                              (:clflush . #x7))
(defattrset *amd64-isa* modrm-grp15-mod11
                                                                                              (:mfence . #x5) (:lfence . #x6) (:sfence . #x7))

(defattrset *amd64-isa* modrm-grp16
  (:prefetch .   #x0) (:prefetch .   #x1) (:prefetch . #x2) (:prefetch . #x3) (:nop .    #x4) (:nop .    #x5) (:nop .    #x6) (:nop .     #x7))

(defattrset *amd64-isa* modrm-grp17
  (:extrq .      #x0)  #| invalid     |#   #| invalid   |#   #| invalid   |#   #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)

(defattrset *amd64-isa* modrm-grpp
  (:prefetch .   #x0) (:prefetch .   #x1)  #| reserved  |#  (:prefetch . #x3)  #| invalid |#   #| invalid |#   #| invalid |#   #| invalid |#)


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
