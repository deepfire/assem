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

(defattrset *amd64-isa* :rex
  (:rex4 .  #b0100))
(defattrset *amd64-isa* :nrex
  (:nrex0 . #b0000) (:nrex1 . #b0001) (:nrex2 . #b0010) (:nrex3 . #b0011)
                    (:nrex5 . #b0101) (:nrex6 . #b0110) (:nrex7 . #b0111)
  (:nrex8 . #b1000) (:nrex9 . #b1001) (:nrexa . #b1010) (:nrexb . #b1011)
  (:nrexc . #b1100) (:nrexd . #b1101) (:nrexe . #b1110) (:nrexf . #b1111))
(defattrset *amd64-isa* :opersz/p
  (:opersz .        #x66))
(defattrset *amd64-isa* :addrsz
  (:addrsz .        #x67))
(defattrset *amd64-isa* :segment
  (:seg-over-cs .   #x2e)
  (:seg-over-ds .   #x3e)
  (:seg-over-es .   #x26)
  (:seg-over-fs .   #x64)
  (:seg-over-gs .   #x65)
  (:seg-over-ss .   #x36))
(defattrset *amd64-isa* :lock
  (:lock .          #xf0))
(defattrset *amd64-isa* :rep/p
  (:rep .           #xf3))
(defattrset *amd64-isa* :repn/p
  (:repn .          #xf2))
(defattrset *amd64-isa* :rex-w
  (nil . #b0) (:w . #b1))
(defattrset *amd64-isa* :rex-r
  (nil . #b0) (:r . #b1))
(defattrset *amd64-isa* :rex-x
  (nil . #b0) (:x . #b1))
(defattrset *amd64-isa* :rex-b
  (nil . #b0) (:b . #b1))
(defattrset *amd64-isa* :xop
  (:xop .           #x0f))
(defattrset *amd64-isa* :3dnow
  (:3dnow .         #x0f))

;;;;
;;;; The assumption:  the "default operand size" for compat/legacy modes is assumed to designate a 32-bit operand size.
;;;;
(defun make-x86/64-isa (sixty-four-p)
  `(nil (00 04 (:rex :nrex))
        (:rex (04 01 (:rex-w))
              (ban :rex :addrsz :segment :lock :opersz/p :rep/p :repn/p)
              (:rex-w (01 01) (:rex-r)
                      (:rex-r (01 01) (:rex-x)
                              (:rex-x (01 01) (:rex-b)
                                      (:rex-b (01 08) (:rex-b)
                                              ;; include keeps the declared window (01 08)
                                              (include :nrex))))))
        (:nrex (-04 08 (:opersz/p :rep/p :repn/p :addrsz :segment :lock
                        :opcode
                        ,(if sixty-four-p
                             :opcode-longmode
                             :opcode-shortmode)
                        (#x80 #x81 ,@(unless sixty-four-p '(#x82)) #x83 #x8f #xc0 #xc1 #xd0 #xd1 #xd2 #xd3 #xf6 #xf7 #xfe #xff #xc6 #xc7)))
               ;; when there's no window declared, include uses the target's one
               (:addrsz   () (ban :addrsz)  (include nil))
               (:segment  () (ban :segment) (include nil))
               (:lock     () (ban :lock)    (include nil))
               (:opersz/p ()
                          (ban :opcode-ext-unprefixed :opersz/p)
                          (add-at :xop :opcode-ext-opersz (#x78))
                          (include nil))
               (:rep/p    ()
                          (ban :opcode-ext-unprefixed :rep/p :repn/p)
                          (add-at :xop :opcode-ext-rep)
                          (include nil))
               (:repn/p   ()
                          (ban :opcode-ext-unprefixed :rep/p :repn/p)
                          (add-at :xop :opcode-ext-repn)
                          (include nil))
               (:opcode ()
                        )
               (:opcode-longmode ()
                                 )
               (:opcode-shortmode ()
                                  )
               (#x80 (+ 03 03 (:grp1-80))
                     (:grp1-80 ()
                               ))
               (#x81 (+ 03 03 (:grp1-81))
                     (:grp1-81 ()
                               ))
               ,@(unless sixty-four-p
                  `((#x82 (+ 03 03 (:grp1-82-shortmode))
                          (:grp1-82-shortmode ()
                                              ))))
               (#x83 (+ 03 03 (:grp1-83))
                     (:grp1-83 ()
                               ))
               (#x8f (+ 03 03 (:grp1-8f))
                     (:grp1-8f ()
                               ))
               (#xc0 (+ 03 03 (:grp2-c0))
                     (:grp2-c0 ()
                               ))
               (#xc1 (+ 03 03 (:grp2-c1))
                     (:grp2-c1 ()
                               ))
               (#xd0 (+ 03 03 (:grp2-d0))
                     (:grp2-d0 ()
                               ))
               (#xd1 (+ 03 03 (:grp2-d1))
                     (:grp2-d1 ()
                               ))
               (#xd2 (+ 03 03 (:grp2-d2))
                     (:grp2-d2 ()
                               ))
               (#xd3 (+ 03 03 (:grp2-d3))
                     (:grp2-d3 ()
                               ))
               (#xf6 (+ 03 03 (:grp3-f6))
                     (:grp3-f6 ()
                               ))
               (#xf7 (+ 03 03 (:grp3-f7))
                     (:grp3-f7 ()
                               ))
               (#xfe (+ 03 03 (:grp4-fe))
                     (:grp4-fe ()
                               ))
               (#xff (+ 03 03 (:grp5-ff))
                     (:grp5-ff ()
                               ))
               (#xc6 (+ 03 03 (:grp11-c6))
                     (:grp11-c6 ()
                                ))
               (#xc7 (+ 03 03 (:grp11-c7))
                     (:grp11-c7 ()
                                ))
               (:xop (08 08 (:opcode-ext
                             ,@(unless sixty-four-p
                                       `(:opcode-ext-shortmode))
                             :opcode-ext-unprefixed :opcode-ext-unprefixed-modrm
                             (#x00 #x01 #xba #xc7 #xb9 #x71 #x72 #x73 #xae #x18 #x0d)))
                     (:opcode-ext ()
                                  )
                     (:opcode-ext-unprefixed ()
                                             )
                     (:opcode-ext-opersz ()
                                         )
                     (:opcode-ext-rep ()
                                      )
                     (:opcode-ext-repn ()
                                       )
                     (#x00 (+ 03 03 (:grp6-0f-00))
                           (:grp6-0f-00 ()
                                        ))
                     (#x01 (+ 03 03 (:grp7-0f-01 (#x101 #x301 #x701)))
                           (:grp7-0f-01 ()
                                        )
                           (#x101 (+ 02 02 (:grp7-0f-01-1-0))
                                  (:grp7-0f-01-1-0 ()
                                                   )
                                  (#x1901 (+ -5 3 (:grp7-0f-01-1-3))
                                          (:grp7-0f-01-1-3 ()
                                                           )))
                           (#x301 (+ 02 02 (:grp7-0f-01-3-0))
                                  (:grp7-0f-01-3-0 ()
                                                   )
                                  (#x1b01 (+ -5 3 (:grp7-0f-01-3-3))
                                          (:grp7-0f-01-3-3 ()
                                                           )))
                           (#x701 (+ 02 02 (:grp7-0f-01-7-0))
                                  (:grp7-0f-01-7-0 ()
                                                   )
                                  (#x1f01 (+ -5 3 (:grp7-0f-01-7-3))
                                          (:grp7-0f-01-7-3 ()
                                                           ))))
                     (#xba (+ 03 03 (:grp8-0f-ba))
                           (:grp8-0f-ba ()
                                        ))
                     (#xc7 (+ 03 03 (:grp9-0f-c7))
                           (:grp9-0f-c7 ()
                                        ))
                     (#xb9 (+ 03 03 (:grp10-0f-b9))
                           (:grp10-0f-b9 ()
                                         ))
                     (#x71 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp12-0f-71))
                           (:grp12-0f-71 ()
                                         ))
                      (#b1 (+ 03 03 (:grp12-0f-71-op))
                           (:grp12-0f-71-op ()
                                         )))
                     (#x72 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp13-0f-72))
                           (:grp13-0f-72 ()
                                         ))
                      (#b1 (+ 03 03 (:grp13-0f-72-op))
                           (:grp13-0f-72-op ()
                                         )))
                     (#x73 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp14-0f-73))
                           (:grp14-0f-73 ()
                                         ))
                      (#b1 (+ 03 03 (:grp14-0f-73-op))
                           (:grp14-0f-73-op ()
                                         )))
                     (#xae (+ 03 03 (:grp15-0f-ae (#x5ae #x6ae #x7ae)))
                           (:grp15-0f-ae ()
                                         )
                           (#x5ae (+ 02 02 (:grp15-0f-ae-5))
                                  (:grp15-0f-ae-5 ()
                                                  ))
                           (#x6ae (+ 02 02 (:grp15-0f-ae-6))
                                  (:grp15-0f-ae-6 ()
                                                  ))
                           (#x7ae (+ 02 02 (:grp15-0f-ae-7))
                                  (:grp15-0f-ae-7 ()
                                                  )))
                     (#x18 (+ 03 03 (:grp16-0f-18))
                           (:grp16-0f-18 ()
                                         ))
                     (#x78 (+ 03 03 (:grp17-0f-78-op))
                           (:grp17-0f-78 ()
                                         ))
                     (#x0d (+ 03 03 (:grpp-0f-0d))
                           (:grpp-0f-0d ()
                                        ))))))

(defattrset *amd64-isa* :opcode
  (:add .       #x00) (:add .     #x01) (:add .      #x02) (:add .       #x03) (:add .       #x04) (:add .       #x05)  #| 32bit mode|#  #| 32bit mode   |#
  (:adc .       #x10) (:adc .     #x11) (:adc .      #x12) (:adc .       #x13) (:adc .       #x14) (:adc .       #x15)  #| 32bit mode|#  #| 32bit mode   |#
  (:and .       #x20) (:and .     #x21) (:and .      #x22) (:and .       #x23) (:and .       #x24) (:and .       #x25)  #| ES seg    |#  #| 32bit mode   |#
  (:xor .       #x30) (:xor .     #x31) (:xor .      #x32) (:xor .       #x33) (:xor .       #x34) (:xor .       #x35)  #| SS seg    |#  #| 32bit mode   |#
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#  #|    rex       |#
  (:push .      #x50) (:push .    #x51) (:push .     #x52) (:push .      #x53) (:push .      #x54) (:push .      #x55) (:push .    #x56) (:push .      #x57)
   #| 32bit mode  |#   #| 32bit mode|#   #| 32bit mode |#   #| 64bit mode  |#   #|   FS seg     |#   #|   GS seg    |#   #| oper size |#   #| addr size   |#
  (:jo .        #x70) (:jno .     #x71) (:jb .       #x72) (:jnb .       #x73) (:jz .        #x74) (:jnz .       #x75) (:jbe .     #x76) (:jnbe .      #x77)
   #|   grp1      |#   #|   grp1    |#   #| 32bit grp  |#   #|   grp1      |#  (:test .      #x84) (:test .      #x85) (:xchg .    #x86) (:xchg .      #x87)
  (:xchg.       #x90) (:xchg .    #x91) (:xchg.      #x92) (:xchg .      #x93) (:xchg .      #x94) (:xchg .      #x95) (:xchg .    #x96) (:xchg .      #x97)
  (:mov .       #xa0) (:mov .     #xa1) (:mov .      #xa2) (:mov .       #xa3) (:movsb .     #xa4) (:movsw/d/q . #xa5) (:cmpsb .   #xa6) (:cmpsw/d/q . #xa7)
  (:mov .       #xb0) (:mov .     #xb1) (:mov .      #xb2) (:mov .       #xb3) (:mov .       #xb4) (:mov .       #xb5) (:mov .     #xb6) (:mov .       #xb7)
   #|   grp2      |#   #|   grp2    |#  (:ret-near . #xc2) (:ret-near .  #xc3)  #| 32bit mode  |#   #| 32bit mode  |#   #|   grp11   |#   #|   grp11     |#
   #|   grp2      |#   #|   grp2    |#   #|   grp2     |#   #|   grp2      |#   #| 32bit mode  |#   #| 32bit mode  |#   #| 32bit mode|#  (:xlat .      #xd7)
  (:loopne/nz . #xe0) (:loope/z . #xe1) (:loop .     #xe2) (:jxcxz .     #xe3) (:in .        #xe4) (:in .        #xe5) (:out .     #xe6) (:out .       #xe7)
   #|  lock       |#  (:int1 .    #xf1)  #|   repn     |#   #|   rep       |#  (:hlt .       #xf4) (:cmc .       #xf5)  #|   grp3    |#   #|   grp3      |#
  (:or .        #x08) (:or .      #x09) (:or .       #x0a) (:or .        #x0b) (:or .        #x0c) (:or .        #x0d)  #| 32bit mode|#   #| xop         |#
  (:sbb .       #x18) (:sbb .     #x19) (:sbb .      #x1a) (:sbb .       #x1b) (:sbb .       #x1c) (:sbb .       #x1d)  #| 32bit mode|#   #| 32bit mode  |# 
  (:sub .       #x28) (:sub .     #x29) (:sub .      #x2a) (:sub .       #x2b) (:sub .       #x2c) (:sub .       #x2d)  #| CS seg    |#   #| 32bit mode  |# 
  (:cmp .       #x38) (:cmp .     #x39) (:cmp .      #x3a) (:cmp .       #x3b) (:cmp .       #x3c) (:cmp .       #x3d)  #| DS seg    |#   #| 32bit mode  |# 
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#  #|    rex       |#
  (:pop .       #x58) (:pop .     #x59) (:pop .      #x5a) (:pop .       #x5b) (:pop .       #x5c) (:pop .       #x5d) (:pop .     #x5e) (:pop .       #x5f)
  (:push .      #x68) (:imul .    #x69) (:push .     #x6a) (:imul .      #x6b) (:insb .      #x6c) (:insw/d .    #x6d) (:outsb .   #x6e) (:outsw/d .   #x6f)
  (:js .        #x78) (:jns .     #x79) (:jp .       #x7a) (:jnp .       #x7b) (:jl .        #x7c) (:jnl .       #x7d) (:jle .     #x7e) (:jnle .      #x7f)
  (:mov .       #x88) (:mov .     #x89) (:mov .      #x8a) (:mov .       #x8b) (:mov .       #x8c) (:lea .       #x8d) (:mov .     #x8e)  #|   grp1      |#
  (:cbwde/qe .  #x98) (:cwdqo .   #x99)  #| 32bit mode |#  (:f/wait .    #x9b) (:pushf/d/q . #x9c) (:popf/d/q .  #x9d) (:sahf .    #x9e) (:lahf .      #x9f)
  (:test .      #xa8) (:test .    #xa9) (:stosb .    #xaa) (:stosw/d/q . #xab) (:lodsb .     #xac) (:lodsw/d/q . #xad) (:scasb .   #xae) (:scasw/d/q . #xaf)
  (:mov .       #xb8) (:mov .     #xb9) (:mov .      #xba) (:mov .       #xbb) (:mov .       #xbc) (:mov .       #xbd) (:mov .     #xbe) (:mov .       #xbf)
  (:enter .     #xc8) (:leave .   #xc9) (:ret .      #xca) (:ret .       #xcb) (:int3 .      #xcc) (:int .       #xcd)  #| 32bit mode|#  (:iret/d/q .  #xcf)
   #|   x87       |#   #|   x87     |#   #|   x87      |#   #|   x87       |#   #|   x87       |#   #|   x87       |#   #|   x87     |#  #|    x87       |#
  (:call .      #xe8) (:jmp .     #xe9)  #| 32bit mode |#  (:jmp .       #xeb) (:in .        #xec) (:in .        #xed) (:out .     #xee) (:out .       #xef)
  (:clc .       #xf8) (:stc .     #xf9) (:cli .      #xfa) (:sti .       #xfb) (:cld .       #xfc) (:std .       #xfd)  #| 64bit mode|#   #|   grp5      |#)
  
(defattrset *amd64-isa* :opcode-longmode
   #|  .........           .......           ........  |#  (:movsxd .    #x63)) #|  .........           .........           .......           .........  |#

(defattrset *amd64-isa* :opcode-shortmode
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-es . #x06) (:pop-es .    #x07)
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ss . #x16) (:pop-ss .    #x17)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:daa .       #x27)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aaa .       #x37)
  (:inc .       #x40) (:inc .     #x41) (:inc .      #x42) (:inc .       #x43) (:inc .       #x44) (:inc .       #x45) (:inc .     #x46) (:inc .       #x47)
  (:pusha/d .   #x60) (:popa/d .  #x61) (:bound .    #x62) (:arpl .      #x63)  #|  .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:les .       #xc4) (:lds .       #xc5)  #|  .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:aam .       #xd4) (:aad .       #xd5) (:salc .    #xd6)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-cs . #x0e)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ds . #x1e) (:pop-ds .    #x1f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:das .       #x2f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aas .       #x3f)
  (:dec .       #x48) (:dec .     #x49) (:dec .      #x4a) (:dec .       #x4b) (:dec .       #x4c) (:dec .       #x4d) (:dec .     #x4e) (:dec .       #x4f)
   #|  .........           .......  |#  (:call .     #x9a)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:into .    #xce)  #|  .........  |#
   #|  .........           .......  |#  (:jmp .      #xea)  #|  .........           .........           .........           .......           .........  |#)

(defattrset *amd64-isa* :opcode-ext
   #|    grp6               grp7      |#  (:lar .       #x02) (:lsl .      #x03)  #|   invalid  |#  (:syscall .  #x05) (:clts .    #x06) (:sysret .   #x07)
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
  (:invd .      #x08) (:wbinvd .    #x09)  #|   invalid   |#  (:ud2 .      #x0b)  #|   invalid  |#   #|   grp p    |#  (:femms .   #x0e)  #|   3dnow    |#
   #| modrm group |#  (:nop .       #x19) (:nop .       #x1a) (:nop .      #x1b) (:nop .      #x1c) (:nop .      #x1d) (:nop .     #x1e) (:nop .      #x1f)
  ;; 2[8-f]: prefixed
  ;; 3[8-f]: invalid
  (:cmovs .     #x48) (:cmovns .    #x49) (:cmovp .     #x4a) (:cmovnp .   #x4b) (:cmovl .    #x4c) (:cmovnl .   #x4d) (:cmovle .  #x4e) (:cmovnle .  #x4f)
  ;; 5[8-f]: prefixed
  ;; 6[8-f]: prefixed
  ;; 7[8-f]: prefixed
  (:js .        #x88) (:jns .       #x89) (:jp .        #x8a) (:jnp .      #x8b) (:jl .       #x8c) (:jnl .      #x8d) (:jle .     #x8e) (:jnle .     #x8f)
  (:sets .      #x98) (:setns .     #x99) (:setp .      #x9a) (:setnp .    #x9b) (:setl .     #x9c) (:setnl .    #x9d) (:setle   . #x9e) (:setnle .   #x9f)
  (:push .      #xa8) (:pop .       #xa9) (:rsm .       #xaa) (:bts .      #xab) (:shrd .     #xac) (:shrd .     #xad) (:grp15-ae . #xae) (:imul .     #xaf)
  ;; b[8-f]: prefixed
  (:bswap .     #xc8) (:bswap .     #xc9) (:bswap .     #xca) (:bswap .    #xcb) (:bswap .    #xcc) (:bswap .    #xcd) (:bswap .   #xce) (:bswap .    #xcf)
  ;; d[8-f]: prefixed
  ;; e[8-f]: prefixed
  ;; f[8-f]: prefixed
  )

(defattrset *amd64-isa* :opcode-ext-shortmode
  #|    .........           .........           .........            ........ |#  (:sysenter .  #x34) (:sysexit .  #x35)  #|   .......            ........ |#)

(defattrset *amd64-isa* :opcode-ext-unprefixed
  (:movups .    #x10) (:movups .    #x11) (:movl/hlps . #x12) (:movlps .    #x13) (:unpcklps .  #x14) (:unpckhps . #x15) (:movh/lhps . #x16) (:movhps .  #x17)
  (:movmskps .  #x50) (:sqrtps .    #x51) (:rsqrtps .   #x52) (:rcpps .     #x53) (:andps .     #x54) (:andnps .   #x55) (:orps .     #x56) (:xorps .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .   #x64) (:pcmpgtw .  #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufw .    #x70)  #|   grp12     |#   #|   grp13     |#   #|   grp14     |#  (:pcmpeqb .   #x74) (:pcmpeqw .  #x75) (:pcmpeqd .  #x76) (:emss .     #x77)
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpps .     #xc2) (:movnti .    #xc3) (:pinsrw .    #xc4) (:pextsrw .  #xc5) (:shufps .   #xc6) (:grp9 .     #xc7)
   #|   invalid   |#  (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .     #xd4) (:pmullw .   #xd5)  #|   invalid  |#  (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .   #xe4) (:pmulhw .   #xe5)  #|   invalid  |#  (:movntq .   #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .   #xf4) (:pmaddwd .  #xf5) (:psadbw .   #xf6) (:maskmovq . #xf7)
  (:movaps .    #x28) (:movaps .    #x29) (:cvtpi2ps .  #x2a) (:movntps .   #x2b) (:cvttps2pi . #x2c) (:cvtps2pi . #x2d) (:ucomiss .  #x2e) (:comiss .   #x2f)
  (:addps .     #x58) (:mulps .     #x59) (:cvtps2pd .  #x5a) (:cvtdq2ps .  #x5b) (:subps .     #x5c) (:minps .    #x5d) (:divps .    #x5e) (:maxps .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b)  #|   invalid   |#   #|   invalid  |#  (:movd .     #x6e) (:movq .     #x6f)
   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movd .     #x7e) (:movq .     #x7f)
   #|   reserved  |#   #|   grp10     |#   #|   grp8      |#  (:btc .       #xbb) (:bsf .       #xbc) (:bsr .      #xbd) (:movsx .    #xbe) (:movsx .    #xbf)
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .   #xdc) (:paddusw .  #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .    #xec) (:paddsw .   #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .      #xfc) (:padw .     #xfd) (:padd .     #xfe)  #|   invalid  |#)

(defattrset *amd64-isa* :opcode-ext-rep
  (:movss .     #x10) (:movss .     #x11) (:movsldup .  #x12)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movshdup . #x16)  #|   invalid  |#
   #|   invalid   |#  (:sqrtss .    #x51) (:rsqrtss .   #x52) (:rcpss .     #x53)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  (:pshufhw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpss .     #xc2)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movq2dq .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:cvtdq2pd . #xe6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#  (:cvtsi2ss .  #x2a) (:movntss .   #x2b) (:cvttss2si . #x2c) (:cvtss2si . #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addss .     #x58) (:mulss .     #x59) (:cvtss2sd .  #x5a) (:cvttps2dq . #x5b) (:subss       #x5c) (:minss .    #x5d) (:divss .    #x5e) (:maxss .    #x5f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#   #|   invalid  |#  (:movdqu     #x6f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movq .     #x7e) (:movdqu .   #x7f)
  (:popcnt .    #xb8) #|    reserved  |#   #|   reserved  |#   #|   reserved  |#   #|   reserved  |#  (:lzcnt .    #xbd)  #|   reserved |#   #|   reserved |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  )

(defattrset *amd64-isa* :opcode-ext-opersz
  (:movupd .    #x10) (:movupd .    #x11) (:movlpd .    #x12) (:movlpd .    #x13) (:unpcklpd .   #x14) (:unpckhpd .   #x15) (:movhpd .   #x16) (:movhpd .   #x17)
  (:movmskpd .  #x50) (:sqrtpd .    #x51)  #|   invalid   |#   #|   invalid   |#  (:andpd .      #x54) (:andnpd .     #x55) (:orpd .     #x56) (:xorpd .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .    #x64) (:pcmpgtw .    #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufd .    #x70)  #|   grp12     |#   #|   grp13     |#   #|   grp14     |#  (:pcmpeqb .    #x74) (:pcmpeqw .    #x75) (:pcmpeqd .  #x76)  #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmppd .     #xc2)  #|   invalid   |#  (:pinsrw .     #xc4) (:pextsrw .    #xc5) (:shufpd .   #xc6)  #|   invalid  |#
  (:addsubpd .  #xd0) (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .      #xd4) (:pmullw .     #xd5) (:movq .     #xd6) (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .    #xe4) (:pmulhw .     #xe5) (:cvttpd2d . #xe6) (:movntdq .  #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .    #xf4) (:pmaddwd .    #xf5) (:psadbw .   #xf6) (:maskmovdqu . #xf7)
  (:movapd .    #x28) (:movapd .    #x29) (:cvtpi2pd .  #x2a) (:movntpd .   #x2b) (:cvttpd2pi .  #x2c) (:cvtpd2pi .   #x2d) (:ucomisd .  #x2e) (:comisd .   #x2f)
  (:addpd .     #x58) (:mulpd .     #x59) (:cvtpd2ps .  #x5a) (:cvtps2dq .  #x5b) (:subpd .      #x5c) (:minpd .      #x5d) (:divpd .    #x5e) (:maxpd .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b) (:punpcklqdq . #x6c) (:punpckhqdq . #x6d) (:movd .     #x6e) (:movdqa .   #x6f)
   #|   grp17     |#  (:extrq .     #x79)  #|   invalid   |#   #|   invalid   |#  (:haddpd       #x7c) (:hsubpd .     #x7d)  (:movd .    #x7e) (:movdqa .   #x7f)
  ;; b[8-f]: strange irregularity (heh) -- absence..
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .    #xdc) (:paddusw .    #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .     #xec) (:paddsw .     #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .       #xfc) (:padw .       #xfd) (:padd .     #xfe)  #|   invalid  |#)

(defattrset *amd64-isa* :opcode-ext-repn
  (:movsd .     #x10) (:movsd .     #x11) (:movddup .   #x12)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  (:sqrtsd .    #x51)  #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:pshuflw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpsd .     #xc2)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:addsubps .  #xd0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:movdq2q .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:cvtpd2dq . #xe6)  #|   invalid  |#
  (:lddqu .     #xf0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#   #|   invalid   |#  (:cvtsi2sd .  #x2a) (:movntsd .   #x2b) (:cvttsd2si .  #x2c) (:cvtsd2si .   #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addsd .     #x58) (:mulsd .     #x59) (:cvtsd2ss .  #x5a)  #|   invalid   |#  (:subsd        #x5c) (:minsd .      #x5d) (:divsd .    #x5e) (:maxsd .    #x5f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
  (:insertq .   #x78) (:insertq .   #x79)  #|   invalid   |#   #|   invalid   |#  (:haddps       #x5c) (:hsubps .     #x5d)  #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#)

(defattrset *amd64-isa* :grp1-80
  (:add    .  #x080) (:or .        #x180) (:adc .     #x280) (:sbb .     #x380) (:and .     #x480) (:sub .    #x580) (:xor .      #x680) (:cmp .       #x780))
(defattrset *amd64-isa* :grp1-81
  (:add .     #x081) (:or .        #x181) (:adc .     #x281) (:sbb .     #x381) (:and .     #x481) (:sub .    #x581) (:xor .      #x681) (:cmp .       #x781))
(defattrset *amd64-isa* :grp1-82-shortmode
  (:add .     #x082) (:or .        #x182) (:adc .     #x282) (:sbb .     #x382) (:and .     #x482) (:sub .    #x582) (:xor .      #x682) (:cmp .       #x782))
(defattrset *amd64-isa* :grp1-83
  (:add .     #x083) (:or .        #x183) (:adc .     #x283) (:sbb .     #x383) (:and .     #x483) (:sub .    #x583) (:xor .      #x683) (:cmp .       #x783))
(defattrset *amd64-isa* :grp1-8f
  (:pop .     #x08f)  #|   invalid    |#   #|   invalid  |#   #|   invalid  |#   #|   invalid  |#   #| invalid   |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp2-c0
  (:rol .     #x0c0) (:ror .       #x1c0) (:rcl .     #x2c0) (:rcr .     #x3c0) (:shl/sal . #x4c0) (:shr .    #x5c0) (:shl/sal .  #x6c0) (:sar .       #x7c0))
(defattrset *amd64-isa* :grp2-c1
  (:rol .     #x0c1) (:ror .       #x1c1) (:rcl .     #x2c1) (:rcr .     #x3c1) (:shl/sal . #x4c1) (:shr .    #x5c1) (:shl/sal .  #x6c1) (:sar .       #x7c1))
(defattrset *amd64-isa* :grp2-d0
  (:rol .     #x0d0) (:ror .       #x1d0) (:rcl .     #x2d0) (:rcr .     #x3d0) (:shl/sal . #x4d0) (:shr .    #x5d0) (:shl/sal .  #x6d0) (:sar .       #x7d0))
(defattrset *amd64-isa* :grp2-d1                                                                                              
  (:rol .     #x0d1) (:ror .       #x1d1) (:rcl .     #x2d1) (:rcr .     #x3d1) (:shl/sal . #x4d1) (:shr .    #x5d1) (:shl/sal .  #x6d1) (:sar .       #x7d1))
(defattrset *amd64-isa* :grp2-d2                                                                                              
  (:rol .     #x0d2) (:ror .       #x1d2) (:rcl .     #x2d2) (:rcr .     #x3d2) (:shl/sal . #x4d2) (:shr .    #x5d2) (:shl/sal .  #x6d2) (:sar .       #x7d2))
(defattrset *amd64-isa* :grp2-d3                                                                                              
  (:rol .     #x0d3) (:ror .       #x1d3) (:rcl .     #x2d3) (:rcr .     #x3d3) (:shl/sal . #x4d3) (:shr .    #x5d3) (:shl/sal .  #x6d3) (:sar .       #x7d3))
(defattrset *amd64-isa* :grp3-f6
  (:test .    #x0f6) (:test .      #x1f6) (:not .     #x2f6) (:neg .     #x3f6) (:mul .     #x4f6) (:imul .   #x5f6) (:div .      #x6f6) (:idiv .      #x7f6))
(defattrset *amd64-isa* :grp3-f7
  (:test .    #x0f7) (:test .      #x1f7) (:not .     #x2f7) (:neg .     #x3f7) (:mul .     #x4f7) (:imul .   #x5f7) (:div .      #x6f7) (:idiv .      #x7f7))
(defattrset *amd64-isa* :grp4-fe
  (:inc .     #x0fe) (:dec .       #x1fe)  #|   invalid  |#   #|   invalid  |#   #|   invalid  |#   #| invalid   |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp5-ff
  (:inc .     #x0ff) (:dec .       #x1ff) (:call .    #x2ff) (:call .    #x3ff) (:jmp .     #x4ff) (:jmp .    #x5ff) (:push .     #x6ff)  #|   invalid    |#)
(defattrset *amd64-isa* :grp6-0f-00
  (:sldt .    #x000) (:str .       #x100) (:lldt .    #x200) (:ltr .     #x300) (:verr .    #x400) (:verw .   #x500)  #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp7-0f-01
  (:sgdt .    #x001)  #|     mod      |#  (:lgdt .    #x201)  #|    mod     |#  (:smsw .    #x401)  #| invalid   |#  (:lmsw .     #x601)  #|     mod      |#)

;; extension by mod00 renders them, opcodes, unchanged
(defattrset *amd64-isa* :grp7-0f-01-1-0
  (:sidt .    #x101))
(defattrset *amd64-isa* :grp7-0f-01-3-0
  (:lidt .    #x301))
(defattrset *amd64-isa* :grp7-0f-01-7-0
  (:invlpg .  #x701))

;; mod11, and three r/m bits
(defattrset *amd64-isa* :grp7-0f-01-1-3
  (:swapgs .  #x1901) (:rdtscp .  #x5901))
(defattrset *amd64-isa* :grp7-0f-01-3-3
  (:vmrun .   #x1b01) (:vmmcall . #x5b01) (:vmload . #x9b01) (:vmsave . #xdb01) (:stgi .  #x11b01) (:clgi . #x15b01) (:skinit . #x19b01) (:invlpga . #x1db01))
(defattrset *amd64-isa* :grp7-0f-01-7-3
  (:monitor . #x1f01) (:mwait .   #x5f01))

(defattrset *amd64-isa* :grp8-0f-ba
   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#  (:bt .      #x4ba) (:bts .    #x5ba) (:btr .      #x6ba) (:btc .       #x7ba))
(defattrset *amd64-isa* :grp9-0f-c7 
   #|   invalid  |# (:cmpxchg8/16b . #x1c7) #|  invalid  |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp10-0f-b9
   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#) ;; what a genius plan...
(defattrset *amd64-isa* :grp11-c6
  (:mov .      #x0c6)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp11-c7
  (:mov .      #x0c7)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grp12-0f-71
   #|   invalid   |#   #|   invalid   |#  (:psrlw .   #x271)  #|   invalid  |#  (:psraw .   #x471)  #|  invalid  |#  (:psllw .    #x671)  #|   invalid    |#)
(defattrset *amd64-isa* :grp12-0f-71-op
   #|   invalid   |#   #|   invalid   |#  (:psrlw .   #x271)  #|   invalid  |#  (:psraw .   #x471)  #|  invalid  |#  (:psllw .    #x671)  #|   invalid    |#)
(defattrset *amd64-isa* :grp13-0f-72
   #|   invalid   |#   #|   invalid   |#  (:psrld .   #x272)  #|   invalid  |#  (:psrad .   #x472)  #|  invalid  |#  (:pslld .    #x672)  #|   invalid    |#)
(defattrset *amd64-isa* :grp13-0f-72-op
   #|   invalid   |#   #|   invalid   |#  (:psrld .   #x272)  #|   invalid  |#  (:psrad .   #x472)  #|  invalid  |#  (:pslld .    #x672)  #|   invalid    |#)
(defattrset *amd64-isa* :grp14-0f-73
   #|   invalid   |#   #|   invalid   |#  (:psrlq .   #x273)  #|   invalid  |#   #|  invalid   |#   #|  invalid  |#  (:psllq .    #x673)  #|   invalid    |#)
(defattrset *amd64-isa* :grp14-0f-73-op
   #|   invalid   |#   #|   invalid   |#  (:psrlq .   #x273) (:psrldq .  #x373)  #|  invalid   |#   #|  invalid  |#  (:psllq .    #x673) (:pslldq .    #x773))
(defattrset *amd64-isa* :grp15-0f-ae
  (:fxsave .   #x0ae) (:fxrstor .  #x1ae) (:ldmxcsr . #x2ae) (:stmxcsr . #x3ae)  #|  invalid   |#   #|    mod    |#   #|     mod     |#   #|     mod      |#)

;; extend opcode by two mod bits
;;        mod00              mod11
(defaddrset *amd64-isa* :grp15-0f-ae-5
                      (:mfence .  #x1dae))
(defaddrset *amd64-isa* :grp15-0f-ae-6
                      (:lfence .  #x1eae))
(defaddrset *amd64-isa* :grp15-0f-ae-7
  (:clflush .  #x7ae) (:sfence .  #x1fae))

(defattrset *amd64-isa* :grp16-0f-18
  (:prefetch .   #x0) (:prefetch .   #x1) (:prefetch .  #x2) (:prefetch .  #x3) (:nop .       #x4) (:nop .      #x5) (:nop .        #x6) (:nop .         #x7))
(defattrset *amd64-isa* :grp17-0f-78-op
  (:extrq .      #x0)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(defattrset *amd64-isa* :grpp-0f-0d
  (:prefetch .   #x0) (:prefetch .   #x1)  #|  reserved  |#  (:prefetch .  #x3)  #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)


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

;;;
;;; Warning: we are only storing the last full discriminating byte of the opcode,
;;; and sometimes (modrm...) we have an xinst ambiguity and a tail to examine...
;;;

(defamd64format "<>AL"                   (:rflags :al)           (:rflags :al)          (:aaa #x37)  (:aas #x3f)  (:daa #x27)  (:das #x2f))
(defamd64format "<AL, AH, imm8"          (:rflags :al)           (:al :ah :imm8)        (:aad #xd5))
(defamd64format "<2|2!AL, AH, imm8"      (:rflags :al :ah)       (:al :imm8)            (:aam #xd4))
(defamd64format "<AL, imm8"              (:rflags :al)           (:al :imm8)            (:add #x04)  (:adc #x14)  (:sbb #x1c)  (:sub #x2c))
(defamd64format "<AX, imm16"             (:rflags :ax)           (:ax :imm16)           (:add #x05)  (:adc #x15)  (:sbb #x1d)  (:sub #x2d))
(defamd64format "<EAX, imm32"            (:rflags :eax)          (:eax :imm32)          (:add #x05)  (:adc #x15)  (:sbb #x1d)  (:sub #x2d))
(defamd64format "<RAX, imm32"            (:rflags :rax)          (:rax :imm32)          (:add #x05)  (:adc #x15)  (:sbb #x1d)  (:sub #x2d))
(defamd64format "<reg/mem8, imm8"        (:rflags :reg/mem8)     (:reg/mem8 :imm8)      (:add #x080) (:adc #x280) (:sbb #x380) (:sub #x580))
(defamd64format "<reg/mem16, imm16"      (:rflags :reg/mem16)    (:reg/mem16 :imm16)    (:add #x081) (:adc #x281) (:sbb #x381) (:sub #x581))
(defamd64format "<reg/mem32, imm32"      (:rflags :reg/mem32)    (:reg/mem32 :imm32)    (:add #x081) (:adc #x281) (:sbb #x381) (:sub #x581))
(defamd64format "<reg/mem64, imm32"      (:rflags :reg/mem64)    (:reg/mem64 :imm32)    (:add #x081) (:adc #x281) (:sbb #x381) (:sub #x581))
(defamd64format "<reg/mem16, imm8"       (:rflags :reg/mem16)    (:reg/mem16 :imm8)     (:add #x083) (:adc #x283) (:sbb #x383) (:sub #x583) (:bts #x5ba) (:btr #x6ba) (:btc #x7ba))
(defamd64format "<reg/mem32, imm8"       (:rflags :reg/mem32)    (:reg/mem32 :imm8)     (:add #x083) (:adc #x283) (:sbb #x383) (:sub #x583) (:bts #x5ba) (:btr #x6ba) (:btc #x7ba))
(defamd64format "<reg/mem64, imm8"       (:rflags :reg/mem64)    (:reg/mem64 :imm8)     (:add #x083) (:adc #x283) (:sbb #x383) (:sub #x583) (:bts #x5ba) (:btr #x6ba) (:btc #x7ba))
(defamd64format "<reg/mem8, reg8"        (:rflags :reg/mem8)     (:reg/mem8 :reg8)      (:add #x00)  (:adc #x10)  (:sbb #x18)  (:sub #x28))
(defamd64format "<reg/mem16, reg16"      (:rflags :reg/mem16)    (:reg/mem16 :reg16)    (:add #x01)  (:adc #x11)  (:sbb #x19)  (:sub #x29)  (:bts #xab)  (:btr #xb3)  (:btc #xbb))
(defamd64format "<reg/mem32, reg32"      (:rflags :reg/mem32)    (:reg/mem32 :reg32)    (:add #x01)  (:adc #x11)  (:sbb #x19)  (:sub #x29)  (:bts #xab)  (:btr #xb3)  (:btc #xbb))
(defamd64format "<reg/mem64, reg64"      (:rflags :reg/mem64)    (:reg/mem64 :reg64)    (:add #x01)  (:adc #x11)  (:sbb #x19)  (:sub #x29)  (:bts #xab)  (:btr #xb3)  (:btc #xbb))
(defamd64format "<reg8, reg/mem8"        (:rflags :reg8)         (:reg8 :reg/mem8)      (:add #x02)  (:adc #x12)  (:sbb #x1a)  (:sub #x2a))
(defamd64format "<reg16, reg/mem16"      (:rflags :reg16)        (:reg16 :reg/mem16)    (:add #x03)  (:adc #x13)  (:sbb #x1b)  (:sub #x2b))
(defamd64format "<reg32, reg/mem32"      (:rflags :reg32)        (:reg32 :reg/mem32)    (:add #x03)  (:adc #x13)  (:sbb #x1b)  (:sub #x2b))
(defamd64format "<reg64, reg/mem64"      (:rflags :reg64)        (:reg64 :reg/mem64)    (:add #x03)  (:adc #x13)  (:sbb #x1b)  (:sub #x2b))
;; opcode sharing pools:
;;   ADC, ADD, SBB, SUB, AND, OR and XOR
;;   BTC, BTR, BTS

(defamd64format "AL, imm8"               (:al)                   (:al :imm8)            (:or #x0c)  (:and #x24)  (:xor #x34))
(defamd64format "AX, imm16"              (:ax)                   (:ax :imm16)           (:or #x0d)  (:and #x25)  (:xor #x35))
(defamd64format "EAX, imm32"             (:eax)                  (:eax :imm32)          (:or #x0d)  (:and #x25)  (:xor #x35))
(defamd64format "RAX, imm32"             (:rax)                  (:rax :imm32)          (:or #x0d)  (:and #x25)  (:xor #x35))
(defamd64format "reg/mem8, imm8"         (:reg/mem8)             (:reg/mem8 :imm8)      (:or #x180) (:and #x480) (:xor #x680))
(defamd64format "reg/mem16, imm16"       (:reg/mem16)            (:reg/mem16 :imm16)    (:or #x181) (:and #x481) (:xor #x681))
(defamd64format "reg/mem32, imm32"       (:reg/mem32)            (:reg/mem32 :imm32)    (:or #x181) (:and #x481) (:xor #x681))
(defamd64format "reg/mem64, imm32"       (:reg/mem64)            (:reg/mem64 :imm32)    (:or #x181) (:and #x481) (:xor #x681))
(defamd64format "reg/mem16, imm8"        (:reg/mem16)            (:reg/mem16 :imm8)     (:or #x183) (:and #x483) (:xor #x683))
(defamd64format "reg/mem32, imm8"        (:reg/mem32)            (:reg/mem32 :imm8)     (:or #x183) (:and #x483) (:xor #x683))
(defamd64format "reg/mem64, imm8"        (:reg/mem64)            (:reg/mem64 :imm8)     (:or #x183) (:and #x483) (:xor #x683))
(defamd64format "reg/mem8, reg8"         (:reg/mem8)             (:reg/mem8 :reg8)      (:or #x08)  (:and #x20)  (:xor #x30))
(defamd64format "reg/mem16, reg16"       (:reg/mem16)            (:reg/mem16 :reg16)    (:or #x09)  (:and #x21)  (:xor #x31))
(defamd64format "reg/mem32, reg32"       (:reg/mem32)            (:reg/mem32 :reg32)    (:or #x09)  (:and #x21)  (:xor #x31))
(defamd64format "reg/mem64, reg64"       (:reg/mem64)            (:reg/mem64 :reg64)    (:or #x09)  (:and #x21)  (:xor #x31))
(defamd64format "reg8, reg/mem8"         (:reg8)                 (:reg8 :reg/mem8)      (:or #x0a)  (:and #x22)  (:xor #x32))
(defamd64format "reg16, reg/mem16"       (:reg16)                (:reg16 :reg/mem16)    (:or #x0b)  (:and #x23)  (:xor #x33))
(defamd64format "reg32, reg/mem32"       (:reg32)                (:reg32 :reg/mem32)    (:or #x0b)  (:and #x23)  (:xor #x33))
(defamd64format "reg64, reg/mem64"       (:reg64)                (:reg64 :reg/mem64)    (:or #x0b)  (:and #x23)  (:xor #x33))
;; opcode sharing pools:
;;   ADC, ADD, SBB, SUB, AND, OR and XOR

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
