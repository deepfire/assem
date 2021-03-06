;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEMBLY; Base: 10 -*-
;;;
;;;  (c) copyright 2007-2009 by
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

(in-package :isa-mips)

(defclass mips-isa (isa)
  ()
  (:default-initargs
   :name :mips
   :nop-insn :nop
   :delay-slots 1
   :insn-defines-format-p t
   :root-shift 26 :root-mask #x3f))

(defparameter *mips-isa* (make-instance 'mips-isa))

(define-optype *mips-isa* im26 26)
(define-optype *mips-isa* syscode 20)
(define-optype *mips-isa* brkcode 10)
(define-optype *mips-isa* im16 16)
(define-optype *mips-isa* im5 5)
(define-optype *mips-isa* im3 3)
(define-optype *mips-isa* c1cond 3)
(define-optype *mips-isa* cpsel2 5)

(deftype mips-insn-param-type () '(member im26 syscode brkcode im16 im3 im5 c1cond gpr fpr cpsel cacheop prefop))
(deftype mips-insn-param-offt-type () '(member 21 16 11 6 0))

(define-enumerated-gpr-optype *mips-isa* gpr 5
  ((:zero 0) (:at 1)   (:v0 2)   (:v1 3)   (:a0 4)
   (:a1 5)   (:a2 6)   (:a3 7)   (:t0 8)   (:t1 9)
   (:t2 10)  (:t3 11)  (:t4 12)  (:t5 13)  (:t6 14)
   (:t7 15)  (:s0 16)  (:s1 17)  (:s2 18)  (:s3 19)
   (:s4 20)  (:s5 21)  (:s6 22)  (:s7 23)  (:t8 24)
   (:t9 25)  (:kt0 26) (:kt1 27) (:gp 28)  (:sp 29)
   (:s8 30)  (:ra 31)
   (:r0 0)   (:r1 1)   (:r2 2)   (:r3 3)   (:r4 4)
   (:r5 5)   (:r6 6)   (:r7 7)   (:r8 8)   (:r9 9)
   (:r10 10) (:r11 11) (:r12 12) (:r13 13) (:r14 14)
   (:r15 15) (:r16 16) (:r17 17) (:r18 18) (:r19 19)
   (:r20 20) (:r21 21) (:r22 22) (:r23 23) (:r24 24)
   (:r25 25) (:r26 26) (:r27 27) (:r28 28) (:r29 29)
   (:r30 30) (:r31 31))
  :unallocatables (:zero :r0))

(define-enumerated-fpr-optype *mips-isa* fpr 5
  ((:f0 0)   (:f1 1)   (:f2 2)   (:f3 3)   (:f4 4)
   (:f5 5)   (:f6 6)   (:f7 7)   (:f8 8)   (:f9 9)
   (:f10 10) (:f11 11) (:f12 12) (:f13 13) (:f14 14)
   (:f15 15) (:f16 16) (:f17 17) (:f18 18) (:f19 19)
   (:f20 20) (:f21 21) (:f22 22) (:f23 23) (:f24 24)
   (:f25 25) (:f26 26) (:f27 27) (:f28 28) (:f29 29)
   (:f30 30) (:f31 31)))

(define-enumerated-optype *mips-isa* cpsel 5
  ((:index 0) (:random 1) (:entrylo0 2) (:entrylo1 3)
   (:context 4) (:pagemask 5) (:wired 6) (:badvaddr 8)
   (:count 9) (:entryhi 10) (:compare 11) (:status 12)
   (:cause 13) (:epc 14) (:prid 15) (:config 16)
   (:lladdr 17) (:watchlo 18) (:watchhi 19) (:debug 23)
   (:debugepc 24) (:perfcnt 25) (:ecc 26) (:cacheerr 27)
   (:taglo 28) (:taghi 29) (:errorepc 30) (:desave 31)))

(define-enumerated-optype *mips-isa* cacheop 5
  ((:index-inv-i #x0) (:index-wbinv-d #x1) (:index-inv-si #x2) (:index-wbinv-sd #x3)
   (:index-load-tag-i #x4) (:index-load-tag-d #x5) (:index-load-tag-si #x6) (:index-load-tag-sd #x7)
   (:index-store-tag-i #x8) (:index-store-tag-d #x9) (:index-store-tag-si #xa) (:index-store-tag-sd #xb)
   (:index-dirty-exc-d #xd) (:index-dirty-exc-sd #xf)
   (:hit-inv-i #x0) (:hit-inv-d #x1) (:hit-inv-si #x2) (:hit-inv-sd #x3)
   (:fill-i #x14)
   (:index-wbinv-d #x15) (:index-wbinv-sd #x17)
   (:index-wb-i #x18) (:index-wb-d #x19) (:index-wb-sd #x1b)
   (:index-set-virt-si #x1e) (:index-set-virt-sd #x1f)))

(define-enumerated-optype *mips-isa* prefop 5
  ())

(defmethod validate-insn-parameter-spec ((isa mips-isa) mnemonics params)
  (assert (<= (length params) 3))
  (dolist (param params)
    (unless (typep (car param) 'mips-insn-param-type)
      (error "in insn definition for ~S: the car is not of type MIPS-INSN-PARAM-TYPE" mnemonics))
    (unless (typep (cadr param) 'mips-insn-param-offt-type)
      (error "in insn definition for ~S: the cadr does not designate a usable parameter offset" mnemonics))))

(defun encode-mips-insn (id &rest params)
  (encode-insn *mips-isa* (cons id params)))

(defun decode-mips-insn (opcode &key verbose)
  (decode-insn *mips-isa* opcode :verbose verbose))

(defmethod param-type-alist ((isa mips-isa) type)
  (ecase type
    ((im26 im16 im5 im3 c1cond))
    ((gpr fpr cpsel cacheop prefop)
     (hash-table-alist (optype-set (optype isa type))))))

(defmethod encode-insn-param ((isa mips-isa) val type)
  (ecase type
    ((im26 syscode brkcode im16 im5 im3 c1cond)
     val)
    ((gpr fpr cpsel cacheop prefop)
     (if (integerp val)
         val
         (gethash val (optype-set (optype isa type)))))))

(defmethod decode-insn-param ((isa mips-isa) val type &aux (optype (optype isa type)))
  (case type
    ((im26 im16 im5 im3 c1cond)
     (logand val (optype-mask optype)))
    ((gpr fpr cpsel cacheop prefop)
     (gethash (logand val (optype-mask optype)) (optype-rset optype)))))

(defclass mips-insn (insn) ())
(defclass mips-branch-insn (mips-insn branch-insn) ())
(defclass rel-imm-cond-pure      (mips-branch-insn branch-rel branch-imm branch-cond) ())
(defclass rel-imm-cond-depcont   (mips-branch-insn branch-rel branch-imm branch-cond dep-continue-mixin) ())
(defclass abs-imm-uncond-depcont (mips-branch-insn branch-abs branch-imm branch-uncond dep-continue-mixin) ())
(defclass abs-imm-uncond-noncont (mips-branch-insn branch-abs branch-imm branch-uncond noncontinue-mixin) ())
(defclass abs-reg-uncond-depcont (mips-branch-insn branch-abs branch-reg branch-uncond dep-continue-mixin) ())
(defclass abs-reg-uncond-noncont (mips-branch-insn branch-abs branch-reg branch-uncond noncontinue-mixin) ())
(defclass indef-cond-depcont     (mips-branch-insn branch-indef branch-cond dep-continue-mixin) ())
(defclass indef-uncond-depcont   (mips-branch-insn branch-indef branch-uncond dep-continue-mixin) ())
(defclass indef-uncond-noncont   (mips-branch-insn branch-indef branch-uncond noncontinue-mixin) ())

(defmethod branch-insn-target-address ((o mips-branch-insn) insn-address args)
  (let ((insn-count (ash insn-address -2)))
    (when-let ((delta-fn (branch-destination-fn o)))
      (+ insn-address (ash (apply delta-fn insn-count args) 2)))))

(defmacro defmipsinsn (id branchspec opcode-spec format-name)
  (multiple-value-bind (type dest-fn) (if (atom branchspec) 'nonbranch-insn
                                          (destructuring-bind (type &optional dest-fn) branchspec
                                            (values (case type
                                                      (:ricp 'rel-imm-cond-pure)
                                                      (:ricd 'rel-imm-cond-depcont)
                                                      (:aiud 'abs-imm-uncond-depcont)
                                                      (:aiun 'abs-imm-uncond-noncont)
                                                      (:arud 'abs-reg-uncond-depcont)
                                                      (:arun 'abs-reg-uncond-noncont)
                                                      (:icd 'indef-cond-depcont)
                                                      (:iud 'indef-uncond-depcont)
                                                      (:iun 'indef-uncond-noncont))
                                                    dest-fn)))
    `(progn
       (definsn *mips-isa* ',type ,id ',opcode-spec :format-name ,format-name
                ,@(when dest-fn `(:destination-fn (function ,dest-fn)))))))

(defmacro defmipsformat (id &rest param-spec)
  `(defformat *mips-isa* ,id () ,param-spec))

(defmipsformat :empty)
(defmipsformat :togpr-fromgpr-im5shift     (gpr 11 :dst) (gpr 16 :src) (im5 6))
(defmipsformat :togpr-fromgpr-shiftgpr     (gpr 11 :dst) (gpr 16 :src) (gpr 21 :src))
(defmipsformat :tofpr-paramfpr-fromfpr     (gpr 11 :dst) (gpr 16 :src) (gpr 21 :src))
(defmipsformat :togpr-xgpr-ygpr            (gpr 11 :dst) (gpr 16 :src) (gpr 21 :src))
(defmipsformat :tofpr-paramfpr		   (gpr 11 :dst) (gpr 16 :src))
(defmipsformat :togpr-xgpr-ygpr            (gpr 11 :dst) (gpr 21 :src) (gpr 16 :src))
(defmipsformat :togpr-fromgpr-testgpr      (gpr 11 :dst) (gpr 21 :src) (gpr 16 :src))
(defmipsformat :savegpr-addrgpr            (gpr 11 :dst) (gpr 21 :src))
(defmipsformat :to-gpr                     (gpr 11 :dst))
(defmipsformat :from-gpr                   (gpr 21 :src))
(defmipsformat :xgpr-ygpr                  (gpr 21 :src) (gpr 16 :src))
(defmipsformat :im16                       (im16 0))
(defmipsformat :brkcode                    (brkcode 16))
(defmipsformat :syscode                    (syscode 6))
(defmipsformat :im26                       (im26 0))
(defmipsformat :togpr-fromgpr-im16parm     (gpr 16 :dst) (gpr 21 :src) (im16 0))
(defmipsformat :fromgpr-fromgpr-im16parm   (gpr 16 :src) (gpr 21 :src) (im16 0))
(defmipsformat :tofpr-fromgpr-im16parm     (fpr 16 :dst) (gpr 21 :src) (im16 0))
(defmipsformat :fromfpr-fromgpr-im16parm   (fpr 16 :src) (gpr 21 :src) (im16 0))
(defmipsformat :testgpr-basegpr-im16off    (gpr 21 :src) (gpr 16 :src) (im16 0))
(defmipsformat :testgpr-im16off            (gpr 21 :src) (im16 0))
(defmipsformat :testgpr-im16               (gpr 21 :src) (im16 0))
(defmipsformat :togpr-im16                 (gpr 16 :dst) (im16 0))
(defmipsformat :fromgpr-cpsel              (gpr 16 :src) (cpsel 11 :dst))
(defmipsformat :fromgpr-cpsel2             (gpr 16 :src) (cpsel2 11 :dst))
(defmipsformat :fromgpr-cpsel-im3          (gpr 16 :src) (cpsel 11 :dst) (im3 0 :dst))
(defmipsformat :fromgpr-tofpr              (gpr 16 :src) (fpr 11 :dst))
(defmipsformat :fromgpr-im16off-basegpr    (gpr 16 :src) (im16 0) (gpr 21 :src))
(defmipsformat :togpr-cpsel                (gpr 16 :dst) (cpsel 11 :src))
(defmipsformat :togpr-cpsel2               (gpr 16 :dst) (cpsel2 11 :src))
(defmipsformat :togpr-cpsel-im3            (gpr 16 :dst) (cpsel 11 :src) (im3 0 :src))
(defmipsformat :togpr-fromfpr              (gpr 16 :dst) (fpr 11 :src))
(defmipsformat :togpr-im16off-basegpr      (gpr 16 :dst) (im16 0) (gpr 21 :src))
(defmipsformat :cacheop-im16off-basegpr    (cacheop 16) (im16 0) (gpr 21 :src))
(defmipsformat :prefop-im16off-basegpr     (prefop 16) (im16 0) (gpr 21 :src))
(defmipsformat :c1cond-im16                (c1cond 18) (im16 0))
(defmipsformat :c1cond-fromfpr-fromfpr     (c1cond 8) (fpr 11 :src) (fpr 16 :src))
(defmipsformat :tofpr-fromfpr-c1cond       (fpr 6 :dst) (fpr 11 :src) (c1cond 18))

(defmipsinsn :sll     nil ((#b000000 0 #x3f) (#b000000 0 0)) :togpr-fromgpr-im5shift)
                          
(defmipsinsn :nop     nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00000 0 0)) :empty)
(defmipsinsn :ssnop   nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00001 0 0)) :empty)
                          
(defmipsinsn :srl     nil ((#b000000 0 #x3f) (#b000010 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sra     nil ((#b000000 0 #x3f) (#b000011 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sllv    nil ((#b000000 0 #x3f) (#b000100 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srlv    nil ((#b000000 0 #x3f) (#b000110 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srav    nil ((#b000000 0 #x3f) (#b000111 0 0)) :togpr-fromgpr-shiftgpr)

(defmipsinsn :jr      (:arun) ((#b000000 0 #x3f) (#b001000 0 0)) :from-gpr)
(defmipsinsn :jalr    (:arud) ((#b000000 0 #x3f) (#b001001 0 0)) :savegpr-addrgpr)
(defmipsinsn :movz    nil ((#b000000 0 #x3f) (#b001010 0 0)) :togpr-fromgpr-testgpr)
(defmipsinsn :movn    nil ((#b000000 0 #x3f) (#b001011 0 0)) :togpr-fromgpr-testgpr)

(defmipsinsn :syscall (:iud) ((#b000000 0 #x3f) (#b001100 0 0)) :syscode)
(defmipsinsn :break   (:iud) ((#b000000 0 #x3f) (#b001101 0 0)) :brkcode)
(defmipsinsn :sync    nil ((#b000000 0 #x3f) (#b001111 0 0)) :empty)
(defmipsinsn :breakd  (:iud) ((#b000000 6 #x1f)(#b00001 0 #x3f) (#b001101 0 0)) :empty)

(defmipsinsn :mfhi    nil ((#b000000 0 #x3f) (#b010000 0 0)) :to-gpr)
(defmipsinsn :mthi    nil ((#b000000 0 #x3f) (#b010001 0 0)) :from-gpr)
(defmipsinsn :mflo    nil ((#b000000 0 #x3f) (#b010010 0 0)) :to-gpr)
(defmipsinsn :mtlo    nil ((#b000000 0 #x3f) (#b010011 0 0)) :from-gpr)
(defmipsinsn :dsllv   nil ((#b000000 0 #x3f) (#b010100 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :dsrlv   nil ((#b000000 0 #x3f) (#b010110 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :dsrav   nil ((#b000000 0 #x3f) (#b010111 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :mult    nil ((#b000000 0 #x3f) (#b011000 0 0)) :xgpr-ygpr)
(defmipsinsn :multu   nil ((#b000000 0 #x3f) (#b011001 0 0)) :xgpr-ygpr)
(defmipsinsn :div     nil ((#b000000 0 #x3f) (#b011010 0 0)) :xgpr-ygpr)
(defmipsinsn :divu    nil ((#b000000 0 #x3f) (#b011011 0 0)) :xgpr-ygpr)
(defmipsinsn :dmult   nil ((#b000000 0 #x3f) (#b011100 0 0)) :xgpr-ygpr)
(defmipsinsn :dmultu  nil ((#b000000 0 #x3f) (#b011101 0 0)) :xgpr-ygpr)
(defmipsinsn :ddiv    nil ((#b000000 0 #x3f) (#b011110 0 0)) :xgpr-ygpr)
(defmipsinsn :ddivu   nil ((#b000000 0 #x3f) (#b011111 0 0)) :xgpr-ygpr)
                          
(defmipsinsn :add     nil ((#b000000 0 #x3f) (#b100000 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :addu    nil ((#b000000 0 #x3f) (#b100001 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :sub     nil ((#b000000 0 #x3f) (#b100010 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :subu    nil ((#b000000 0 #x3f) (#b100011 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :and     nil ((#b000000 0 #x3f) (#b100100 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :or      nil ((#b000000 0 #x3f) (#b100101 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :xor     nil ((#b000000 0 #x3f) (#b100110 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :nor     nil ((#b000000 0 #x3f) (#b100111 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :slt     nil ((#b000000 0 #x3f) (#b101010 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :sltu    nil ((#b000000 0 #x3f) (#b101011 0 0)) :togpr-xgpr-ygpr)

(defmipsinsn :dadd    nil ((#b000000 0 #x3f) (#b101100 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :daddu   nil ((#b000000 0 #x3f) (#b101101 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :dsub    nil ((#b000000 0 #x3f) (#b101110 0 0)) :togpr-xgpr-ygpr)
(defmipsinsn :dsubu   nil ((#b000000 0 #x3f) (#b101111 0 0)) :togpr-xgpr-ygpr)

(defmipsinsn :tge     nil ((#b000000 0 #x3f) (#b110000 0 0)) :xgpr-ygpr)
(defmipsinsn :tgeu    nil ((#b000000 0 #x3f) (#b110001 0 0)) :xgpr-ygpr)
(defmipsinsn :tlt     nil ((#b000000 0 #x3f) (#b110010 0 0)) :xgpr-ygpr)
(defmipsinsn :tltu    nil ((#b000000 0 #x3f) (#b110011 0 0)) :xgpr-ygpr)
(defmipsinsn :teq     nil ((#b000000 0 #x3f) (#b110100 0 0)) :xgpr-ygpr)
(defmipsinsn :tne     nil ((#b000000 0 #x3f) (#b110110 0 0)) :xgpr-ygpr)

(defmipsinsn :dsll    nil ((#b000000 0 #x3f) (#b111000 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :dsrl    nil ((#b000000 0 #x3f) (#b111010 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :dsra    nil ((#b000000 0 #x3f) (#b111011 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :dsll32  nil ((#b000000 0 #x3f) (#b111100 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :dsrl32  nil ((#b000000 0 #x3f) (#b111110 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :dsra32  nil ((#b000000 0 #x3f) (#b111111 0 0)) :togpr-fromgpr-im5shift)

(defparameter *branch-shift* 1)

(defun im2bd16 (addr c1cond imoff)
  (declare (ignore addr c1cond))
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :bltz    (:ricp im2bd16) ((#b000001 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bgez    (:ricp im2bd16) ((#b000001 16 #x1f) (#b00001 0 0)) :testgpr-im16off)
(defmipsinsn :bltzl   (:ricp im2bd16) ((#b000001 16 #x1f) (#b00010 0 0)) :testgpr-im16off)
(defmipsinsn :bgezl   (:ricp im2bd16) ((#b000001 16 #x1f) (#b00011 0 0)) :testgpr-im16off)
(defmipsinsn :tgei    (:icd) ((#b000001 16 #x1f) (#b01000 0 0)) :testgpr-im16)
(defmipsinsn :tgeiu   (:icd) ((#b000001 16 #x1f) (#b01001 0 0)) :testgpr-im16)
(defmipsinsn :tlti    (:icd) ((#b000001 16 #x1f) (#b01010 0 0)) :testgpr-im16)
(defmipsinsn :tltiu   (:icd) ((#b000001 16 #x1f) (#b01011 0 0)) :testgpr-im16)
(defmipsinsn :teqi    (:icd) ((#b000001 16 #x1f) (#b01100 0 0)) :testgpr-im16)
(defmipsinsn :tnei    (:icd) ((#b000001 16 #x1f) (#b01110 0 0)) :testgpr-im16)
(defmipsinsn :bltzal  (:ricd im2bd16) ((#b000001 16 #x1f) (#b10000 0 0)) :testgpr-im16off)
(defmipsinsn :bgezal  (:ricd im2bd16) ((#b000001 16 #x1f) (#b10001 0 0)) :testgpr-im16off)
(defmipsinsn :bltzall (:ricd im2bd16) ((#b000001 16 #x1f) (#b10010 0 0)) :testgpr-im16off)
(defmipsinsn :bgezall (:ricd im2bd16) ((#b000001 16 #x1f) (#b10011 0 0)) :testgpr-im16off)

(defun im1bd26 (addr imoff)
  (let ((target (dpb imoff (byte 26 0) addr)))
    (- target addr)))

(defmipsinsn :j       (:aiun im1bd26) ((#b000010 0 0)) :im26)
(defmipsinsn :jal     (:aiud im1bd26) ((#b000011 0 0)) :im26)

(defun im3bd16 (addr gpr1 gpr2 imoff)
  (declare (ignore addr gpr1 gpr2))
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :beq     (:ricp im3bd16) ((#b000100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bne     (:ricp im3bd16) ((#b000101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :blez    (:ricp im3bd16) ((#b000110 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bgtz    (:ricp im3bd16) ((#b000111 0 0)) :testgpr-basegpr-im16off)

(defmipsinsn :addi    nil ((#b001000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :addiu   nil ((#b001001 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :li      nil ((#b001001 21 #x1f) (#b00000 0 0)) :togpr-im16)
(defmipsinsn :slti    nil ((#b001010 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :sltiu   nil ((#b001011 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :andi    nil ((#b001100 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :ori     nil ((#b001101 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :xori    nil ((#b001110 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :lui     nil ((#b001111 0 0)) :togpr-im16)

(defmipsinsn :mfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0000 0 0)) :fromgpr-cpsel-im3)
(defmipsinsn :dmfc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0001 0 0)) :fromgpr-cpsel)
(defmipsinsn :cfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0010 0 0)) :fromgpr-cpsel)
(defmipsinsn :mtc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0100 0 0)) :togpr-cpsel-im3)
(defmipsinsn :dmtc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0101 0 0)) :togpr-cpsel)
(defmipsinsn :ctc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0110 0 0)) :togpr-cpsel)

(defun im1bd16 (addr imoff)
  (declare (ignore addr))
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :bc0f    (:ricp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0000 0 0)) :im16)
(defmipsinsn :bc0t    (:ricp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0001 0 0)) :im16)
(defmipsinsn :bc0f1   (:ricp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0010 0 0)) :im16)
(defmipsinsn :bc0t1   (:ricp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0011 0 0)) :im16)

(defmipsinsn :tlbr    nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000001 0 0)) :empty)
(defmipsinsn :tlbwi   nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000010 0 0)) :empty)
(defmipsinsn :tlbwr   nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000110 0 0)) :empty)
(defmipsinsn :tlbp    nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b001000 0 0)) :empty)
(defmipsinsn :rfe     (:iun)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b010000 0 0)) :empty)
(defmipsinsn :eret    (:iun)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b011000 0 0)) :empty)
(defmipsinsn :dret    (:iun)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b011111 0 0)) :empty)

(defmipsinsn :mfc1    nil  ((#b010001 21 #x1f) (#b00000 0 0)) :togpr-fromfpr)
(defmipsinsn :dmfc1   nil  ((#b010001 21 #x1f) (#b00001 0 0)) :togpr-fromfpr)
(defmipsinsn :cfc1    nil  ((#b010001 21 #x1f) (#b00010 0 0)) :togpr-fromfpr)
(defmipsinsn :mtc1    nil  ((#b010001 21 #x1f) (#b00100 0 0)) :fromgpr-tofpr)
(defmipsinsn :dmtc1   nil  ((#b010001 21 #x1f) (#b00101 0 0)) :fromgpr-tofpr)
(defmipsinsn :ctc1    nil  ((#b010001 21 #x1f) (#b00110 0 0)) :fromgpr-tofpr)

(defmipsinsn :bc1f    (:ricp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b00 0 0)) :c1cond-im16)
(defmipsinsn :bc1t    (:ricp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b01 0 0)) :c1cond-im16)
(defmipsinsn :bc1fl   (:ricp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b10 0 0)) :c1cond-im16)
(defmipsinsn :bc1fl   (:ricp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b11 0 0)) :c1cond-im16)

(defmipsinsn :add.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000000 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :add.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000000 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :sub.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000001 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :sub.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000001 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :mul.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000010 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :mul.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000010 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :div.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000011 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :div.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000011 0 0)) :tofpr-paramfpr-fromfpr)

(defmipsinsn :sqrt.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000100 0 0)) :tofpr-paramfpr)
(defmipsinsn :sqrt.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000100 0 0)) :tofpr-paramfpr)
(defmipsinsn :abs.s     nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000101 0 0)) :tofpr-paramfpr)
(defmipsinsn :abs.d     nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000101 0 0)) :tofpr-paramfpr)
(defmipsinsn :mov.s     nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000110 0 0)) :tofpr-paramfpr)
(defmipsinsn :mov.d     nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000110 0 0)) :tofpr-paramfpr)
(defmipsinsn :neg.s     nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b000111 0 0)) :tofpr-paramfpr)
(defmipsinsn :neg.d     nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b000111 0 0)) :tofpr-paramfpr)
(defmipsinsn :round.l.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001000 0 0)) :tofpr-paramfpr)
(defmipsinsn :round.l.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001000 0 0)) :tofpr-paramfpr)
(defmipsinsn :trunc.l.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001001 0 0)) :tofpr-paramfpr)
(defmipsinsn :trunc.l.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001001 0 0)) :tofpr-paramfpr)
(defmipsinsn :ceil.l.s  nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001010 0 0)) :tofpr-paramfpr)
(defmipsinsn :ceil.l.d  nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001010 0 0)) :tofpr-paramfpr)
(defmipsinsn :floor.l.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001011 0 0)) :tofpr-paramfpr)
(defmipsinsn :floor.l.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001011 0 0)) :tofpr-paramfpr)
(defmipsinsn :round.w.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001100 0 0)) :tofpr-paramfpr)
(defmipsinsn :round.w.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001100 0 0)) :tofpr-paramfpr)
(defmipsinsn :trunc.w.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001101 0 0)) :tofpr-paramfpr)
(defmipsinsn :trunc.w.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001101 0 0)) :tofpr-paramfpr)
(defmipsinsn :ceil.w.s  nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001110 0 0)) :tofpr-paramfpr)
(defmipsinsn :ceil.w.d  nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001110 0 0)) :tofpr-paramfpr)
(defmipsinsn :floor.w.s nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b001111 0 0)) :tofpr-paramfpr)
(defmipsinsn :floor.w.d nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b001111 0 0)) :tofpr-paramfpr)

(defmipsinsn :movf.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010001 16 #x1) (0 0 0)) :tofpr-fromfpr-c1cond)
(defmipsinsn :movt.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010001 16 #x1) (1 0 0)) :tofpr-fromfpr-c1cond)
(defmipsinsn :movf.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010001 16 #x1) (0 0 0)) :tofpr-fromfpr-c1cond)
(defmipsinsn :movt.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010001 16 #x1) (1 0 0)) :tofpr-fromfpr-c1cond)

(defmipsinsn :movz.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010010 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :movz.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010010 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :movn.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010011 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :movn.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010011 0 0)) :tofpr-paramfpr-fromfpr)
(defmipsinsn :recip.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010101 0 0)) :tofpr-paramfpr)
(defmipsinsn :recip.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010101 0 0)) :tofpr-paramfpr)
(defmipsinsn :rsqrt.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b010111 0 0)) :tofpr-paramfpr)
(defmipsinsn :rsqrt.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b010111 0 0)) :tofpr-paramfpr)

(defmipsinsn :cvt.s.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b100000 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.s.w   nil ((#b010001 21 #x1f) (#b10100 0 #x3f) (#b100000 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.s.l   nil ((#b010001 21 #x1f) (#b10101 0 #x3f) (#b100000 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.d.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b100001 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.d.w   nil ((#b010001 21 #x1f) (#b10100 0 #x3f) (#b100001 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.d.l   nil ((#b010001 21 #x1f) (#b10101 0 #x3f) (#b100001 0 0)) :tofpr-paramfpr)

(defmipsinsn :cvt.w.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b100100 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.w.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b100100 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.l.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b100101 0 0)) :tofpr-paramfpr)
(defmipsinsn :cvt.l.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b100101 0 0)) :tofpr-paramfpr)

(defmipsinsn :c.f.s     nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110000 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.f.d     nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110000 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.un.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110001 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.un.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110001 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.eq.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110010 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.eq.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110010 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ueq.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110011 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ueq.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110011 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.olt.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110100 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.olt.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110100 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ult.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110101 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ult.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110101 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ole.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110110 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ole.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110110 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ule.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b110111 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ule.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b110111 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.sf.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111000 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.sf.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111000 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.seq.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111010 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.seq.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111010 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ngl.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111011 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ngl.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111011 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.lt.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111100 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.lt.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111100 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.nge.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111101 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.nge.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111101 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.le.s    nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111110 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.le.d    nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111110 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ngt.s   nil ((#b010001 21 #x1f) (#b10000 0 #x3f) (#b111111 0 0)) :c1cond-fromfpr-fromfpr)
(defmipsinsn :c.ngt.d   nil ((#b010001 21 #x1f) (#b10001 0 #x3f) (#b111111 0 0)) :c1cond-fromfpr-fromfpr)

(defmipsinsn :mfc2      nil ((#b010010 21 #x1f) (#b00000 0 0) (#b111111 0 0)) :fromgpr-cpsel2)
(defmipsinsn :cfc2      nil ((#b010010 21 #x1f) (#b00010 0 0) (#b111111 0 0)) :fromgpr-cpsel2)
(defmipsinsn :mtc2      nil ((#b010010 21 #x1f) (#b00100 0 0) (#b111111 0 0)) :togpr-cpsel2)
(defmipsinsn :ctc2      nil ((#b010010 21 #x1f) (#b00110 0 0) (#b111111 0 0)) :togpr-cpsel2)
(defmipsinsn :bc2f      nil ((#b010010 21 #x1f) (#b01000 16 #x1f) (#b00000 0 0)) :im16)
(defmipsinsn :bc2t      nil ((#b010010 21 #x1f) (#b01000 16 #x1f) (#b00001 0 0)) :im16)
(defmipsinsn :bc2fl     nil ((#b010010 21 #x1f) (#b01000 16 #x1f) (#b00010 0 0)) :im16)
(defmipsinsn :bc2tl     nil ((#b010010 21 #x1f) (#b01000 16 #x1f) (#b00011 0 0)) :im16)

(defmipsinsn :beql    (:ricp im3bd16) ((#b010100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :beqzl   (:ricp im2bd16) ((#b010100 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bnel    (:ricp im3bd16) ((#b010101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bnezl   (:ricp im2bd16) ((#b010101 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :blezl   (:ricp im2bd16) ((#b010110 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bgtzl   (:ricp im2bd16) ((#b010111 16 #x1f) (#b00000 0 0)) :testgpr-im16off)

(defmipsinsn :daddi   nil ((#b011000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :daddiu  nil ((#b011001 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :ldl     nil ((#b011010 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :ldr     nil ((#b011011 0 0)) :togpr-im16off-basegpr)

;;; These four are R4600, according to See MIPS Run.
;; (defmipsinsn :mad     nil ((#b011100 0 #x1f) (#b00000 11 #xf) (0 0 0)) ) ; a variant
(defmipsinsn :mad     nil ((#b011100 0 #x1f) (#b00000 0 0)) :xgpr-ygpr) ; mutates hilo
(defmipsinsn :madu    nil ((#b011100 0 #x1f) (#b00001 0 0)) :xgpr-ygpr) ; mutates hilo
(defmipsinsn :mul     nil ((#b011100 0 #x1f) (#b00010 0 0)) :togpr-xgpr-ygpr)

(defmipsinsn :lb      nil ((#b100000 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lh      nil ((#b100001 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lwl     nil ((#b100010 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lw      nil ((#b100011 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lbu     nil ((#b100100 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lhu     nil ((#b100101 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lwr     nil ((#b100110 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :lwu     nil ((#b100111 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :sb      nil ((#b101000 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :sh      nil ((#b101001 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :swl     nil ((#b101010 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :sw      nil ((#b101011 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :sdl     nil ((#b101100 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :sdr     nil ((#b101101 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :swr     nil ((#b101110 0 0)) :fromgpr-im16off-basegpr)

(defmipsinsn :cache   nil ((#b101111 0 0)) :cacheop-im16off-basegpr)

(defmipsinsn :ll      nil ((#b110000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :l.s     nil ((#b110001 0 0)) :tofpr-fromgpr-im16parm)

(defmipsinsn :pref    nil ((#b110011 0 0)) :prefop-im16off-basegpr)

(defmipsinsn :lld     nil ((#b110100 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :l.d     nil ((#b110101 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :ld      nil ((#b110111 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :sc      nil ((#b111000 0 0)) :fromgpr-fromgpr-im16parm)
(defmipsinsn :s.s     nil ((#b111001 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :swc2    nil ((#b111010 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :swc3    nil ((#b111011 0 0)) :fromgpr-im16off-basegpr)

(defmipsinsn :scd     nil ((#b111100 0 0)) :fromfpr-fromgpr-im16parm)
(defmipsinsn :s.d     nil ((#b111101 0 0)) :fromfpr-fromgpr-im16parm)
(defmipsinsn :sdc2    nil ((#b111110 0 0)) :fromfpr-fromgpr-im16parm)
(defmipsinsn :sd      nil ((#b111111 0 0)) :fromfpr-fromgpr-im16parm)

(defvar *tlb-raw* #(1075445760 660209665 861536271 1083834368 1008435290 1075462144 2407219208
                    1758594 1757312 58382369 2407202816 1075453952 1757378 861552632 58382369
                    2407137280 2407202820 1757570 1083838464 1825154 1083906048 0 0 1107296258 0 0
                    1107296280 0))

(defvar *tlb-decoded* #((:MFC0 :kt0 :INDEX) (:ADDIU :kt0 :kt0 1) (:ANDI :kt0 :kt0 15)
                        (:MTC0 :kt0 :INDEX) (:LUI :kt1 32858) (:MFC0 :kt0 :BADVADDR)
                        (:LW :kt1 16392 :kt1) (:SRL :kt0 :kt0 22) (:SLL :kt0 :kt0 2)
                        (:ADDU :kt1 :kt1 :kt0) (:LW :kt1 0 :kt1) (:MFC0 :kt0 :CONTEXT)
                        (:SRL :kt0 :kt0 3) (:ANDI :kt0 :kt0 16376) (:ADDU :kt1 :kt1 :kt0)
                        (:LW :kt0 0 :kt1) (:LW :kt1 4 :kt1) (:SRL :kt0 :kt0 6) (:MTC0 :kt0 :ENTRYLO0)
                        (:SRL :kt1 :kt1 6) (:MTC0 :kt1 :ENTRYLO1) (:NOP) (:NOP) (:TLBWI) (:NOP) (:NOP)
                        (:ERET) (:NOP)))

(deftest :assembly mips-assemble () (null &key (input *tlb-decoded*) (expected *tlb-raw*))
  (declare (ignore null))
  (let ((actual (map 'simple-vector (curry #'encode-insn *mips-isa*) input)))
    (expect-value expected actual :test #'equalp)))

(deftest :assembly mips-disassemble () (null &key (input *tlb-raw*) (expected *tlb-decoded*))
  (declare (ignore null))
  (let ((actual (map 'simple-vector (curry #'decode-insn *mips-isa*) input)))
    (expect-value expected actual :test #'equalp)))