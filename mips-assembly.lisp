;;
;;  Copyright (C) 2007  Samium Gromoff
;;
;; This piece of code is licenced under the terms of the Lesser GNU Public Licence.
;;
;; See:
;;   http://www.gnu.org/licenses/lgpl-3.0.txt
;;

(in-package :mips-assembly)

(deftype im26 () '(unsigned-byte 26))
(deftype syscode () '(unsigned-byte 20))
(deftype brkcode () '(unsigned-byte 10))
(deftype im16 () '(unsigned-byte 16))
(deftype im5 () '(unsigned-byte 5))
(deftype mips-insn-param-type () '(member im26 syscode brkcode im16 im5 c1cond gpr cpsel fpr cacheop prefop))
(deftype mips-insn-param-offt-type () '(member 21 16 11 6 0))

(defmacro define-enumerated-operand-type (name bit-width (&rest set))
  `(progn
     (deftype ,name () '(or (unsigned-byte ,bit-width) (member ,@(mapcar #'car set))))
     (defparameter ,(format-symbol t "*~A*" name) ',set)))

(define-enumerated-operand-type gpr 5
  ((:r0 . 0)   (:r1 . 1)   (:r2 . 2)   (:r3 . 3)   (:r4 . 4)
   (:r5 . 5)   (:r6 . 6)   (:r7 . 7)   (:r8 . 8)   (:r9 . 9)
   (:r10 . 10) (:r11 . 11) (:r12 . 12) (:r13 . 13) (:r14 . 14)
   (:r15 . 15) (:r16 . 16) (:r17 . 17) (:r18 . 18) (:r19 . 19)
   (:r20 . 20) (:r21 . 21) (:r22 . 22) (:r23 . 23) (:r24 . 24)
   (:r25 . 25) (:r26 . 26) (:r27 . 27) (:r28 . 28) (:r29 . 29)
   (:r30 . 30) (:r31 . 31)))

(define-enumerated-operand-type fpr 5
  ((:f0 . 0)   (:f1 . 1)   (:f2 . 2)   (:f3 . 3)   (:f4 . 4)
   (:f5 . 5)   (:f6 . 6)   (:f7 . 7)   (:f8 . 8)   (:f9 . 9)
   (:f10 . 10) (:f11 . 11) (:f12 . 12) (:f13 . 13) (:f14 . 14)
   (:f15 . 15) (:f16 . 16) (:f17 . 17) (:f18 . 18) (:f19 . 19)
   (:f20 . 20) (:f21 . 21) (:f22 . 22) (:f23 . 23) (:f24 . 24)
   (:f25 . 25) (:f26 . 26) (:f27 . 27) (:f28 . 28) (:f29 . 29)
   (:f30 . 30) (:f31 . 31)))

(define-enumerated-operand-type cpsel 5
  ((:prid . 15) (:status . 12) (:cause . 13) (:epc . 14) (:badvaddr . 8)
   (:index . 0) (:random . 1) (:entrylo0 . 2) (:entrylo1 . 3)
   (:entryhi . 10) (:context . 4) (:pagemask . 5) (:wired . 6)
   (:count . 9) (:compare . 11) (:config . 16) (:watchlo . 18)
   (:watchhi . 19) (:cacheerr . 27) (:ecc . 26) (:errorepc . 30)
   (:taglo . 28) (:taghi . 29) (:lladdr . 17) (:debugepc . 24) (:perfcnt . 25) (:desave . 31)))

(define-enumerated-operand-type cacheop 5
  ((:index-inv-i . #x0) (:index-wbinv-d . #x1) (:index-inv-si . #x2) (:index-wbinv-sd . #x3)
   (:index-load-tag-i . #x4) (:index-load-tag-d . #x5) (:index-load-tag-si . #x6) (:index-load-tag-sd . #x7)
   (:index-store-tag-i . #x8) (:index-store-tag-d . #x9) (:index-store-tag-si . #xa) (:index-store-tag-sd . #xb)
   (:index-dirty-exc-d . #xd) (:index-dirty-exc-sd . #xf)
   (:hit-inv-i . #x0) (:hit-inv-d . #x1) (:hit-inv-si . #x2) (:hit-inv-sd . #x3)
   (:fill-i . #x14)
   (:index-wbinv-d . #x15) (:index-wbinv-sd . #x17)
   (:index-wb-i . #x18) (:index-wb-d . #x19) (:index-wb-sd . #x1b)
   (:index-set-virt-si . #x1e) (:index-set-virt-sd . #x1f)))

(define-enumerated-operand-type prefop 5
  ())

(defclass mips-isa (isa)
  ()
  (:default-initargs
   :delay-slots 1
   :insn-defines-format-p t
   :root-shift 26 :root-mask #x3f))

(defparameter *mips-isa* (make-instance 'mips-isa))

(defmethod validate-insn-parameter-spec ((isa mips-isa) mnemonics params)
  (assert (<= (length params) 3))
  (dolist (param params)
    (unless (typep (car param) 'mips-insn-param-type)
      (error "in insn definition for ~S: the car is not of type MIPS-INSN-PARAM-TYPE" mnemonics))
    (unless (typep (cadr param) 'mips-insn-param-offt-type)
      (error "in insn definition for ~S: the cadr does not designate a usable parameter offset" mnemonics))))

(defun encode-mips-insn (id &rest params)
  (apply #'encode-insn *mips-isa* id params))

(defun decode-mips-insn (opcode)
  (funcall #'decode-insn *mips-isa* opcode))

(defmethod encode-insn-param ((isa mips-isa) val type)
  (declare (ignore isa))
  (ecase type
    ((im26 im16 im5 c1cond) val)
    (gpr (if (integerp val) val (cdr (assoc val *gpr*))))
    (fpr (if (integerp val) val (cdr (assoc val *fpr*))))
    (cpsel (if (integerp val) val (cdr (assoc val *cpsel*))))
    (cacheop (if (integerp val) val (cdr (assoc val *cacheop*))))
    (prefop (if (integerp val) val (cdr (assoc val *prefop*))))))

(defmethod decode-insn-param ((isa mips-isa) val type)
  (declare (ignore isa))
  (case type
    (im26 (logand val #x3ffffff))
    (im16 (logand val #xffff))
    (im5 (logand val #x1f))
    (c1cond (logand val #x7))
    (gpr (car (rassoc (logand val #x1f) *gpr*)))
    (fpr (car (rassoc (logand val #x1f) *fpr*)))
    (cpsel (car (rassoc (logand val #x1f) *cpsel*)))
    (cacheop (car (rassoc (logand val #x1f) *cacheop*)))
    (prefop (car (rassoc (logand val #x1f) *prefop*)))))

(defmacro defmipsparamtype (id spec)
  `(defparamtype *mips-isa* ',id ,spec))

(defclass rel-cond-pure (rel-branch-insn cond-branch-mixin) ())
(defclass rel-cond-depcont (rel-branch-insn cond-branch-mixin dep-continue-mixin) ())
(defclass rel-uncond-depcont (rel-branch-insn uncond-branch-mixin dep-continue-mixin) ())
(defclass rel-uncond-noncont (rel-branch-insn uncond-branch-mixin noncontinue-mixin) ())
(defclass abs-uncond-depcont (abs-branch-insn uncond-branch-mixin dep-continue-mixin) ())
(defclass abs-uncond-noncont (abs-branch-insn uncond-branch-mixin noncontinue-mixin) ())
(defclass indef-cond-depcont (indef-branch-insn cond-branch-mixin dep-continue-mixin) ())
(defclass indef-uncond-depcont (indef-branch-insn uncond-branch-mixin dep-continue-mixin) ())
(defclass indef-uncond-noncont (indef-branch-insn uncond-branch-mixin noncontinue-mixin) ())

(defmacro defmipsinsn (id branchspec opcode-spec format-name)
  (multiple-value-bind (type dest-fn) (if (atom branchspec) 'nonbranch-insn
                                          (destructuring-bind (type &optional dest-fn) branchspec
                                            (values (case type
                                                      (:rcp 'rel-cond-pure)
                                                      (:rcd 'rel-cond-depcont)
                                                      (:rud 'rel-uncond-depcont)
                                                      (:run 'rel-uncond-noncont)
                                                      (:aud 'abs-uncond-depcont)
                                                      (:aun 'abs-uncond-noncont)
                                                      (:icd 'indef-cond-depcont)
                                                      (:iud 'indef-uncond-depcont)
                                                      (:iun 'indef-uncond-noncont))
                                                    dest-fn)))
    `(progn
       (definsn *mips-isa* ',type ,id ',opcode-spec :format-name ,format-name
                ,@(when dest-fn `(:destination-fn (function ,dest-fn)))))))

(defmacro defmipsformat (id &rest param-spec)
  `(defformat *mips-isa* ,id () ,param-spec))

(defmipsparamtype gpr 5)
(defmipsparamtype fpr 5)
(defmipsparamtype cpsel 5)
(defmipsparamtype cacheop 5)
(defmipsparamtype prefop 5)
(defmipsparamtype c1cond 3)
(defmipsparamtype im5 5)
(defmipsparamtype im16 16)
(defmipsparamtype brkcode 10)
(defmipsparamtype syscode 20)
(defmipsparamtype im26 26)

(defmipsformat :empty)
(defmipsformat :togpr-fromgpr-im5shift     (gpr 11 :dst) (gpr 16 :src) (im5 6))
(defmipsformat :togpr-fromgpr-shiftgpr     (gpr 11 :dst) (gpr 16 :src) (gpr 21 :src))
(defmipsformat :tofpr-paramfpr-fromfpr     (gpr 11 :dst) (gpr 16 :src) (gpr 21 :src))
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
(defmipsformat :tofpr-fromgpr-im16parm     (fpr 16 :dst) (gpr 21 :src) (im16 0))
(defmipsformat :testgpr-basegpr-im16off    (gpr 21 :src) (gpr 16 :src) (im16 0))
(defmipsformat :testgpr-im16off            (gpr 21 :src) (im16 0))
(defmipsformat :testgpr-im16               (gpr 21 :src) (im16 0))
(defmipsformat :togpr-im16                 (gpr 16 :dst) (im16 0))
(defmipsformat :fromgpr-cpsel              (gpr 16 :src) (cpsel 11 :dst))
(defmipsformat :fromgpr-tofpr              (gpr 16 :src) (fpr 11 :dst))
(defmipsformat :fromgpr-im16off-basegpr    (gpr 16 :src) (im16 0) (gpr 21 :src))
(defmipsformat :togpr-cpsel                (gpr 16 :dst) (cpsel 11 :src))
(defmipsformat :togpr-fromfpr              (gpr 16 :dst) (fpr 11 :src))
(defmipsformat :togpr-im16off-basegpr      (gpr 16 :dst) (im16 0) (gpr 21 :src))
(defmipsformat :cacheop-im16off-basegpr    (cacheop 16) (im16 0) (gpr 21 :src))
(defmipsformat :prefop-im16off-basegpr     (prefop 16) (im16 0) (gpr 21 :src))
(defmipsformat :c1cond-im16                (c1cond 18) (im16 0))
(defmipsformat :c1cond-fromfpr-fromfpr       (c1cond 8) (fpr 11 :src) (fpr 16 :src))
(defmipsformat :tofpr-fromfpr-c1cond       (fpr 6 :dst) (fpr 11 :src) (c1cond 18))

(defmipsinsn :sll     nil ((#b000000 0 #x3f) (#b000000 0 0)) :togpr-fromgpr-im5shift)
                          
(defmipsinsn :nop     nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00000 0 0)) :empty)
(defmipsinsn :ssnop   nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00001 0 0)) :empty)
                          
(defmipsinsn :srl     nil ((#b000000 0 #x3f) (#b000010 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sra     nil ((#b000000 0 #x3f) (#b000011 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sllv    nil ((#b000000 0 #x3f) (#b000100 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srlv    nil ((#b000000 0 #x3f) (#b000110 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srav    nil ((#b000000 0 #x3f) (#b000111 0 0)) :togpr-fromgpr-shiftgpr)

(defmipsinsn :jr      (:aun) ((#b000000 0 #x3f) (#b001000 0 0)) :from-gpr)
(defmipsinsn :jalr    (:aud) ((#b000000 0 #x3f) (#b001001 0 0)) :savegpr-addrgpr)
(defmipsinsn :movz    nil ((#b000000 0 #x3f) (#b001010 0 0)) :togpr-fromgpr-testgpr)
(defmipsinsn :movn    nil ((#b000000 0 #x3f) (#b001011 0 0)) :togpr-fromgpr-testgpr)

(defmipsinsn :syscall (:iud) ((#b000000 0 #x3f) (#b001100 0 0)) :syscode)
(defmipsinsn :break   (:iud) ((#b000000 0 #x3f) (#b001101 0 0)) :brkcode)
(defmipsinsn :sync    nil ((#b000000 0 #x3f) (#b001111 0 0)) :empty)

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

(defparameter *branch-shift* 1)

(defun im2bd16 (c1cond imoff)
  (declare (ignore c1cond))
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :bltz    (:rcp im2bd16) ((#b000001 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bgez    (:rcp im2bd16) ((#b000001 16 #x1f) (#b00001 0 0)) :testgpr-im16off)
(defmipsinsn :bltzl   (:rcp im2bd16) ((#b000001 16 #x1f) (#b00010 0 0)) :testgpr-im16off)
(defmipsinsn :bgezl   (:rcp im2bd16) ((#b000001 16 #x1f) (#b00011 0 0)) :testgpr-im16off)
(defmipsinsn :tgei    (:icd) ((#b000001 16 #x1f) (#b01000 0 0)) :testgpr-im16)
(defmipsinsn :tgeiu   (:icd) ((#b000001 16 #x1f) (#b01001 0 0)) :testgpr-im16)
(defmipsinsn :tlti    (:icd) ((#b000001 16 #x1f) (#b01010 0 0)) :testgpr-im16)
(defmipsinsn :tltiu   (:icd) ((#b000001 16 #x1f) (#b01011 0 0)) :testgpr-im16)
(defmipsinsn :teqi    (:icd) ((#b000001 16 #x1f) (#b01100 0 0)) :testgpr-im16)
(defmipsinsn :tnei    (:icd) ((#b000001 16 #x1f) (#b01110 0 0)) :testgpr-im16)
(defmipsinsn :bltzal  (:rcd im2bd16) ((#b000001 16 #x1f) (#b10000 0 0)) :testgpr-im16off)
(defmipsinsn :bgezal  (:rcd im2bd16) ((#b000001 16 #x1f) (#b10001 0 0)) :testgpr-im16off)
(defmipsinsn :bltzall (:rcd im2bd16) ((#b000001 16 #x1f) (#b10010 0 0)) :testgpr-im16off)
(defmipsinsn :bgezall (:rcd im2bd16) ((#b000001 16 #x1f) (#b10011 0 0)) :testgpr-im16off)

(defun im1bd26 (imoff)
  (+ *branch-shift* (if (logbitp 25 imoff)
          (- imoff (ash 1 26))
          imoff)))

(defmipsinsn :j       (:run im1bd26) ((#b000010 0 0)) :im26)
(defmipsinsn :jal     (:rud im1bd26) ((#b000011 0 0)) :im26)

(defun im3bd16 (gpr1 gpr2 imoff)
  (declare (ignore gpr1 gpr2))
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :beq     (:rcp im3bd16) ((#b000100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bne     (:rcp im3bd16) ((#b000101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :blez    (:rcp im3bd16) ((#b000110 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bgtz    (:rcp im3bd16) ((#b000111 0 0)) :testgpr-basegpr-im16off)

(defmipsinsn :addi    nil ((#b001000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :addiu   nil ((#b001001 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :li      nil ((#b001001 21 #x1f) (#b00000 0 0)) :togpr-im16)
(defmipsinsn :slti    nil ((#b001010 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :sltiu   nil ((#b001011 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :andi    nil ((#b001100 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :ori     nil ((#b001101 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :xori    nil ((#b001110 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :lui     nil ((#b001111 0 0)) :togpr-im16)

(defmipsinsn :mfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0000 0 0)) :fromgpr-cpsel)
(defmipsinsn :dmfc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0001 0 0)) :fromgpr-cpsel)
(defmipsinsn :cfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0010 0 0)) :fromgpr-cpsel)
(defmipsinsn :mtc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0100 0 0)) :togpr-cpsel)
(defmipsinsn :dmtc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0101 0 0)) :togpr-cpsel)
(defmipsinsn :ctc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0110 0 0)) :togpr-cpsel)

(defun im1bd16 (imoff)
  (+ *branch-shift* (if (logbitp 15 imoff)
          (- imoff (ash 1 16))
          imoff)))

(defmipsinsn :bc0f    (:rcp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0000 0 0)) :im16)
(defmipsinsn :bc0t    (:rcp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0001 0 0)) :im16)
(defmipsinsn :bc0f1   (:rcp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0010 0 0)) :im16)
(defmipsinsn :bc0t1   (:rcp im1bd16) ((#b010000 21 #x1) (#x8 16 #x1f) (#b0011 0 0)) :im16)

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

(defmipsinsn :bc1f    (:rcp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b00 0 0)) :c1cond-im16)
(defmipsinsn :bc1t    (:rcp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b01 0 0)) :c1cond-im16)
(defmipsinsn :bc1fl   (:rcp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b10 0 0)) :c1cond-im16)
(defmipsinsn :bc1fl   (:rcp im2bd16) ((#b010001 21 #x1f) (#b01000 16 #x3) (#b11 0 0)) :c1cond-im16)

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

(defmipsinsn :beql    (:rcp im3bd16) ((#b010100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :beqzl   (:rcp im2bd16) ((#b010100 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bnel    (:rcp im3bd16) ((#b010101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bnezl   (:rcp im2bd16) ((#b010101 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :blezl   (:rcp im2bd16) ((#b010110 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bgtzl   (:rcp im2bd16) ((#b010111 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
                      
(defmipsinsn :lb      nil ((#b100000 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lh      nil ((#b100001 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lwl     nil ((#b100010 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lw      nil ((#b100011 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lbu     nil ((#b100100 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lhu     nil ((#b100101 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lwr     nil ((#b100110 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :lwu     nil ((#b100111 0 0)) :fromgpr-im16off-basegpr)
(defmipsinsn :sb      nil ((#b101000 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :sh      nil ((#b101001 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :swl     nil ((#b101010 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :sw      nil ((#b101011 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :sdl     nil ((#b101100 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :sdr     nil ((#b101101 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :swr     nil ((#b101110 0 0)) :togpr-im16off-basegpr)

(defmipsinsn :cache   nil ((#b101111 0 0)) :cacheop-im16off-basegpr)

(defmipsinsn :ll      nil ((#b110000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :l.s     nil ((#b110001 0 0)) :tofpr-fromgpr-im16parm)

(defmipsinsn :pref    nil ((#b110011 0 0)) :prefop-im16off-basegpr)

(defmipsinsn :lld     nil ((#b110100 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :l.d     nil ((#b110101 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :ld      nil ((#b110111 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :sc      nil ((#b111000 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :swc1    nil ((#b111001 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :swc2    nil ((#b111010 0 0)) :togpr-im16off-basegpr)
(defmipsinsn :swc3    nil ((#b111011 0 0)) :togpr-im16off-basegpr)

(defmipsinsn :scd     nil ((#b111100 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :s.d     nil ((#b111101 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :sdc2    nil ((#b111110 0 0)) :tofpr-fromgpr-im16parm)
(defmipsinsn :sd      nil ((#b111111 0 0)) :tofpr-fromgpr-im16parm)

(defvar *tlb-raw* #(1075445760 660209665 861536271 1083834368 1008435290 1075462144 2407219208
                    1758594 1757312 58382369 2407202816 1075453952 1757378 861552632 58382369
                    2407137280 2407202820 1757570 1083838464 1825154 1083906048 0 0 1107296258 0 0
                    1107296280 0))

(defvar *tlb-decoded* #((:MFC0 :R26 :INDEX) (:ADDIU :R26 :R26 1) (:ANDI :R26 :R26 15)
                        (:MTC0 :R26 :INDEX) (:LUI :R27 32858) (:MFC0 :R26 :BADVADDR)
                        (:LW :R27 16392 :R27) (:SRL :R26 :R26 22) (:SLL :R26 :R26 2)
                        (:ADDU :R27 :R27 :R26) (:LW :R27 0 :R27) (:MFC0 :R26 :CONTEXT)
                        (:SRL :R26 :R26 3) (:ANDI :R26 :R26 16376) (:ADDU :R27 :R27 :R26)
                        (:LW :R26 0 :R27) (:LW :R27 4 :R27) (:SRL :R26 :R26 6) (:MTC0 :R26 :ENTRYLO0)
                        (:SRL :R27 :R27 6) (:MTC0 :R27 :ENTRYLO1) (:NOP) (:NOP) (:TLBWI) (:NOP) (:NOP)
                        (:ERET) (:NOP)))

(deftest :assembly mips-assemble (null &key (input *tlb-decoded*) (expected *tlb-raw*))
  (declare (ignore null))
  (let ((actual (map 'simple-vector (curry #'apply (curry #'encode-insn *mips-isa*)) input)))
    (expect-value expected actual :test #'equalp)))

(deftest :assembly mips-disassemble (null &key (input *tlb-raw*) (expected *tlb-decoded*))
  (declare (ignore null))
  (let ((actual (map 'simple-vector (curry #'decode-insn *mips-isa*) input)))
    (expect-value expected actual :test #'equalp)))