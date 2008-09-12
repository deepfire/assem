;;
;;  Copyright (C) 2007  Samium Gromoff
;;
;; This piece of code is licenced under the terms of the Lesser GNU Public Licence.
;;
;; See:
;;   http://www.gnu.org/licenses/lgpl-3.0.txt
;;

(defpackage mips-assembly
  (:nicknames :asm-mips) 
  (:use :common-lisp :alexandria :assembly :custom-harness)
  (:export
   #:*mips-isa*
   #:gpr #:cpsel #:encode-mips-insn #:decode-mips-insn))

(in-package :mips-assembly)

(deftype im26 () '(unsigned-byte 26))
(deftype im20 () '(unsigned-byte 20))
(deftype im16 () '(unsigned-byte 16))
(deftype im5 () '(unsigned-byte 5))
(deftype mips-insn-param-type () '(member im26 im20 im16 im5 gpr cpsel))
(deftype mips-insn-param-offt-type () '(member 21 16 11 6 0))

(deftype gpr () '(or (unsigned-byte 5)
		  (member
		   :r0 :r1 :r2 :r3 :r4 :r5 :r6 :r7 :r8 :r9
		   :r10 :r11 :r12 :r13 :r14 :r15 :r16 :r17 :r18 :r19
		   :r20 :r21 :r22 :r23 :r24 :r25 :r26 :r27 :r28 :r29
		   :r30 :r31)))

(defparameter *gpr* '((:r0 . 0) (:r1 . 1) (:r2 . 2) (:r3 . 3) (:r4 . 4)
		      (:r5 . 5) (:r6 . 6) (:r7 . 7) (:r8 . 8) (:r9 . 9)
		      (:r10 . 10) (:r11 . 11) (:r12 . 12) (:r13 . 13) (:r14 . 14)
		      (:r15 . 15) (:r16 . 16) (:r17 . 17) (:r18 . 18) (:r19 . 19)
		      (:r20 . 20) (:r21 . 21) (:r22 . 22) (:r23 . 23) (:r24 . 24)
		      (:r25 . 25) (:r26 . 26) (:r27 . 27) (:r28 . 28) (:r29 . 29)
		      (:r30 . 30) (:r31 . 31)))

(deftype cpsel () '(or (unsigned-byte 5)
		    (member
		     :prid :status :cause :epc :badvaddr
		     :index :random :entrylo0 :entrylo1 :entryhi :context :pagemask :wired
		     :count :compare :config :watchlo :watchhi
		     :cacheerr :ecc :errorepc :taglo :taghi)))


(defparameter *cpsel* '((:prid . 15) (:status . 12) (:cause . 13) (:epc . 14) (:badvaddr . 8)
			(:index . 0) (:random . 1) (:entrylo0 . 2) (:entrylo1 . 3)
			(:entryhi . 10) (:context . 4) (:pagemask . 5) (:wired . 6)
			(:count . 9) (:compare . 11) (:config . 16) (:watchlo . 18)
			(:watchhi . 19) (:cacheerr . 27) (:ecc . 26) (:errorepc . 30)
			(:taglo . 28) (:taghi . 29) (:lladdr . 17) (:debugepc . 24) (:perfcnt . 25) (:desave . 31))
  "cp0 registers are in see-mips-run order")

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
    ((im26 im16 im5) val)
    (gpr (if (integerp val) val (cdr (assoc val *gpr*))))
    (cpsel (if (integerp val) val (cdr (assoc val *cpsel*))))))

(defmethod decode-insn-param ((isa mips-isa) val type)
  (declare (ignore isa))
  (case type
    (im26 (logand val #x3ffffff))
    (im16 (logand val #xffff))
    (im5 (logand val #x1f))
    (gpr (car (rassoc (logand val #x1f) *gpr*)))
    (cpsel (car (rassoc (logand val #x1f) *cpsel*)))))

(defmacro defmipsparamtype (id spec)
  `(defparamtype *mips-isa* ',id ,spec))

(defmacro defmipsinsn (id branchspec opcode-spec format-name)
  (multiple-value-bind (type dest-fn) (if (atom branchspec) 'insn
                                          (destructuring-bind (type &optional dest-fn) branchspec
                                            (case type
                                              (:cond (values 'cond-branch-insn dest-fn))
                                              (:abs (values 'abs-branch-insn dest-fn))
                                              (:rel (values 'rel-branch-insn dest-fn))
                                              (:ex (values 'exception-insn)))))
    `(progn
       (definsn *mips-isa* ',type ,id ',opcode-spec :format-name ,format-name
                ,@(when dest-fn `(:dest-fn ,dest-fn))))))

(defmacro defmipsformat (id &rest param-spec)
  `(defformat *mips-isa* ,id () ,param-spec))

(defmipsparamtype gpr 5)
(defmipsparamtype cpsel 5)
(defmipsparamtype im5 5)
(defmipsparamtype im16 16)
(defmipsparamtype im20 20)
(defmipsparamtype im26 26)

(defmipsformat :empty)
(defmipsformat :togpr-fromgpr-im5shift     (gpr 11) (gpr 16) (im5 6))
(defmipsformat :togpr-fromgpr-shiftgpr     (gpr 11) (gpr 16) (gpr 21))
(defmipsformat :togpr-xgpr-ygpr            (gpr 11) (gpr 21) (gpr 16))
(defmipsformat :togpr-fromgpr-testgpr      (gpr 11) (gpr 21) (gpr 16))
(defmipsformat :savegpr-addrgpr            (gpr 11) (gpr 21))
(defmipsformat :to-gpr                     (gpr 11))
(defmipsformat :from-gpr                   (gpr 21))
(defmipsformat :xgpr-ygpr                  (gpr 21) (gpr 16))
(defmipsformat :im20                       (im20 6))
(defmipsformat :im26                       (im26 0))
(defmipsformat :togpr-fromgpr-im16parm     (gpr 16) (gpr 21) (im16 0))
(defmipsformat :testgpr-basegpr-im16off    (gpr 21) (gpr 16) (im16 0))
(defmipsformat :testgpr-im16off            (gpr 21) (im16 0))
(defmipsformat :togpr-im16                 (gpr 16) (im16 0))
(defmipsformat :from/togpr-cpsel           (gpr 16) (cpsel 11))
(defmipsformat :from/togpr-im16off-basegpr (gpr 16) (im16 0) (gpr 21))

(defmipsinsn :sll     nil ((#b000000 0 #x3f) (#b000000 0 0)) :togpr-fromgpr-im5shift)
                          
(defmipsinsn :nop     nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00000 0 0)) :empty)
(defmipsinsn :ssnop   nil ((#b000000 0 #x3f) (#b000000 11 #x1f) (#b00000 16 #x1f) (#b00000 6 #x1f) (#b00001 0 0)) :empty)
                          
(defmipsinsn :srl     nil ((#b000000 0 #x3f) (#b000010 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sra     nil ((#b000000 0 #x3f) (#b000011 0 0)) :togpr-fromgpr-im5shift)
(defmipsinsn :sllv    nil ((#b000000 0 #x3f) (#b000100 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srlv    nil ((#b000000 0 #x3f) (#b000110 0 0)) :togpr-fromgpr-shiftgpr)
(defmipsinsn :srav    nil ((#b000000 0 #x3f) (#b000111 0 0)) :togpr-fromgpr-shiftgpr)
                             
(defmipsinsn :jr      (:abs) ((#b000000 0 #x3f) (#b001000 0 0)) :from-gpr)
(defmipsinsn :jalr    (:abs) ((#b000000 0 #x3f) (#b001001 0 0)) :savegpr-addrgpr)
(defmipsinsn :movz    nil ((#b000000 0 #x3f) (#b001010 0 0)) :togpr-fromgpr-testgpr)
(defmipsinsn :movn    nil ((#b000000 0 #x3f) (#b001011 0 0)) :togpr-fromgpr-testgpr)

(defmipsinsn :syscall (:ex)  ((#b000000 0 #x3f) (#b001100 0 0)) :im20)
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

(defmipsinsn :j       (:abs) ((#b000010 0 0)) :im26)
(defmipsinsn :jal     (:abs) ((#b000011 0 0)) :im26)

(defmipsinsn :beq     (:rel) ((#b000100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bne     (:rel) ((#b000101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :blez    (:rel) ((#b000110 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bgtz    (:rel) ((#b000111 0 0)) :testgpr-basegpr-im16off)

(defmipsinsn :addi    nil ((#b001000 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :addiu   nil ((#b001001 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :li      nil ((#b001001 21 #x1f) (#b00000 0 0)) :togpr-im16)
(defmipsinsn :slti    nil ((#b001010 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :sltiu   nil ((#b001011 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :andi    nil ((#b001100 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :ori     nil ((#b001101 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :xori    nil ((#b001110 0 0)) :togpr-fromgpr-im16parm)
(defmipsinsn :lui     nil ((#b001111 0 0)) :togpr-im16)

(defmipsinsn :mfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0000 0 0)) :from/togpr-cpsel)
(defmipsinsn :dmfc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0001 0 0)) :from/togpr-cpsel)
(defmipsinsn :cfc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0010 0 0)) :from/togpr-cpsel)
(defmipsinsn :mtc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0100 0 0)) :from/togpr-cpsel)
(defmipsinsn :dmtc0   nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0101 0 0)) :from/togpr-cpsel)
(defmipsinsn :ctc0    nil ((#b010000 25 #x1) (#b0 21 #xf) (#b0110 0 0)) :from/togpr-cpsel)

(defmipsinsn :tlbr    nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000001 0 0)) :empty)
(defmipsinsn :tlbwi   nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000010 0 0)) :empty)
(defmipsinsn :tlbwr   nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b000110 0 0)) :empty)
(defmipsinsn :tlbp    nil ((#b010000 21 #x1f) (#x10 0 #x3f) (#b001000 0 0)) :empty)
(defmipsinsn :rfe     (:ex)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b010000 0 0)) :empty)
(defmipsinsn :eret    (:ex)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b011000 0 0)) :empty)
(defmipsinsn :dret    (:ex)  ((#b010000 21 #x1f) (#x10 0 #x3f) (#b011111 0 0)) :empty)

(defmipsinsn :beql    (:rel) ((#b010100 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :beqzl   (:rel) ((#b010100 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bnel    (:rel) ((#b010101 0 0)) :testgpr-basegpr-im16off)
(defmipsinsn :bnezl   (:rel) ((#b010101 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :blezl   (:rel) ((#b010110 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
(defmipsinsn :bgtzl   (:rel) ((#b010111 16 #x1f) (#b00000 0 0)) :testgpr-im16off)
                      
(defmipsinsn :lb      nil ((#b100000 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lh      nil ((#b100001 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lwl     nil ((#b100010 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lw      nil ((#b100011 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lbu     nil ((#b100100 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lhu     nil ((#b100101 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lwr     nil ((#b100110 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :lwu     nil ((#b100111 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :sb      nil ((#b101000 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :sh      nil ((#b101001 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :swl     nil ((#b101010 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :sw      nil ((#b101011 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :sdl     nil ((#b101100 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :sdr     nil ((#b101101 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :swr     nil ((#b101110 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :swc1    nil ((#b111001 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :swc2    nil ((#b111010 0 0)) :from/togpr-im16off-basegpr)
(defmipsinsn :swc3    nil ((#b111011 0 0)) :from/togpr-im16off-basegpr)

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