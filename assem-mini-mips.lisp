;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEM-MINI; Base: 10 -*-
;;;
;;;  (c) copyright 2006-2009 by
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

(in-package :assem-mini)

(defmacro with-mips-assem ((&rest tags) &body body)
  `(with-assem asm-mips:gpr (,@tags)
     ,@body))

(defmacro with-extentable-mips-segment ((extentable addr) (&rest tags) &body body)
  `(with-extentable-segment (asm-mips:*mips-isa* ,extentable ,addr) asm-mips:gpr (,@tags)
     ,@body))

(defmacro with-mips-gpri ((&rest gprs) &body body)
  `(allocate-let (asm-mips:gpr ,@gprs)
     ,@body))

(defun allocate-mips-gpr (name)
  (pool-allocate 'asm-mips:gpr name))

(defun emit-nops (count)
  (dotimes (i count)
    (emit* :nop)))

(defmacro define-emitter (name lambda-list binding-spec &body body)
  (multiple-value-bind (docstring decls body) (destructure-def-body body)
    (multiple-value-bind (special-decls nonspecial-decls) (unzip (feq 'special) decls :key #'car)
      (destructuring-bind (&optional (optype 'asm-mips:gpr) &rest binding-set) binding-spec
        (emit-defun
         name (mapcar (compose #'car #'ensure-cons) lambda-list)
         `((allocate-let (,optype ,@binding-set) ,@special-decls ,@body))
         :documentation docstring
         :declarations (append nonspecial-decls
                               (iter (for paramspec in lambda-list)
                                     (destructuring-bind (paramname &optional paramwidth) (ensure-cons paramspec)
                                       (when paramwidth
                                         (unless (typep paramwidth '(unsigned-byte 6))
                                           (asm:assembly-error "~@<Error in DEFINE-LET-EMITTER ~A: bad parameter width ~S for parameter ~S.~:@>"
                                                               name paramwidth paramname))
                                         (collect `(type (unsigned-byte ,paramwidth) ,paramname)))))))))))

(define-emitter emit-set-gpr (gpr value) nil
  (etypecase value
    (integer
     (let ((hi (ldb (byte 16 16) value))
           (lo (ldb (byte 16 0) value)))
       ;; The first case also takes care of (ZEROP VALUE)
       (cond ((zerop hi) (emit* :ori gpr :zero lo))
             ((zerop lo) (emit* :lui gpr hi))
             (t          (emit* :lui gpr hi)
                         (emit* :ori gpr gpr lo)))))
    (keyword
     (emit* :or gpr :zero value))))

;;;
;;; Register-based memory stores
;;;
(define-emitter emit-based-store32 ((value 32) basereg (offset 16)) (asm-mips:gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sw :proxy offset basereg))
(define-emitter emit-based-store16 ((value 16) basereg (offset 16)) (asm-mips:gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sh :proxy offset basereg))
(define-emitter emit-based-store8 ((value 8) basereg (offset 16)) (asm-mips:gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sb :proxy offset basereg))

;;;
;;; Absolute memory stores
;;;
(define-emitter emit-store32 ((value 32) address) (asm-mips:gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store32 value :base (logand #xffff address)))
(define-emitter emit-store16 ((value 32) address) (asm-mips:gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store16 value :base (logand #xffff address)))
(define-emitter emit-store8 ((value 32) address) (asm-mips:gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store8 value :base (logand #xffff address)))

;;;
;;; Register-based memory loads
;;;
(define-emitter emit-based-load32 (dstreg (offset 16) basereg) nil
  (emit* :lw dstreg offset basereg))
(define-emitter emit-based-load16 (dstreg (offset 16) basereg) nil
  (emit* :lh dstreg offset basereg))
(define-emitter emit-based-load8 (dstreg (offset 16) basereg) nil
  (emit* :lb dstreg offset basereg))

;;;
;;; Absolute, self-based memory loads
;;;
(define-emitter emit-load32 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load32 dstreg (logand addr #xffff) dstreg))
(define-emitter emit-load16 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load16 dstreg (logand addr #xffff) dstreg))
(define-emitter emit-load8 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load8 dstreg (logand addr #xffff) dstreg))

;;;
;;; Masking
;;;
(define-emitter emit-mask32 (dstreg srcreg (mask 32)) (asm-mips:gpr :mask)
  (emit-set-gpr :masker mask)
  (emit* :and dstreg :mask srcreg))
(define-emitter emit-mask16 (dstreg srcreg (mask 16)) nil
  (emit* :andi dstreg srcreg mask))

;;;
;;; Miscellaneous complex accesses
;;;
(define-emitter emit-set-cp0 (cp0 (value 32)) (asm-mips:gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :nop)
  (emit* :mtc0 :proxy cp0))

(define-emitter emit-set-tlb-entry (i value) nil
  (emit-set-cp0 :index i)
  (emit-set-cp0 :entryhi (first value))
  (emit-set-cp0 :entrylo0 (second value))
  (emit-set-cp0 :entrylo1 (third value))
  (emit* :nop)
  (emit* :tlbwi))

;;;
;;; Jumps
;;;
(define-emitter emit-long-jump ((address 32)) (asm-mips:gpr :proxy)
  (emit-set-gpr :proxy address)
  (emit* :nop)
  (emit* :jr :proxy)
  (emit* :nop))

;;;
;;; Beginnings of cell machinery
;;;
(defun ensure-cell (name val)
  "Should not exist: must be taken care of by LET-alikes."
  (cond
    ;; already a register? rebind lexically.
    ((keywordp val)
     (allocate-lexical-binding 'asm-mips:gpr name)
     (setf (lexical-binding 'asm-mips:gpr name)
           (if (lexical-p 'asm-mips:gpr val)
               (lexical-binding 'asm-mips:gpr val)
               val)))
    ;; no? allocate, bind lexically and set.
    (t
     (let ((cell (allocate-lexically-bound-global 'asm-mips:gpr name)))
       (emit-set-gpr cell val)))))

(defun release-cell (name)
  "Shouldn't exist, likewise."
  (if (lexical-p 'asm-mips:gpr name)
      (undo-lexical-binding 'asm-mips:gpr name)))

(define-emitter emit-based-cell-store32 (value basereg (offset 16)) (asm-mips:gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sw :proxy offset basereg))
    (keyword
     (emit* :sw value offset basereg))))
(define-emitter emit-based-cell-store16 (value basereg (offset 16)) (asm-mips:gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sh :proxy offset basereg))
    (keyword
     (emit* :sh value offset basereg))))
(define-emitter emit-based-cell-store8 (value basereg (offset 16)) (asm-mips:gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sb :proxy offset basereg))
    (keyword
     (emit* :sb value offset basereg))))

;;;
;;; Jumps
;;;
(defun emit-jump (name)
  (emit-ref name (delta) :beq :zero :zero delta))

(defun emit-jump-if-eq (name r1 r2)
  (emit-ref name (delta) :beq r1 r2 delta))

(defun emit-jump-if-ne (name r1 r2)
  (emit-ref name (delta) :bne r1 r2 delta))

;;;
;;; Iteration
;;;
(defmacro emitting-iteration ((iterations &optional exit-tag (counter-reg :counter)) &body body)
  (once-only (iterations)
    `(progn
       (ensure-cell ,counter-reg ,iterations)
       (with-tags (:loop-begin ,@(when exit-tag `(,exit-tag)))
         (emit-tag :loop-begin)
         ,@body
         (emit-ref :loop-begin (delta) :bne ,counter-reg :zero delta)
         (emit* :addiu ,counter-reg ,counter-reg #xffff)
         ,@(when exit-tag
                 `((emit-tag ,exit-tag))))
       (release-cell ,counter-reg))))

;;;
;;; Function call machinery
;;;
(defparameter *initial-stack-top* nil)

(defmacro with-function-calls (initial-stack-top &body body)
  `(let (,@(when initial-stack-top `((*initial-stack-top* ,initial-stack-top))))
     ,@(when initial-stack-top `((declare (special *initial-stack-top*))))
     (allocate-let (asm-mips:gpr :stack-top :arg0-ret :arg1 :arg2)
       (declare (special :stack-top))
       ,@(when initial-stack-top `((emit-set-gpr :stack-top *initial-stack-top*)))
       ,@body)))

(defmacro with-function-definitions-and-calls ((&optional initial-stack-top) &body body)
  `(with-function-calls ,initial-stack-top
     (progn-1
       ,@body
       (backpatch-outstanding-global-tag-references))))

(defun emit-stack-push (value)
  (emit-based-cell-store32 value :stack-top 0)
  (emit* :addiu :stack-top :stack-top #xfffc))

(defun emit-stack-pop ()
  (emit* :addiu :stack-top :stack-top #x4))

(defun emit-near-function-call (name &rest args)
  (iter (for arg in args)
        (for argreg in '(:arg0-ret :arg1 :arg2))
        (unless (eq arg argreg)
          (emit-set-gpr argreg arg)))
  (emit-stack-push (+ 8 (current-insn-addr)))
  (emit-jump name)
  (emit* :nop))

(defmacro emitting-function (name (&key (return-tag :return)) &body body)
  `(allocate-let (asm-mips:gpr :ret-reg)
     (with-tags (,return-tag)
       (emit-global-tag ,name)
       ,@body
       (emit-tag ,return-tag)
       (emit-stack-pop)
       (emit-based-load32 :ret-reg 0 :stack-top)
       (emit* :nop)
       (emit* :jr :ret-reg)
       (emit* :nop))))

;;;
;;; Predicate functions
;;;
(defmacro emitting-predicate-function (name (&key (return-tag :return) (return-zero-tag :return-zero) (return-one-tag :return-one)) &body body)
  `(emitting-function ,name ()
     (with-tags (,return-tag ,return-zero-tag ,return-one-tag)
       ,@body
       (emit-tag ,return-one-tag)
       (emit-set-gpr :arg0-ret 1)
       (emit-jump ,return-tag)
       (emit* :nop)
       (emit-tag ,return-zero-tag)
       (emit-set-gpr :arg0-ret 0))))

(defun emit-succeed ()
  (emit-jump-if-eq :return-one :zero :zero))

(defun emit-fail ()
  (emit-jump-if-eq :return-zero :zero :zero))

(defun emit-succeed-if-eq (val1 val2)
  "See the ugliness? LET-alike must be here!"
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (ensure-cell name1 val1)
    (ensure-cell name2 val2)
    (emit-jump-if-eq :return-one name1 name2)
    (release-cell name1)
    (release-cell name2)))

(defun emit-succeed-if-ne (val1 val2)
  "See the ugliness? LET-alike must be here!"
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (ensure-cell name1 val1)
    (ensure-cell name2 val2)
    (emit-jump-if-ne :return-one name1 name2)
    (release-cell name1)
    (release-cell name2)))

(defun emit-fail-if-eq (val1 val2)
  "See the ugliness? LET-alike must be here!"
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (ensure-cell name1 val1)
    (ensure-cell name2 val2)
    (emit-jump-if-eq :return-zero name1 name2)
    (release-cell name1)
    (release-cell name2)))

(defun emit-fail-if-ne (val1 val2)
  "See the ugliness? LET-alike must be here!"
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (ensure-cell name1 val1)
    (ensure-cell name2 val2)
    (emit-jump-if-ne :return-zero name1 name2)
    (release-cell name1)
    (release-cell name2)))

(defun emit-test-eq (val1 val2)
  "See the predicate explosion? Name and compose them."
  (emit-succeed-if-eq val1 val2)
  (emit* :nop)
  (emit-fail)
  (emit* :nop))

(defun emit-test-ne (val1 val2)
  "See the predicate explosion? Name and compose them."
  (emit-succeed-if-ne val1 val2)
  (emit* :nop)
  (emit-fail)
  (emit* :nop))

(defun emit-jump-if (tag predicate &rest args)
  (apply #'emit-near-function-call predicate args)
  (with-tags (:skip)
    (emit-jump-if-eq :skip :arg0-ret :zero)
    (emit* :nop)
    (emit-jump tag)
    (emit* :nop)
    (emit-tag :skip)))