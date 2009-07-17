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

(in-package :assem-mips)

(defvar *mips-gpr-environment*)

;;;
;;; Top levels for emission
;;;
(defmacro with-mips-gpr-environment (&body body)
  `(let ((*mips-gpr-environment* (find-environment 'gpr)))
     (declare (special *mips-gpr-environment*))
     ,@body))

(defmacro with-mips-assem (&body body)
  `(with-ensured-assem *mips-isa*
     (with-mips-gpr-environment
       ,@body)))

(defmacro with-extentable-mips-segment ((extentable addr) &body body)
  `(with-extentable-segment (*mips-isa* ,extentable ,addr)
     (with-mips-gpr-environment
       ,@body)))

;;;
;;; GPR yayity
;;;
(defun evaluate-mips-gpr (name)
  (multiple-value-bind (physical bound-p) (pool-evaluate *mips-gpr-environment* name)
    (unless bound-p
      (assembly-error "~@<Cell name ~S not bound in ~S.~:@>" name *mips-gpr-environment*))
    physical))

(defmacro with-mips-gpri ((&rest gprs) &body body)
  `(with-pool-subset (*mips-gpr-environment* ,@gprs)
     ,@body))

(defun allocate-mips-gpr (name)
  (pool-allocate (env-pool *mips-gpr-environment*) name))

(defun release-mips-gpr (gpr)
  (pool-release (env-pool *mips-gpr-environment*) gpr))

;;;
;;; Override ASSEM-EMISSION for happiness
;;;
(defun emit (insn)
  (assem-emit:emit *mips-gpr-environment* insn))

(defun emit* (opcode &rest insn-args)
  (emit (cons opcode insn-args)))

(defmacro emit-ref (name (delta-var-name) &body insn)
  `(prog1 (assem-emission:emit-ref *mips-gpr-environment* ,name (,delta-var-name) ,@insn)
     (emit* :nop)))

;;;
;;; Extend ASSEM...
;;;
(defmacro define-emitter (name lambda-list binding-set &body body)
  (multiple-value-bind (docstring decls body) (destructure-def-body body)
    (multiple-value-bind (special-decls nonspecial-decls) (unzip (feq 'special) decls :key #'car)
      (emit-defun
       name (mapcar (compose #'car #'ensure-cons) lambda-list)
       `((with-mips-gpr-environment
           (with-mips-gpri (,@binding-set)
             ,@special-decls
             ,@body)))
       :documentation docstring
       :declarations (append nonspecial-decls
                             (iter (for paramspec in lambda-list)
                                   (destructuring-bind (paramname &optional paramwidth) (ensure-cons paramspec)
                                     (when paramwidth
                                       (unless (typep paramwidth '(unsigned-byte 6))
                                         (assembly-error "~@<Error in DEFINE-EMITTER ~A: bad parameter width ~S for parameter ~S.~:@>"
                                                         name paramwidth paramname))
                                       (collect `(type (unsigned-byte ,paramwidth) ,paramname))))))))))

(defun emit-nops (count)
  (dotimes (i count)
    (emit* :nop)))

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
(define-emitter emit-based-store32 (value basereg (offset 16)) (gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sw :proxy offset basereg))
    (keyword
     (emit* :sw value offset basereg))))
(define-emitter emit-based-store16 (value basereg (offset 16)) (gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sh :proxy offset basereg))
    (keyword
     (emit* :sh value offset basereg))))
(define-emitter emit-based-store8 (value basereg (offset 16)) (gpr :proxy)
  (etypecase value
    (integer
     (emit-set-gpr :proxy value)
     (emit* :sb :proxy offset basereg))
    (keyword
     (emit* :sb value offset basereg))))

;;;
;;; Absolute memory stores
;;;
(define-emitter emit-store32 ((value 32) address) (gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store32 value :base (logand #xffff address)))
(define-emitter emit-store16 ((value 32) address) (gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store16 value :base (logand #xffff address)))
(define-emitter emit-store8 ((value 32) address) (gpr :base)
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
(define-emitter emit-mask32 (dstreg srcreg (mask 32)) (gpr :mask)
  (emit-set-gpr :masker mask)
  (emit* :and dstreg :mask srcreg))
(define-emitter emit-mask16 (dstreg srcreg (mask 16)) nil
  (emit* :andi dstreg srcreg mask))

;;;
;;; Miscellaneous complex accesses
;;;
(define-emitter emit-set-cp0 (cp0 (value 32)) (gpr :proxy)
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
(define-emitter emit-long-jump ((address 32)) (gpr :proxy)
  (emit-set-gpr :proxy address)
  (emit* :nop)
  (emit* :jr :proxy)
  (emit* :nop))

(defun emit-jump (name)
  (emit-ref name (delta) :beq :zero :zero delta))

(defun emit-jump-if-eq (name r1 r2)
  (emit-ref name (delta) :beq r1 r2 delta))

(defun emit-jump-if-ne (name r1 r2)
  (emit-ref name (delta) :bne r1 r2 delta))

;;;
;;; Scoped register allocation
;;;
(defun ensure-cell (env name val)
  "Ensure that NAME is bound to whatever is signified by VAL.
In any case the bottom frame is extended with NAME. The value of that new
binding is either a newly allocated register, if VAL designates an
immediate value, or if VAL designates a binding, the backing register
of that binding. The returned primary value specifies whether
a new register was allocated."
  (etypecase val
    (keyword ;; already a register? rebind.
     (bind (bottom-frame env) name
           (cond ((name-bound-p env val) (lookup env val))
                 ((name-bound-p (env-pool env) val) val)
                 (t (allocation-error "~@<Attempt to rebind and unbound name ~S in ~S.~:@>" val env))))
     nil)
    (integer ;; no? allocate, bind dynamicly and set.
     (let ((cell (pool-allocate-binding env name)))
       (emit-set-gpr cell val))
     t)))

(defmacro cell-let (bindings &body body)
  "Execute BODY with freshly established dynamic BINDINGS."
  (if bindings
      (destructuring-bind ((name value) &rest maybe-more-bindings) bindings
        (with-gensyms (reg-allocated-p)
          `(let ((,reg-allocated-p (ensure-cell *mips-gpr-environment* ,name ,value)))
             (unwind-protect
                  (cell-let ,maybe-more-bindings
                    ,@body)
               (when ,reg-allocated-p
                 (pool-release (env-pool *mips-gpr-environment*) (pool-evaluate *mips-gpr-environment* ,name)))
               (unbind (bottom-frame *mips-gpr-environment*) ,name)))))
      `(progn ,@body)))

;;;
;;; Iteration
;;;
(defmacro emitting-iteration ((iterations &optional exit-tag (counter-reg :counter)) &body body)
  (once-only (iterations)
    `(cell-let ((,counter-reg ,iterations))
       (with-tags *tag-domain*
         (emit-tag :loop-begin)
         ,@body
         (emit-ref :loop-begin (delta) :bne ,counter-reg :zero delta)
         (emit* :addiu ,counter-reg ,counter-reg #xffff)
         ,@(when exit-tag
                 `((emit-tag ,exit-tag)))))))

;;;
;;; Function call machinery
;;;
(defmacro with-function-calls (&body body)
  `(with-mips-gpri (:stack-top :arg0-ret :arg1 :arg2)
     ,@body))

(defun emit-stack-push (value)
  (emit-based-store32 value :stack-top 0)
  (emit* :addiu :stack-top :stack-top #xfffc))

(defun emit-stack-pop ()
  (emit* :addiu :stack-top :stack-top #x4))

(defun emit-function-call-prologue (function-args offset)
  (iter (for arg in function-args)
        (for argreg in '(:arg0-ret :arg1 :arg2))
        (unless (eq arg argreg)
          (emit-set-gpr argreg arg)))
  (emit-stack-push (+ offset (current-absolute-addr))))

;;; Everything is position-independent, whereas function return addresses aren't.
(defun emit-near-function-call (name &rest args)
  (emit-function-call-prologue args #x18)
  (let ((ref (emit-jump name)))
    (when-let ((tag (find-tag name)))
      (backpatch-tag-reference tag ref)))
  (emit* :nop))

;;; Everything is position-independent, whereas function return addresses aren't.
(defun emit-long-function-call (name &rest args)
  (emit-function-call-prologue args #x24)
  (emit-long-jump (tag-address name))
  (emit* :nop))

(defmacro emitting-function (name (&key (return-tag :return)) &body body)
  `(with-function-definition-and-emission *tag-domain* ,name
     (with-mips-gpri (:ret-reg)
       (with-tags *tag-domain*
         ,@body
         (emit-tag ,return-tag)
         (emit-stack-pop)
         (emit-based-load32 :ret-reg 0 :stack-top)
         (emit* :nop)
         (emit* :jr :ret-reg)
         (emit* :nop)))))

;;;
;;; Predicate functions
;;;
(defmacro emitting-predicate-function (name (&key (return-tag :return) (return-zero-tag :return-zero) (return-one-tag :return-one)) &body body)
  `(emitting-function ,name (:return-tag ,return-tag)
     (with-tags *tag-domain*
       ,@body
       (emit-tag ,return-zero-tag)
       (emit-set-gpr :arg0-ret 0)
       (emit-jump ,return-tag)
       (emit* :nop)
       (emit-tag ,return-one-tag)
       (emit-set-gpr :arg0-ret 1))))

(defun emit-succeed ()
  (emit-jump-if-eq :return-one :zero :zero))

(defun emit-fail ()
  (emit-jump-if-eq :return-zero :zero :zero))

(defun emit-succeed-if-eq (val1 val2)
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (cell-let ((name1 val1)
               (name2 val2))
      (emit-jump-if-eq :return-one name1 name2))))

(defun emit-succeed-if-ne (val1 val2)
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (cell-let ((name1 val1)
               (name2 val2))
      (emit-jump-if-ne :return-one name1 name2))))

(defun emit-fail-if-eq (val1 val2)
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (cell-let ((name1 val1)
               (name2 val2))
      (emit-jump-if-eq :return-zero name1 name2))))

(defun emit-fail-if-ne (val1 val2)
  (let ((name1 (make-keyword (gensym)))
        (name2 (make-keyword (gensym))))
    (cell-let ((name1 val1)
               (name2 val2))
      (emit-jump-if-ne :return-zero name1 name2))))

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
  (with-tags *tag-domain*
    (emit-jump-if-eq :skip :arg0-ret :zero)
    (emit* :nop)
    (emit-jump tag)
    (emit* :nop)
    (emit-tag :skip)))