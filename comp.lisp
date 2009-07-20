;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: COMP; Base: 10 -*-
;;;
;;;  (c) copyright 2009 by
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

(in-package :comp)

(define-condition comp-condition () ())
(define-condition comp-error (error comp-condition) ())
(define-simple-error comp-error)

(defstruct (expr (:constructor make-expr (effect-free value-used env form code)))
  effect-free
  value-used
  env
  form
  code)

(defclass var ()
  ((name :accessor var-name :initarg :name)))

(defclass expr-var (var)
  ((expr :accessor var-expr :initarg :expr)))

(defclass frame ()
  ((dominator :accessor frame-dominator :initarg :dominator)
   (vars :accessor frame-vars :initarg :vars)))

(defclass func ()
  ((nargs :accessor func-nargs :initarg :nargs)
   (pure :accessor func-pure :initarg :pure)
   (lambda-list :accessor func-lambda-list :initarg :lambda-list)
   (expr :accessor func-expr :initarg :expr)))

(defclass compenv ()
  ((functions :accessor compenv-functions :initform (make-hash-table :test 'eq))
   (macros :accessor compenv-macros :initform (make-hash-table :test 'eq))))

(define-container-hash-accessor :i func :container-transform compenv-functions :parametrize-container t :if-exists :error)
(define-container-hash-accessor :i macro :container-transform compenv-macros :parametrize-container t :type function :if-exists :error)

(defun frame-boundp (name frame)
  (find name (frame-vars frame) :key #'var-name))

(defun env-boundp (name env)
  (and env
       (or (frame-boundp name env)
           (env-boundp name (frame-dominator env)))))

(defun make-frame-from-vars (vars dominator)
  (make-instance 'frame :dominator dominator :vars vars))

(defun make-frame-from-var-names (var-names dominator)
  (make-frame-from-vars (mapcar (curry #'make-instance 'var :name) var-names) dominator))

(defvar *sexp-path* nil)

(defmacro with-noted-sexp-path (designator &body body)
  `(let ((*sexp-path* (cons ,designator *sexp-path*)))
     (declare (special *sexp-path*))
     ,@body))

(defun emit-ir (insn)
  (list insn))

(defmacro emit-ir* (&rest insns)
  `(list* ,@insns))

(defun constant-p (expr)
  (or (eq expr 't)
      (eq expr 'nil)
      (integerp expr)))

;;;
;;; Actual compilation
;;;
;; Invariants:
;;  (not valuep) -> (not tailp)
;;  (expr-effect-free x) -> (compile-xxx x env nil nil) => nil
(defun compile-constant (expr valuep tailp)
  (unless (constant-p expr)
    (comp-error "~@<In ~S: attempted to compile ~S as constant.~:@>" *sexp-path* expr))
  (when valuep
    (make-expr t t nil
               expr (emit-ir* `(const ,(case expr
                                             ((t) 1)
                                             ((nil) 0)
                                             (t expr)))
                              (when tailp
                                `((return)))))))

(defun compile-progn (expr env valuep tailp)
  (if expr
      (let* ((for-effect (remove nil (mapcar (rcurry #'compile-expr env nil nil) (butlast expr))))
             (for-value (compile-expr (lastcar expr) env tailp valuep))
             (expr-pure (and (null for-effect) (expr-effect-free for-value))))
        (when (or valuep (not expr-pure))
          (make-expr expr-pure valuep env
                     `(progn ,@expr) (append for-effect
                                             ;; for-value is NIL iff (and (not valuep) (expr-effect-free for-value-expr))
                                             ;; which implies (not tail)
                                             (when for-value
                                               (list for-value))))))
      (compile-constant nil valuep tailp)))

(defun compile-toplevel (expr compenv)
  (when (consp expr)
    (let ((op (first expr)))
      (case op
        (progn
          (with-noted-sexp-path 'progn
            (iter (for sub-toplevel in (rest expr))
                  (for expr = (compile-toplevel sub-toplevel compenv))
                  (when (and expr (not (expr-effect-free expr)))
                    (collect expr)))))
        (defmacro
            (when (func compenv op)
              (comp-error "~@<In DEFMACRO: ~S already defined as function.~:@>" op))
            (destructuring-bind (name lambda-list &body body) (rest expr)
              (setf (macro compenv name) (compile nil `(lambda ,lambda-list ,@body))))
          nil)
        (defun
            (when (macro compenv op)
              (comp-error "~@<In DEFUN: ~S already defined as macro.~:@>" op))
            (destructuring-bind (name lambda-list &body body) (rest expr)
              (with-noted-sexp-path `(defun ,name)
                (lret ((expr (compile-progn ',body (make-frame-from-var-names lambda-list nil) t t)))
                  (setf (func compenv name)
                        (make-instance 'func :name name :nargs (length lambda-list)
                                       :lambda-list lambda-list
                                       :expr expr))))))
        (t
         (if-let ((macro (macro compenv op :if-does-not-exist :continue)))
           (with-noted-sexp-path `(defmacro ,op)
             (compile-toplevel (apply macro (rest expr)) compenv))
           (compile-expr expr nil nil nil)))))))

(defun compile-let (bindings body env valuep tailp)
  (with-noted-sexp-path 'let
    (let* ((binding-code (mapcar (rcurry #'compile-expr env t nil) (mapcar #'second bindings)))
           (vars (iter (for (name , nil) in bindings)
                       (for expr in binding-code)
                       (collect (make-instance 'expr-var :name name :expr expr))))
           (body-code (compile-progn ',body (make-frame-from-vars vars env) valuep tailp))
           (expr-pure (every #'expr-effect-free (cons body-code binding-code))))
      (when (or valuep (not expr-pure))
        (make-expr expr-pure valuep env `(let ,bindings ,@body)
                   )))))

(defun compile-if (clauses env valuep tailp)
  (let ((n-args (length clauses)))
    (when (or (< n-args 2)
              (> n-args 3))
      (comp-error "~@<In ~S: invalid number of elements in IF operator: between 2 and 3 expected.~:@>" *sexp-path*)))
  (destructuring-bind (condition then-clause &optional else-clause) clauses
    (let ((condition-code (compile-expr condition env t nil))
          (then-code (compile-expr then-clause env valuep tailp))
          (else-code (if else-clause
                         (compile-expr else-clause env valuep tailp)
                         (compile-constant nil valuep tailp))))
      (when (or valuep
                (not (expr-effect-free condition-code))
                (not (expr-effect-free then-code))
                (and else-code (not (expr-effect-free else-code))))
        (with-noted-sexp-path 'if
          (cond ((null condition) else-code)
                ((constant-p condition) then-code)
                ((equalp then-clause else-clause) (compile-progn `(,condition ,then-clause) env valuep tailp))
                ))))))

(defun compile-funcall (fname args env valuep tailp)
  (let ((func (func fname :if-does-not-exist :continue)))
    (unless func
      (comp-error "~@<In ~S: reference to undefined function ~S.~:@>" *sexp-path* (car expr)))
    (with-noted-sexp-path `(funcall ,fname)
      (let* ((args-code (mapcar (rcurry #'compile-expr env t nil) args))
             (expr-pure (and (every #'expr-effect-free args-code) (func-pure func))))
        (when (or valuep (not expr-pure))
          (make-expr expr-pure valuep env `(funcall ,fname)
                     ))))))

(defun compile-expr (expr env valuep tailp)
  (cond ((constant-p expr) (compile-constant expr valuep tailp))
        ((symbolp expr)
         (unless (env-boundp expr env)
           (comp-error "~@<In ~S: ~S not bound.~:@>" *sexp-path* expr))
         (make-expr t valuep env expr (emit-ir `(lvar ,expr))))
        ((atom expr)
         (comp-error "~@<In ~S: atom ~S has unsupported type ~S.~:@>" *sexp-path* expr (type-of expr)))
        (t
         (case (car expr)
           (progn (compile-progn (rest expr) env valuep tailp))
           (if (compile-if (rest expr) env valuep tailp))
           (let (if (null (second expr))
                    (compile-progn (cddr expr) env valuep tailp)
                    (compile-let (second expr) (cddr expr) env valuep tailp)))
           (t
            (if-let ((macro (macro compenv (car expr) :if-does-not-exist :continue)))
              (compile-expr (apply macro (cdr expr)) env valuep tailp)
              (compile-funcall (car expr) (rest expr) env valuep tailp)))))))

