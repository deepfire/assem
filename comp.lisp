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

(defclass var ()
  ((name :accessor var-name :initarg :name)))

(defclass frame ()
  ((dominator :accessor frame-dominator :initarg :dominator)
   (vars :accessor frame-vars :initarg :vars)))

(defstruct (expr (:constructor make-expr (effect-free value-used env form code)))
  effect-free
  value-used
  env
  form
  code)

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

(defun make-frame (var-names dominator)
  (make-instance 'frame :dominator dominator :vars (mapcar (curry #'make-instance 'var :name) var-names)))

(defvar *sexp-path* nil)

(defmacro with-noted-sexp-path (designator &body body)
  `(let ((*sexp-path* (cons ,designator *sexp-path*)))
     (declare (special *sexp-path*))
     ,@body))

(defun emit-ir (insn)
  (list insn))

(defun constant-p (expr)
  (or (eq expr 't)
      (eq expr 'nil)
      (integerp expr)))

;;;
;;; Actual compilation
;;;
(defun compile-constant (expr)
  (unless (constant-p expr)
    (comp-error "~@<In ~S: attempted to compile ~S as constant.~:@>" *sexp-path* expr))
  (make-expr t t nil
             expr (emit-ir `(const ,(case expr
                                          ((t) 1)
                                          ((nil) 0)
                                          (t expr))))))

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
                (lret ((expr (compile-progn ',body (make-frame lambda-list))))
                  (setf (func compenv name)
                        (make-instance 'func :name name :nargs (length lambda-list)
                                       :lambda-list lambda-list
                                       :expr expr))))))
        (t
         (if-let ((macro (macro compenv op)))
           (compile-toplevel (apply macro (rest expr)) compenv)
           (compile-expr expr nil)))))))

(defun compile-if (clauses env)
  (let ((n-args (length clauses)))
    (when (or (< n-args 2)
              (> n-args 3))
      (comp-error "~@<In ~S: invalid number of elements in IF operator: between 2 and 3 expected.~:@>" *sexp-path*)))
  (destructuring-bind (condition then-clause &optional else-clause) clauses
    (let ((condition-code (compile-expr condition env)))
      (if ()
       (cond ((null condition) (compile-expr else-clause))
             ((constant-p condition) (compile-expr then-clause))
             ((equalp then-clause else-clause) (compile-progn `(,condition ,then-clause)))
             )))))

(defun compile-expr (expr env)
  (cond ((constant-p expr) (compile-constant expr))
        ((symbolp expr)
         (unless (env-boundp expr env)
           (comp-error "~@<In ~S: ~S not bound.~:@>" *sexp-path* expr))
         (emit-ir `(lvar ,expr)))
        ((atom expr)
         (comp-error "~@<In ~S: atom ~S has unsupported type ~S.~:@>" *sexp-path* expr (type-of expr)))
        (t
         (case (car expr)
           (prog1 (compile-prog1 (rest expr)))
           (progn (compile-progn (rest expr)))
           (if (compile-if (rest expr) env))
           (let (if (null (second expr))
                    (compile-progn (cddr expr) env)
                    (compile-let (second expr) (cddr expr) env)))
           ))))

