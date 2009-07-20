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

(defconstant +arglist-length-limit+ 5)
(define-constant +arg-lvar-names+ '(arg0 arg1 arg2 arg3 arg4) :test 'equal)

;;;
;;; IR1
;;;
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
  ((name :accessor func-name :initarg :name)
   (nargs :accessor func-nargs :initarg :nargs)
   (purep :accessor func-purep :initarg :purep)
   (leafp :accessor func-leafp :initarg :leafp)))

(defclass expr-func (func)
  ((lambda-list :accessor func-lambda-list :initarg :lambda-list)
   (expr :accessor func-expr :initarg :expr)))

(defclass primitive-func (func)
  ())

(defclass compenv ()
  ((primops :accessor compenv-primops :initform (make-hash-table :test 'eq))
   (functions :accessor compenv-functions :initform (make-hash-table :test 'eq))
   (macros :accessor compenv-macros :initform (make-hash-table :test 'eq))))

(define-container-hash-accessor :i primop :container-transform compenv-primops :parametrize-container t :type primitive-func :if-exists :error)
(define-container-hash-accessor :i func :container-transform compenv-functions :parametrize-container t :type expr-func :if-exists :error)
(define-container-hash-accessor :i macro :container-transform compenv-macros :parametrize-container t :type function :if-exists :error)

(defun defprimitive (compenv name nargs purep)
  (setf (primop compenv name) (make-instance 'primitive-func :name name :nargs nargs :purep purep :leafp t)))

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

;;;
;;; IR2
;;;
(defstruct vop
  code)

(defmethod print-object ((o vop) stream)
  (print-unreadable-object (o stream)
    (format stream "VOP ~S" (vop-code o))))

(defun emit-label (name)
  (list name))

(defun emit-constant (value)
  (list (make-vop :code `(const ,value))))

(defun emit-lvar-ref (lvar)
  (list (make-vop :code `(lvar-ref, lvar))))

(defun emit-lvar-set (lvar)
  (list (make-vop :code `(lvar-set, lvar))))

(defun emit-save-continuation (label)
  (list (make-vop :code `(save-continuation ,label))))

(defun emit-jump (label)
  (list (make-vop :code `(jump ,label))))

(defun emit-jump-if (label)
  (list (make-vop :code `(jump-if ,label))))

(defun emit-jump-if-not (label)
  (list (make-vop :code `(jump-if-not ,label))))

(defun emit-return ()
  (list (make-vop :code `(return))))

(defun emit-primitive (name &rest args)
  (list (make-vop :code `(,name ,@args))))

;;;
;;; Actual compilation
;;;
;; Invariants:
;;  (not valuep) -> (not tailp)
;;  (expr-effect-free x) -> (compile-xxx x env nil nil) => nil
(defun constant-p (expr)
  (or (eq expr 't)
      (eq expr 'nil)
      (integerp expr)))

(defun compile-constant (expr valuep tailp)
  (unless (constant-p expr)
    (comp-error "~@<In ~S: attempted to compile ~S as constant.~:@>" *sexp-path* expr))
  (when valuep
    (make-expr t t nil expr
               (append (emit-constant (case expr
                                        ((t) 1)
                                        ((nil) 0)
                                        (t expr)))
                       (when tailp
                         (emit-return))))))

(defun compile-variable-ref (var lexenv valuep tailp)
  (with-noted-sexp-path var
    (unless (env-boundp var lexenv)
      (comp-error "~@<In ~S: ~S not bound.~:@>" *sexp-path* var))
    (when valuep
      (make-expr t t lexenv var
                 (append (emit-lvar-ref var)
                         (when tailp
                           (emit-return)))))))

(defun compile-variable-set (var value compenv lexenv valuep tailp)
  (with-noted-sexp-path `(setf ,var)
    (unless (env-boundp var lexenv)
      (comp-error "~@<In ~S: ~S not bound.~:@>" *sexp-path* var))
    (make-expr nil valuep lexenv var
               (append (if (typep value 'expr)
                           value
                           (compile-expr value compenv lexenv t nil))
                       (emit-lvar-set var)
                       (when tailp
                         (emit-return))))))

(defun compile-funcall (fname args compenv lexenv valuep tailp)
  (let ((func (or (func compenv fname :if-does-not-exist :continue)
                  (primop compenv fname :if-does-not-exist :continue))))
    (unless func
      (comp-error "~@<In ~S: reference to undefined function ~S.~:@>" *sexp-path* fname))
    (unless (= (length args) (func-nargs func))
      (comp-error "~@<In ~S: wrong argument count in call of ~S: got ~D, expected ~D.~:@>"
                  *sexp-path* fname (length args) (func-nargs func)))
    (with-noted-sexp-path `(funcall ,fname)
      (let* ((args-code (mapcar (rcurry #'compile-expr compenv lexenv t nil) args))
             (expr-pure (and (every #'expr-effect-free args-code) (func-purep func))))
        (when (or valuep (not expr-pure))
          (make-expr expr-pure valuep lexenv `(funcall ,fname)
                     (let ((ret-label (gensym (concatenate 'string "BACK-FROM-" (symbol-name fname)))))
                       ;; need to abstract the argument count issue better
                       (append (iter (for arg-lvar in +arg-lvar-names+)
                                     (for arg-code in args-code)
                                     (collect (compile-variable-set arg-lvar arg-code compenv lexenv nil nil)))
                               (if (typep func 'primitive-func)
                                   (emit-primitive (func-name func))
                                   (append
                                    (unless tailp
                                      (emit-save-continuation ret-label))
                                    (emit-jump fname)
                                    (unless tailp
                                      (emit-label ret-label))))))))))))

;;;
;;; Non-leaf expressions
;;;
(defun compile-progn (expr compenv lexenv valuep tailp)
  (if expr
      (let* ((for-effect (remove nil (mapcar (rcurry #'compile-expr compenv lexenv nil nil) (butlast expr))))
             (for-value (compile-expr (lastcar expr) compenv lexenv tailp valuep))
             (expr-pure (and (null for-effect) (expr-effect-free for-value))))
        (when (or valuep (not expr-pure))
          (make-expr expr-pure valuep lexenv `(progn ,@expr)
                     (append for-effect
                             ;; for-value is NIL iff (and (not valuep) (expr-effect-free for-value-expr))
                             ;; which implies (not tail)
                             (when for-value
                               (list for-value))))))
      (compile-constant nil valuep tailp)))

;;; For now, we can't rely much on VAR-EXPR.
(defun compile-let (bindings body compenv lexenv valuep tailp)
  (with-noted-sexp-path 'let
    (let* ((binding-value-code (mapcar (rcurry #'compile-expr compenv lexenv t nil) (mapcar #'second bindings)))
           (vars (iter (for (name . nil) in bindings)
                       (for expr in binding-value-code)
                       (collect (make-instance 'expr-var :name name :expr expr))))
           (new-lexenv (make-frame-from-vars vars lexenv))
           (body-code (compile-progn body compenv new-lexenv valuep tailp))
           (expr-pure (every #'expr-effect-free (cons body-code binding-value-code))))
      (when (or valuep (not expr-pure))
        (make-expr expr-pure valuep lexenv `(let ,bindings ,@body)
                   (append (iter (for var in vars)
                                 (collect (compile-variable-set (var-name var) (var-expr var) compenv lexenv nil nil)))
                           body-code))))))

(defun compile-if (clauses compenv lexenv valuep tailp)
  (let ((n-args (length clauses)))
    (when (or (< n-args 2)
              (> n-args 3))
      (comp-error "~@<In ~S: invalid number of elements in IF operator: between 2 and 3 expected.~:@>" *sexp-path*)))
  (destructuring-bind (condition then-clause &optional else-clause) clauses
    (let* ((condition-code (compile-expr condition compenv lexenv t nil))
           (then-code (compile-expr then-clause compenv lexenv valuep tailp))
           (else-code (if else-clause
                          (compile-expr else-clause compenv lexenv valuep tailp)
                          (compile-constant nil valuep tailp)))
           (expr-pure (every #'expr-effect-free (list condition-code then-code else-code))))
      (when (or valuep expr-pure)
        (with-noted-sexp-path 'if
          (cond ((null condition) else-code)
                ((constant-p condition) then-code)
                ((equalp then-clause else-clause) (compile-progn `(,condition ,then-clause) compenv lexenv valuep tailp))
                ((and (= 2 (length condition)) (eq (first condition) 'not))
                 (compile-if (list* 'if (second condition) then-clause (when else-clause (list else-clause))) compenv lexenv valuep tailp))
                (t
                 (make-expr expr-pure valuep lexenv (list* 'if condition then-clause (when else-clause (list else-clause)))
                            (let ((else-label (gensym (concatenate 'string "IF-NOT")))
                                  (end-label (gensym (concatenate 'string "IF-END"))))
                             (append condition-code
                                     (emit-jump-if-not else-label)
                                     then-code
                                     (emit-jump end-label)
                                     (emit-label else-label)
                                     else-code
                                     (emit-label end-label)))))))))))

(defun compile-expr (expr compenv lexenv valuep tailp)
  (cond ((constant-p expr) (compile-constant expr valuep tailp))
        ((symbolp expr) (compile-variable-ref expr lexenv valuep tailp))
        ((atom expr)
         (comp-error "~@<In ~S: atom ~S has unsupported type ~S.~:@>" *sexp-path* expr (type-of expr)))
        (t
         (case (car expr)
           (progn (compile-progn (rest expr) compenv lexenv valuep tailp))
           (if (compile-if (rest expr) compenv lexenv valuep tailp))
           (let (if (null (second expr))
                    (compile-progn (cddr expr) compenv lexenv valuep tailp)
                    (compile-let (second expr) (cddr expr) compenv lexenv valuep tailp)))
           (t
            (if-let ((macro (macro compenv (car expr) :if-does-not-exist :continue)))
              (compile-expr (apply macro (cdr expr)) compenv lexenv valuep tailp)
              (compile-funcall (car expr) (rest expr) compenv lexenv valuep tailp)))))))

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
                (lret ((body-code (append (emit-label name)
                                          (compile-progn body compenv (make-frame-from-var-names lambda-list nil) t t))))
                  (setf (func compenv name)
                        (make-instance 'expr-func :name name :nargs (length lambda-list) :lambda-list lambda-list
                                       :purep (expr-effect-free body-code) :leafp nil
                                       :expr body-code))))))
        (t
         (if-let ((macro (macro compenv op :if-does-not-exist :continue)))
           (with-noted-sexp-path `(defmacro ,op)
             (compile-toplevel (apply macro (rest expr)) compenv))
           (compile-expr expr compenv nil nil nil)))))))
