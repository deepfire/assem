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

(defvar *comp-verbose* nil)

(eval-when (:compile-toplevel :load-toplevel)
  (define-condition comp-condition () ())
  (define-condition comp-error (error comp-condition) ())
  (define-simple-error comp-error))

;;;
;;; IR1
;;;
(defun comp-typep (x type)
  (if (consp type)
      (ecase (first type)
        (and (not (null (every (curry #'comp-typep x) (rest type)))))
        (or (not (null (some (curry #'comp-typep x) (rest type))))))
      (ecase type
        (boolean (member x '(t nil)))
        (integer (typep x '(unsigned-byte 32)))
        (nil nil)
        ((t) t))))

(defun comp-type-of (x)
  (cond ((member x '(t nil)) 'boolean)
        ((typep x '(unsigned-byte 32)) 'integer)
        (t t)))

(defun comp-simplify-logical-expression (x &aux (pass-list '(fold-constants remove-duplicates unnest-similars detrivialize recurse)))
  (cond ((atom x) x)
        ((= 2 (length x)) (comp-simplify-logical-expression (second x)))
        (t
         (cons (first x) (let ((state pass-list)
                               (x-body (rest x)))
                           (block machine-collector
                             (tagbody
                              loop
                                (let ((xform (case (car state)
                                               (fold-constants
                                                (lambda ()
                                                  (ecase (first x)
                                                    (or (if (member t (rest x))
                                                            (return-from comp-simplify-logical-expression t)
                                                            (remove nil x-body)))
                                                    (and (if (member nil (rest x))
                                                             (return-from comp-simplify-logical-expression nil)
                                                             (remove t x-body))))))
                                               (remove-duplicates
                                                (lambda ()
                                                  (remove-duplicates x-body :test #'eq)))
                                               (unnest-similars
                                                (lambda ()
                                                  (multiple-value-bind (nested-similars others) (unzip (lambda (subx)
                                                                                                         (and (consp subx) (eq (car subx) (car x))))
                                                                                                       x-body)
                                                    (apply #'append (cons others (mapcar #'rest nested-similars))))))
                                               (detrivialize
                                                (lambda ()
                                                  (if (null (cdr x-body))
                                                      (values (car x-body) t)
                                                      x-body)))
                                               (recurse
                                                (lambda ()
                                                  (mapcar #'comp-simplify-logical-expression x-body))))))
                                  (if xform
                                      (multiple-value-bind (processed-x-body trivial-p) (funcall xform)
                                        (cond (trivial-p
                                               (return-from comp-simplify-logical-expression
                                                 (comp-simplify-logical-expression processed-x-body)))
                                              ((equalp processed-x-body x-body)
                                               (setf state (cdr state)))
                                              (t
                                               (setf state pass-list
                                                     x-body processed-x-body)))
                                        (go loop))
                                      (return-from machine-collector x-body))))))))))

(defclass var ()
  ((name :accessor var-name :initarg :name)))

(defclass frame ()
  ((dominator :accessor frame-dominator :initarg :dominator)
   (vars :accessor frame-vars :initarg :vars)))

(defclass expr-like ()
  ((type :accessor expr-type :type (or symbol list) :initarg :type)
   (effect-free :accessor expr-effect-free :type boolean :initarg :effect-free)
   (pure :accessor expr-pure :type boolean :initarg :pure)
   (branching :accessor expr-branching :type (or null (member :tail :non-tail :funcall)) :initarg :branching)))

(defclass expr (expr-like)
  ((value-used :accessor expr-value-used :type boolean :initarg :value-used)
   (env :accessor expr-env :type (or null frame) :initarg :env)
   (form :accessor expr-form :initarg :form)
   (code :accessor expr-code :initarg :code)
   (df-code :accessor expr-df-code :initform nil :documentation "DF nodes in CODE order (to facilitate side-effect ordering preservation).")))

(define-print-object-method ((o expr) effect-free pure value-used type code)
    "~@<#<EXPR ~;effect-free: ~S, pure: ~S, used: ~S, type: ~S~_~{~S~:@_~}~;>~:@>" effect-free pure value-used type code)

(defclass tn (expr)
  ()
  (:documentation "An EXPR whose result requires attention of the register allocator."))

(define-protocol-class dfnode ()
  ((generator :accessor generator :initarg :generator))
  (:documentation "Data flow node."))
(define-print-object-method ((o dfnode) generator)
    "~@<#<~;~A ~S~;>~:@>" (type-of o) generator)

(define-protocol-class dfproducer (dfnode) ((consumers :accessor consumers :initform nil :initarg :consumers)))
(define-protocol-class dfconsumer (dfnode) ((producers :accessor producers :initarg :producers)))
(define-print-object-method ((o dfconsumer) generator producers)
    "~@<#<~;~A ~S~_~{~S~:@_~}~;>~:@>" (type-of o) generator producers)

(define-protocol-class dfcontinue (dfproducer dfconsumer) ())
(define-protocol-class dfextremum (dfnode) ())

(define-protocol-class dfstart (dfextremum dfproducer) ())
(define-protocol-class dfend (dfextremum dfconsumer) ())

(define-protocol-class dffanin (dfconsumer) ())
(define-protocol-class dffanout (dfproducer) ())
(define-protocol-class dfnotfan (dfnode) ())

;; neither a producer, nor a consumer, a category of its own
(defclass dfnop (dfnotfan) ())

(defclass dfhead (dfstart dfnotfan) ())
(defclass dftail (dfend dfnotfan) ())
(defclass dfpipe (dfcontinue dfnotfan) ())

(defclass dfstartfan (dfstart dffanout) ())
(defclass dfendfan (dfend dffanin) ())
(defclass dfuga (dfcontinue dffanout) ())
(defclass dfagu (dfcontinue dffanin) ())

(defclass dfhedge (dfcontinue dffanout dffanin) ())

(defun compute-df-class (input output &aux (input (min 2 input)) (output (min 2 output)))
  (cdr (find (cons input output)
             '(((0 . 0) . dfnop)
               ((0 . 1) . dfhead) ((1 . 0) . dftail) ((1 . 1) . dfpipe)
               ((2 . 0) . dfendfan) ((0 . 2) . dfstartfan) ((2 . 1) . dfagu) ((1 . 2) . dfuga) ((2 . 2) . dfhedge))
             :key #'car :test #'equal)))

(defclass expr-var (var)
  ((expr :accessor var-expr :type expr :initarg :expr)))

(defclass func ()
  ((name :accessor func-name :type symbol :initarg :name)
   (nargs :accessor func-nargs :type (integer 0) :initarg :nargs)
   (nvalues :accessor func-nvalues :type (integer 0) :initarg :nvalues)
   (leafp :accessor func-leafp :type boolean :initarg :leafp)))

(defclass primop (expr-like func)
  ((valuep :accessor primop-valuep :type boolean :initarg :valuep)
   (instantiator :accessor primop-instantiator :type function :initarg :instantiator)
   (folder :accessor primop-folder :type function :initarg :folder)
   (papplicable-p :accessor primop-papplicable-p :type function :initarg :papplicable-p)
   (papplicator :accessor primop-papplicator :type function :initarg :papplicator)))

(defclass expr-func (func)
  ((lambda-list :accessor func-lambda-list :type list :initarg :lambda-list)
   (expr :accessor func-expr :type expr :initarg :expr)
   (complete :accessor func-complete :type boolean :initarg :complete)))

(defmethod expr-type ((o expr-func)) (expr-type (func-expr o)))
(defmethod expr-effect-free ((o expr-func)) (expr-effect-free (func-expr o)))
(defmethod expr-pure ((o expr-func)) (expr-pure (func-expr o)))

(define-print-object-method ((o func) name nargs leafp)
    "~@<#<FUNC ~;~S, ~S args, leafp: ~S, type: ~S, effect-free: ~S>~:@>" name nargs leafp (expr-type o) (expr-effect-free o))

(defparameter *primops* (make-hash-table :test 'eq))

(define-container-hash-accessor *primops* primop :if-exists :error)

(defclass compenv ()
  ((functions :accessor compenv-functions :initform (make-hash-table :test 'eq))
   (macros :accessor compenv-macros :initform (make-hash-table :test 'eq))))
(define-container-hash-accessor :i func :container-transform compenv-functions :parametrize-container t :type expr-func :if-exists :error)
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

(defun expr-error (format-control &rest format-arguments)
  (apply #'comp-error (format nil "~~@<In ~~S: ~A.~~:@>" format-control) *sexp-path* format-arguments))

(defun compiler-note (format-control &rest format-arguments)
  (apply #'format t (format nil "~~@<; ~~@;note: ~A.~~:@>~%" format-control) format-arguments))

;;;
;;; IR2
;;;
(defstruct vop
  nargs
  nvalues
  code)

(defmethod print-object ((o vop) stream)
  (print-unreadable-object (o stream)
    (format stream "VOP ~S" (vop-code o))))

(defun emit-label (name)
  (list name))

(defun emit-constant (value)
  (list (make-vop :nargs 0 :nvalues 1 :code `(const ,value))))

(defun emit-lvar-ref (lvar)
  (list (make-vop :nargs 0 :nvalues 1 :code `(lvar-ref ,lvar))))

(defun emit-lvar-set (lvar)
  (list (make-vop :nargs 1 :nvalues 0 :code `(lvar-set ,lvar))))

(defun emit-funarg-set (i)
  (list (make-vop :nargs 1 :nvalues 0 :code `(funarg-set ,i))))

(defun emit-save-continuation (label)
  (list (make-vop :nargs 0 :nvalues 1 :code `(save-continuation ,label))))

(defun emit-jump (label)
  (list (make-vop :nargs 0 :nvalues 0 :code `(jump ,label))))

(defun emit-jump-if (label)
  (list (make-vop :nargs 1 :nvalues 0 :code `(jump-if ,label))))

(defun emit-jump-if-not (label)
  (list (make-vop :nargs 1 :nvalues 0 :code `(jump-if-not ,label))))

(defun emit-return ()
  (list (make-vop :nargs 1 :nvalues 0 :code `(return))))

(defun emit-primitive (name nargs nvalues &rest primitive-args)
  (list (make-vop :nargs nargs :nvalues nvalues :code `(primitive ,name ,@primitive-args))))

;;;
;;; The megaquestion is whether PRIMOP's expr slot is warranted.
;;;
(defun instantiate-simple-primop (primop valuep args arg-exprs &aux (name (func-name primop)))
  (unless (= (length args) (func-nargs primop))
    (error "~@<~S was provided the wrong amount of values: ~D, expected ~D.~:@>" primop (length args) (func-nargs primop)))
  (make-instance 'expr :effect-free (expr-effect-free primop) :pure (expr-pure primop) :value-used valuep :env nil
                 :type (expr-type primop) :branching (expr-branching primop) :form `(,name ,@args) 
                 :code (append arg-exprs
                               (emit-primitive name (func-nargs primop) (func-nvalues primop)))))

(defun ensure-primitive (name nargs nvalues type valuep effect-free pure branching &key folder-fn (instantiator-fn #'instantiate-simple-primop)
                         (papplicable-p (constantly nil)) papplicator-fn)
  (setf (primop name) (make-instance 'primop :name name :nargs nargs :nvalues nvalues :leafp t :type type :valuep valuep :effect-free effect-free :pure pure
                                     :branching branching
                                     :instantiator instantiator-fn
                                     :folder folder-fn
                                     :papplicable-p papplicable-p :papplicator papplicator-fn)))

(defmacro defprimitive (name nargs nvalues type valuep effect-free pure branching &rest args)
  (let ((instantiator (rest (find :instantiator args :key #'car)))
        (folder (rest (find :folder args :key #'car)))
        (papplicable-p (rest (find :papplicable-p args :key #'car)))
        (papplicator (rest (find :papplicator args :key #'car))))
   `(ensure-primitive ',name ,nargs ,nvalues ',type ,valuep ,effect-free ,pure ,branching
                      ,@(when instantiator
                              `(:instantiator-fn (lambda ,(first instantiator) ,@(rest instantiator))))
                      ,@(when folder
                              `(:folder-fn (lambda ,(first folder) ,@(rest folder))))
                      ,@(when papplicable-p
                              (unless papplicator
                                (comp-error "~@<In DEFPRIMITIVE ~S: PAPPLICABLE-P specified without PAPPLICATOR.~:@>" name))
                              `(:papplicable-p (lambda ,(first papplicable-p) ,@(rest papplicable-p))))
                      ,@(when papplicator
                              (unless papplicable-p
                                (comp-error "~@<In DEFPRIMITIVE ~S: PAPPLICATOR specified without PAPPLICABLE-P.~:@>" name))
                              `(:papplicator-fn (lambda ,(first papplicator) ,@(rest papplicator)))))))

(defprimitive +              2 1 integer t   t   t   nil
  (:folder (arg-exprs tailp)
    (compile-constant (apply #'+ (mapcar #'expr-form arg-exprs)) t tailp)))
(defprimitive -              2 1 integer t   t   t   nil)
(defprimitive logior         2 1 integer t   t   t   nil)
(defprimitive logand         2 1 integer t   t   t   nil)
(defprimitive logxor         2 1 integer t   t   t   nil)
(defprimitive ash            2 1 integer t   t   t   nil
  (:folder (arg-exprs tailp)
    (compile-constant (apply #'ash (mapcar #'expr-form arg-exprs)) t tailp))
  (:papplicable-p (arg-exprs &aux (shift (expr-form (second arg-exprs))))
    (and (integerp shift) (zerop shift)))
  (:papplicator (arg-exprs)
    (first arg-exprs)))
(defprimitive lognot         1 1 integer t   t   t   nil)
(defprimitive =              2 1 boolean t   t   t   nil)
(defprimitive /=             2 1 boolean t   t   t   nil)
(defprimitive >=             2 1 boolean t   t   t   nil)
(defprimitive <=             2 1 boolean t   t   t   nil)
(defprimitive >              2 1 boolean t   t   t   nil)
(defprimitive <              2 1 boolean t   t   t   nil)
(defprimitive mem-ref        2 1 integer t   t   nil nil)
(defprimitive mem-set        3 0 nil     nil nil nil nil)
(defprimitive mem-ref-impure 2 1 integer t   nil nil nil)
(defprimitive funarg-ref     2 1 t       t   t   t   nil
  (:instantiator (primop valuep args arg-exprs &aux (type (second args)))
    (declare (ignore arg-exprs))
    (make-instance 'expr :effect-free t :pure t :value-used valuep :env nil
                   :type type :branching nil :form `(,(func-name primop) ,@args)
                   :code (apply #'emit-primitive 'funarg-ref 0 1 args))))

;;;
;;; Actual compilation
;;;
;; Invariants:
;;  (not valuep) -> (not tailp)
;;  (expr-effect-free x) -> (compile-xxx x env nil nil) => nil
;;;
;;; General notes.
;;;
;;; A simplification candidate: DFA might be entirely enough to shake out effect-free dead code.
;;; Practical equivalence of IR1 transforms to it must be seen, though, if not proven.
;;;
;;; Another simplification candidate: some kind of constituent iteration can simplify branching analysis.
;;; Turning CODE sequences of EXPRs into a form useful for that would take:
;;;   - a shift of label generation into a later point,
;;;   - an increase of branch target granularity to EXPRs.
;;;
(defun constant-p (expr)
  (or (eq expr 't)
      (eq expr 'nil)
      (integerp expr)))

(defun degrade-tail-branching (x)
  (if (eq x :tail)
      :non-tail
      x))

(defun maybe-wrap-with-return (wrap-p expr)
  (if wrap-p
      (make-instance 'expr :effect-free (expr-effect-free expr) :pure (expr-pure expr) :value-used t :env nil
                     :type (expr-type expr) :branching (degrade-tail-branching (expr-branching expr)) :form `(return ,(expr-code expr))
                     :code
                     (append (list expr)
                             (emit-return)))
      expr))

(defmacro with-return-wrapped-if (wrap-p &body expr)
  `(maybe-wrap-with-return ,wrap-p ,@expr))

(defun compile-constant (expr valuep tailp)
  (unless (constant-p expr)
    (expr-error "attempted to compile non-constant expression ~S as constant" expr))
  (when valuep
    (with-return-wrapped-if tailp
      (make-instance 'expr :effect-free t :pure t :value-used t :env nil
                     :type (comp-type-of expr) :branching nil :form expr
                     :code
                     (emit-constant (case expr
                                      ((t) 1)
                                      ((nil) 0)
                                      (t expr)))))))

(defun compile-variable-ref (var lexenv valuep tailp)
  (with-noted-sexp-path var
    (unless (env-boundp var lexenv)
      (expr-error "~S not bound" var))
    (when valuep
      (with-return-wrapped-if tailp
        (make-instance 'expr :effect-free t :pure nil :value-used t :env lexenv
                       :type t :branching nil :form var
                       :code
                       (emit-lvar-ref var))))))

(defun compile-variable-set (var value compenv lexenv valuep tailp)
  (with-noted-sexp-path `(setf ,var)
    (unless (env-boundp var lexenv)
      (expr-error "~S not bound" var))
    (with-return-wrapped-if tailp
      (let ((value-expr (if (typep value 'expr)
                            value
                            (compile-expr value compenv lexenv t nil))))
        (make-instance 'expr :effect-free nil :pure nil :value-used valuep :env lexenv
                       :type (expr-type value-expr) :branching nil :form `(setf ,var ,(expr-form value-expr))
                       :code
                       (append (list value-expr)
                               (emit-lvar-set var)))))))

(defvar *compiled-function*)

(defun compile-funcall (fname args compenv lexenv valuep tailp)
  (let ((func (or (func compenv fname :if-does-not-exist :continue)
                  (primop fname :if-does-not-exist :continue))))
    (unless func
      (expr-error "reference to undefined function ~S" fname))
    (unless (= (length args) (func-nargs func))
      (expr-error "wrong argument count in call of ~S: got ~D, expected ~D"
                  fname (length args) (func-nargs func)))
    (with-noted-sexp-path `(funcall ,fname)
      (let* ((args-code (mapcar (rcurry #'compile-expr compenv lexenv t nil) args))
             (effect-free (every #'expr-effect-free (cons func args-code)))
             (pure (and effect-free (expr-pure func) (every #'expr-pure args-code))))
        (when (or valuep (not effect-free))
          (cond ((typep func 'primop)
                 (cond ((and pure (primop-folder func))
                        (funcall (primop-folder func) args-code tailp))
                       ((funcall (primop-papplicable-p func) args-code)
                        (with-return-wrapped-if tailp
                          (funcall (primop-papplicator func) args-code)))
                       (t
                        (with-return-wrapped-if tailp
                          (funcall (primop-instantiator func) func valuep args args-code)))))
                (t
                 (when (and (boundp '*compiled-function*)
                            (func-leafp *compiled-function*))
                   (compiler-note "degrading ~S to non-leaf" *compiled-function*)
                   (setf (func-leafp *compiled-function*) nil))
                 (make-instance 'expr :effect-free effect-free :pure pure :value-used valuep :env lexenv
                                :type (if (and (boundp '*compiled-function*)
                                               (eq func *compiled-function*))
                                          nil
                                          (expr-type func))
                                :branching :funcall
                                :form `(,fname ,@args)
                                :code (let ((ret-label (gensym (concatenate 'string "BACK-FROM-" (symbol-name fname)))))
                                        (append (iter (for arg-code in args-code)
                                                      (for i from 0)
                                                      (collect (make-instance 'expr :effect-free nil :pure nil :value-used t :env lexenv
                                                                              :type (expr-type arg-code) :form `(funarg-set ,i ,(expr-form arg-code))
                                                                              :code
                                                                              (append (list arg-code)
                                                                                      (emit-funarg-set i)))))
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
             (effect-free (and (null for-effect) (expr-effect-free for-value)))
             (pure (and effect-free (expr-pure for-value))))
        (when (or valuep (not effect-free))
          (make-instance 'expr :effect-free effect-free :pure pure :value-used valuep :env lexenv
                         :type (expr-type for-value) :form `(progn ,@expr)
                         :branching (cond ((find :funcall for-effect :key #'expr-branching) :funcall)
                                          ((find :tail for-effect :key #'expr-branching) :non-tail)
                                          ((find :non-tail for-effect :key #'expr-branching) :non-tail)
                                          (for-value (expr-branching for-value)))
                         :code
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
           (effect-free (every #'expr-effect-free (cons body-code binding-value-code)))
           (pure (and effect-free (every #'expr-pure (cons body-code binding-value-code)))))
      (when (or valuep (not effect-free))
        (make-instance 'expr :effect-free effect-free :pure pure :value-used valuep :env lexenv
                       :type (expr-type body-code) :form `(let ,bindings ,@body)
                       :branching (cond ((find :funcall binding-value-code :key #'expr-branching) :funcall)
                                        ((find :tail binding-value-code :key #'expr-branching) :non-tail)
                                        ((find :non-tail binding-value-code :key #'expr-branching) :non-tail)
                                        (t (expr-branching body-code)))
                       :code
                       (append (iter (for var in vars)
                                     (collect (compile-variable-set (var-name var) (var-expr var) compenv new-lexenv nil nil)))
                               (list body-code)))))))

;;;
;;;   At this point we're past the fist pass, namely conversion of code
;;; into soup of PRIMOPs, carrying concrete details of:
;;;   - amount of required inputs and outputs, and
;;;   - expansion on specific architecture;
;;; and EXPR tree nodes, qualifying subtrees with:
;;;   - effect-fulness or, perhapes even purity, and
;;;   - type information.
;;;
;;;   Important invariants, simplifying (but, probably, not precluding)
;;; interpretation of the tree, are:
;;;   - dependencies are EXPR-local, i.e. EXPRs cannot have dependencies.
;;;   - whenever a VOP has dependencies, it must be the last one in its
;;; parent's EXPR CODE sequence;
;;;   - at the point of that particular VOP's occurence the amount of
;;; outstanding DF sticks must be equal to the amount of VOP's dependencies.
;;;
;;;   As it stands, EXPR's CODE sequences fall into two types:
;;;   - those ending with a producing VOP or EXPR, described above.
;;; Such entries will mark their parent EXPR as a DF producer.
;;;   - EXPRs which always have a zero DF producer count in their CODE
;;; sequence.
;;;
(defun build-data-flow-graph (parent soup consumer acc-producers)
  (etypecase soup
    (vop
     (unless (or consumer (zerop (vop-nargs soup)))
       (error "~@<Starved VOP ~S in ~S: requires ~D arguments, but wasn't marked as consumer.~:@>" soup parent (vop-nargs soup)))
     (when (and consumer (not (= (vop-nargs soup) (length acc-producers))))
       (error "~@<At expression ~S: producer count ~D, but VOP ~S expected ~D.~:@>" parent (length acc-producers) soup (vop-nargs soup)))
     (let ((dfnode (make-instance (compute-df-class (vop-nargs soup) (vop-nvalues soup))
                                  :generator soup
                                  :producers (when consumer acc-producers))))
       (when consumer
         (format t "~@<Consuming ~S.~:@>~%" acc-producers)
         (dolist (producer acc-producers)
           (push dfnode (consumers producer))))
       (format t "~@<VOP ~S returning ~S.~:@>~%" soup (append (when (typep dfnode 'dfproducer)
                                                                (make-list (vop-nvalues soup) :initial-element dfnode))
                                                              (unless consumer acc-producers)))
       (values (append (when (typep dfnode 'dfproducer)
                         (make-list (vop-nvalues soup) :initial-element dfnode))
                       (unless consumer acc-producers))
               dfnode)))
    (expr
     (when consumer
       (error "~@<EXPR ~S was marked as consumer.~:@>" soup))
     ;; Here's the point where we need CFA to perform separate iterations
     ;; on basic block, so as not to conflate BBs producers.
     ;; But if we localize passing to subnodes in branchy-branchy EXPRs,
     ;; shouldn't it justwork?
     (values
      (let (producers)
        (format t "~@<Processing ~S.~:@>~%" soup)
        (setf (expr-df-code soup)
              (iter (for (subsoup . rest-code) on (expr-code soup))
                    (format t "~@<Producers: ~S before sub ~S.~:@>~%" producers subsoup)
                    (multiple-value-bind (new-producers node)
                        (build-data-flow-graph soup subsoup (and (endp rest-code) (typep subsoup 'vop) (plusp (vop-nargs subsoup))) producers)
                      (etypecase node 
                        (dfnode (collect node))
                        (expr (appending (expr-df-code node))))
                      (setf producers new-producers))))
        (format t "~@<Returning ~S.~:@>~%" producers)
        (append producers acc-producers))
      soup))))

;;; NOTE: the expression doesn't contain the label, which must be emitted by the linker.
(defun compile-defun (name lambda-list body compenv)
  (with-noted-sexp-path `(defun ,name ,lambda-list ,@body)
    ;; Make a temporary, incomplete function object for the purpose of recursion, with expression lacking proper code,
    ;; and type being set to t.
    (let ((func (make-instance 'expr-func :name name :nargs (length lambda-list) :lambda-list lambda-list :leafp t :complete nil
                               :expr (make-instance 'expr :effect-free nil :pure nil :value-used t :env nil
                                                    :type t :form `(defun ,name ,lambda-list #:phony) :code nil))))
      (setf (func compenv name) func)
      (multiple-value-bind (docstring declarations body) (destructure-def-body body)
        (declare (ignore docstring))
        (lret ((type-decls (mapcar #'rest (remove-if-not (feq 'type) declarations :key #'car)))
              (*compiled-function* func))
          (declare (special *compiled-function*))
          (setf (func-expr func)
                (compile-let (iter (for arg-name in lambda-list)
                                   (for i from 0)
                                   (collect `(,arg-name (funarg-ref ,i ,(or (first (find name type-decls :key #'rest :test #'member)) t)))))
                             body
                             compenv nil t t)
                (func-complete func) t)
          ;; #+(or)
          (build-data-flow-graph nil (func-expr func) nil nil))))))

(defun compile-if (clauses compenv lexenv valuep tailp)
  (let ((n-args (length clauses)))
    (when (or (< n-args 2)
              (> n-args 3))
      (expr-error "invalid number of elements in IF operator: between 2 and 3 expected")))
  (destructuring-bind (condition then-clause &optional else-clause) clauses
    (let* ((condition-code (compile-expr condition compenv lexenv t nil))
           (then-code (compile-expr then-clause compenv lexenv valuep tailp))
           (else-code (if else-clause
                          (compile-expr else-clause compenv lexenv valuep tailp)
                          (compile-constant nil valuep tailp)))
           (effect-free (every #'expr-effect-free (list condition-code then-code else-code)))
           (pure (and effect-free (every #'expr-pure (list condition-code then-code else-code)))))
      (when (or valuep effect-free)
        (with-noted-sexp-path 'if
          (cond ((null condition) else-code)
                ((constant-p condition) then-code)
                ((equalp then-clause else-clause) (compile-progn `(,condition ,then-clause) compenv lexenv valuep tailp))
                ((and (= 2 (length condition)) (eq (first condition) 'not))
                 (compile-if `(if ,(second condition) ,then-clause ,else-clause) compenv lexenv valuep tailp))
                (t
                 (make-instance 'expr :effect-free effect-free :pure pure :value-used valuep :env lexenv
                                :type (comp-simplify-logical-expression `(or ,(expr-type then-code) ,(expr-type else-code)))
                                :form `(if ,condition ,then-clause ,@(when else-clause `(,else-clause)))
                                :branching (if (find :funcall (list condition-code then-code else-code) :key #'expr-branching)
                                               :funcall
                                               :non-tail)
                                :code
                                (let ((else-label (gensym (concatenate 'string "IF-NOT")))
                                      (end-label (gensym (concatenate 'string "IF-END"))))
                                  (append (list (make-instance 'expr :effect-free (expr-effect-free condition-code) :pure (expr-pure condition-code)
                                                               :value-used t :env lexenv
                                                               :type 'boolean :form condition
                                                               :code
                                                               (append (list condition-code)
                                                                       (emit-jump-if-not else-label))))
                                          (list then-code)
                                          (unless tailp
                                            (emit-jump end-label))
                                          (emit-label else-label)
                                          (list else-code)
                                          (unless tailp
                                            (emit-label end-label))))))))))))

(defun compile-expr (expr compenv lexenv valuep tailp)
  (when *comp-verbose*
    (compiler-note "compiling ~S" expr))
  (cond ((constant-p expr) (compile-constant expr valuep tailp))
        ((symbolp expr) (compile-variable-ref expr lexenv valuep tailp))
        ((atom expr)
         (expr-error "atom ~S has unsupported type ~S" expr (type-of expr)))
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
  (compiler-note "compiling toplevel: ~S" expr)
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
            (when (func compenv op :if-does-not-exist :continue)
              (comp-error "~@<In DEFMACRO: ~S already defined as function.~:@>" op))
            (destructuring-bind (name lambda-list &body body) (rest expr)
              (setf (macro compenv name) (compile nil `(lambda ,lambda-list ,@body))))
          nil)
        (defun
            (when (macro compenv op :if-does-not-exist :continue)
              (expr-error "~@<In DEFUN: ~S already defined as macro.~:@>" op))
            (destructuring-bind (name lambda-list &body body) (rest expr)
              (compile-defun name lambda-list body compenv)))
        (t
         (if-let ((macro (macro compenv op :if-does-not-exist :continue)))
           (with-noted-sexp-path `(defmacro ,op)
             (compile-toplevel (apply macro (rest expr)) compenv))
           (compile-expr expr compenv nil nil nil)))))))

(defparameter *test-code* `((defun flash-write-abs (absolute-addr value)
                              (mem-set absolute-addr 0
                                       (logior (ash value 0)
                                               (ash value 16))))
                            (defun flash-write (flash-base offset value)
                              (mem-set (+ flash-base (ash offset 2)) 0
                                       (logior (ash value 0)
                                               (ash value 16))))
                            (defun issue-command-abs (flash-base absolute-addr command)
                              (flash-write flash-base #x555 #xaa)
                              (flash-write flash-base #x2aa #x55)
                              (flash-write-abs absolute-addr command))
                            (defun issue-command (flash-base offset command)
                              (flash-write flash-base #x555 #xaa)
                              (flash-write flash-base #x2aa #x55)
                              (flash-write flash-base offset command))
                            (defun poll-toggle-ready (absolute-addr iterations-left)
                              (if (= 0 iterations-left)
                                  nil
                                  (if (= (logand #x40 (mem-ref-impure absolute-addr 0))
                                         (logand #x40 (mem-ref-impure absolute-addr 0)))
                                      t
                                      (poll-toggle-ready absolute-addr (- iterations-left 1)))))
                            (defun poll-ds7 (absolute-addr iterations-left)
                              (if (= 0 iterations-left)
                                  nil
                                  (if (/= 0 (logand #x80 (mem-ref-impure absolute-addr 0)))
                                      t
                                      (poll-ds7  absolute-addr (- iterations-left 1)))))
                            (defun program-word (flash-base absolute-addr value)
                              (issue-command flash-base #x555 ,#xa0 #+nil (bits :amd-opcode :word-program))
                              (mem-set absolute-addr 0 value)
                              (poll-toggle-ready absolute-addr #x7ffffff))
                            (defun program-region (flash-base dest src word-count)
                              (if (= 0 word-count)
                                  nil
                                  (progn
                                    (program-word flash-base dest (mem-ref src 0))
                                    (program-region flash-base (+ dest 4) (+ src 4) (- word-count 1)))))
                            (defun erase-sector (flash-base absolute-sector-address)
                              (issue-command flash-base #x555 ,#x80 #+nil (bits :amd-opcode :cyc1-erase))
                              (issue-command-abs flash-base absolute-sector-address ,#x50 #+nil (bits :amd-opcode :cyc2-erase-sector))
                              (poll-toggle-ready absolute-sector-address #x7ffffff))
                            (defun erase-block (flash-base absolute-block-address)
                              (issue-command flash-base #x555 ,#x80 #+nil (bits :amd-opcode :cyc1-erase))
                              (issue-command-abs flash-base absolute-block-address ,#x30 #+nil (bits :amd-opcode :cyc2-erase-block))
                              (poll-toggle-ready absolute-block-address #x7ffffff))
                            (defun erase-chip (flash-base)
                              (issue-command flash-base #x555 ,#x80 #+nil (bits :amd-opcode :cyc1-erase))
                              (issue-command flash-base 0 ,#x10 #+nil (bits :amd-opcode :cyc2-erase-chip))
                              (poll-ds7 flash-base #x7ffffff))))

#+(or)
(let ((compenv (make-instance 'compenv)))
  (dolist (component (subseq  *test-code* 0))
    (let ((result (compile-toplevel component compenv)))
      (compiler-note "got: ~S" result)
      (when (typep result 'expr-func)
        (compiler-note "IR1 tree: ~S" (func-expr result))))))