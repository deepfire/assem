;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEM-MINI; Base: 10 -*-
;;;
;;;  (c) copyright 2006-2008 by
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

(in-package :assem)


;;;
;;; Address space
;;;
(defclass address-space ()
  ((extent :reader as-extent :initarg :extent)
   (code :reader as-code :initarg :code)
   (data :reader as-data :initarg :data)
   (stack :reader as-stack :initarg :stack)))

;;; XXX: hardwired 4
(defmethod initialize-instance :after ((o address-space) &key extent code stack (stack-allocation #x100) &allow-other-keys)
  (setf (slot-value o 'code) (or code extent)
        (slot-value o 'data) (cons 0 0)
        (slot-value o 'stack) (or stack (extent (- (end extent) 4) stack-allocation))))

;;;
;;; Segment
;;;
(defclass segment ()
  ((data :accessor segment-data :initform (make-array 1024 :element-type '(unsigned-byte 8) :adjustable t :initial-element 0))
   (current-index :type (unsigned-byte 32) :initform 0)
   (emitted-insn-count :accessor segment-emitted-insn-count :initform 0)))

(defclass pinned-segment (segment)
  ((base :accessor pinned-segment-base :type (integer 0) :initarg :base)))

(defun segment-current-index (segment)
  (declare (type segment segment))
  (slot-value segment 'current-index))

(defun (setf segment-current-index) (new-value segment)
  (declare (type (unsigned-byte 32) new-value) (type segment segment))
  (let ((current (array-dimension (segment-data segment) 0)))
    (when (>= new-value current)
      (setf (segment-data segment)
            (adjust-array (segment-data segment)
                          (ash current (- (integer-length new-value) (integer-length current) -1))))))
  (setf (slot-value segment 'current-index) new-value))

(defun segment-active-vector (segment)
  (declare (type segment segment))
  (subseq (segment-data segment) 0 (segment-current-index segment)))

(defun segment-disassemble (isa segment)
  (declare (type segment segment))
  (disassemble isa (segment-active-vector segment)))

(defun upload-segment (bioable segment)
  (write-block bioable (pinned-segment-base segment) (segment-active-vector segment)))

;;;
;;; Environment-based evaluation and emission
;;;
(defvar *isa*)

(defmacro with-optype-pool ((isa optype) &body body)
  "The only custom optype syntactic hook."
  `(let* ((*isa* ,isa))
     (declare (special *isa*))
     (with-environment ((optype-name ,optype) (make-pool-backed-frame-chain (optype-allocatables ,optype)))
       ,@body)))

;;;
;;; Tag environment
;;;
(defvar *tag-domain*)

(defclass tag-environment (frame-chain immutable-environment)
  ((global-frame :accessor env-global-frame)
   (functions :accessor env-functions :initform (make-hash-table :test 'eq))
   (forward-references :accessor env-forward-references :initform nil)))

(defmethod copy-environment-to :after ((to tag-environment) (from tag-environment))
  (setf (env-global-frame to) (env-global-frame from)
        (env-functions to) (env-functions from)
        (env-forward-references to) (env-forward-references from)))

(defstruct envobject
  (name nil :type symbol)
  (cell-env nil :type (or null pool-backed-frame-chain)))

(defstruct (segpoint (:include envobject))
  (segment nil :type pinned-segment)
  (offset nil :type unsigned-byte)
  (insn-nr nil :type unsigned-byte))

(defun segpoint-address (segpoint)
  (declare (type segpoint segpoint))
  (+ (pinned-segment-base (segpoint-segment segpoint)) (segpoint-offset segpoint)))

(defstruct (tag (:include segpoint) (:constructor make-tag (name segment offset insn-nr finalizer)))
  (finalizer nil :type (function (tag) (values)))
  (references nil :type list))

(defstruct (func (:include envobject))
  (tag nil :type (or null tag))
  (emitter nil :type (or null function)))

(defstruct (ref (:include segpoint) (:constructor make-ref (name cell-env segment offset insn-nr emitter func)))
  (func nil :type (or null func))
  (emitter nil :type (function (pool-backed-frame-chain unsigned-byte unsigned-byte) unsigned-byte)))

(define-subcontainer func :container-slot functions :if-exists :error)

(defvar *function*)

(defun define-function (tag-env name emitter)
  (lret ((func (make-func :name name)))
    (setf (func-emitter func) (lambda ()
                                (let ((*function* func))
                                  (declare (special *function*))
                                  (funcall emitter)))
          (func tag-env name) func)))

(defun current-function ()
  (when (boundp '*function*)
    *function*))

(defun emit-function (tag-env func)
  (setf (func-tag func) (%emit-global-tag tag-env (func-name func)))
  (funcall (func-emitter func)))

(defmacro with-function-definition-and-emission (tag-env name &body body)
  `(emit-function ,tag-env (define-function ,tag-env ,name (lambda () ,@body))))

(defun eval-insn (env insn)
  (flet ((evaluate-and-subst-one-variable (iargs iargvar)
           (multiple-value-bind (result bound-p) (pool-evaluate env iargvar)
             (unless bound-p
               (error "~@<In definition of ~:[#<ANONYMOUS-CODE>~;~:*~S~]: ~S is not bound.~:@>" (current-function) iargvar))
             (subst result iargvar iargs))))
    (destructuring-bind (opcode &rest iargs) insn
      (cons opcode (reduce #'evaluate-and-subst-one-variable (insn-optype-variables *isa* (isa-gpr-optype *isa*) insn) :initial-value iargs)))))

(defun %emit-ref (tag-env cell-env segment name insn-emitter)
  (lret ((ref (make-ref name (copy-environment cell-env) segment (current-segment-offset) (current-insn-count) insn-emitter (current-function))))
    (if-let ((tag (do-lookup tag-env name)))
      (push ref (tag-references tag))
      (push ref (env-forward-references tag-env)))))

(defun relink-forward-references (tag-env)
  "Find tag matches for outstanding forward references in TAG-ENV, 
thus clearing them.
BUG: local tags can overthrow globals: first come first served.
Will lead to hard-to-diagnose, strange bugs."
  (iter (for ref in (env-forward-references tag-env))
        (for tag = (do-lookup tag-env (ref-name ref)))
        (when tag
          (push ref (tag-references tag))
          (collect ref into defined-refs))
        (finally
         (nset-differencef (env-forward-references tag-env) defined-refs))))

(defun note-tag-domain-forward-references (tag-env)
  "Warn about forward references outstanding in TAG-ENV."
  (when-let ((undefined-refs (env-forward-references tag-env)))
    (when-let ((anons (remove nil undefined-refs :key #'ref-func :test-not #'eq)))
      (format t "~@<WARNING: In anonymous code: undefined referred tags were referred:~{ ~S~}.~:@>" (mapcar #'ref-name anons)))
    (dolist (referrer-func (remove-duplicates (mapcar #'ref-func undefined-refs)))
      (format t "~@<WARNING: In definition of ~S: undefined tags were referred:~{ ~S~}.~:@>"
              (func-name referrer-func) (mapcar #'ref-name (remove referrer-func undefined-refs :key #'ref-func :test-not #'eq))))))

(defun finalize-frame (tag-env frame warn-on-forward-refs)
  ;; The line below could be sped up by tracking forward refs locally, only
  ;; promoting them to global forwards here.
  (relink-forward-references tag-env)
  (when warn-on-forward-refs
    (note-tag-domain-forward-references tag-env))
  (do-frame-bindings (nil tag) frame
    (assert tag)
    (funcall (tag-finalizer tag) tag)))

(defmacro with-tag-domain (&body body)
  (with-gensyms (global-frame)
    `(let ((*tag-domain* (make-instance 'tag-environment)))
       (declare (special *tag-domain*))
       (multiple-value-prog1
           (with-environment ('tags *tag-domain*)
             (with-fresh-frame (*tag-domain* ,global-frame)
               (setf (env-global-frame *tag-domain*) ,global-frame)
               (unwind-protect (progn ,@body)
                 (finalize-frame *tag-domain* ,global-frame t))))))))

(defmacro with-tags (tag-env &body body)
  (with-gensyms (frame)
    (once-only (tag-env)
      `(with-fresh-frame (,tag-env ,frame)
         (unwind-protect (progn ,@body)
           (finalize-frame ,tag-env ,frame nil))))))

(defun maybe-invoke-with-assem (wrap-p isa fn)
  (if (not wrap-p)
      (funcall fn)
      (with-metaenvironment
        (with-optype-pool (isa (isa-gpr-optype isa))
          (with-tag-domain
            (funcall fn))))))

(defun invoke-with-assem-ensured (isa fn)
  (maybe-invoke-with-assem (not (boundp '*tag-domain*)) isa fn))

(defmacro with-ensured-assem (isa &body body)
  `(invoke-with-assem-ensured ,isa (lambda () ,@body)))

;;;
;;; Segment emission
;;;
(defvar *segment*)

(defmacro with-segment-emission ((isa &optional (segment '(make-instance 'segment))) &body body)
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(lret ((*segment* ,segment))
       (declare (special *segment*))
       (with-ensured-assem ,isa
         ,@(when decls `((declare ,@decls)))
         ,@body))))

(defun current-insn-count ()
  (segment-emitted-insn-count *segment*))

(defun current-segment-offset ()
  (length (segment-active-vector *segment*)))

(defun current-absolute-addr ()
  (+ (pinned-segment-base *segment*) (length (segment-active-vector *segment*))))

(defun backpatch-tag-reference (tag ref)
  (setf (u8-vector-word32le (segment-data (ref-segment ref)) (ref-offset ref))
        (funcall (ref-emitter ref) (ref-cell-env ref) (- (ref-offset ref) (tag-offset tag)) (- (ref-insn-nr ref) (tag-insn-nr tag)))))

(defun backpatch-tag-references (tag)
  (mapc (curry #'backpatch-tag-reference tag) (tag-references tag)))

(defun %emit-tag (tag-env name)
  (lret ((tag (make-tag name *segment* (current-segment-offset) (current-insn-count) #'backpatch-tag-references)))
    (bind tag-env name tag)))

(defun %emit-global-tag (tag-env name)
  (lret ((tag (make-tag name *segment* (current-segment-offset) (current-insn-count) #'backpatch-tag-references)))
    (bind (env-global-frame tag-env) name tag)))

;;;
;;; Environment-relative tag
;;;
(defun emit-tag (name)
  (%emit-tag *tag-domain* name))

(defun emit-global-tag (name)
  (%emit-global-tag *tag-domain* name))

(defun find-tag (name)
  (lookup *tag-domain* name))

(defun tag-address (tag-or-name)
  (segpoint-address (xform-if-not #'tag-p #'find-tag tag-or-name)))

;;;
;;; Compilation environment
;;;
(defclass compilation-environment ()
  ((isa :accessor cenv-isa :initarg :isa)
   (segments :accessor cenv-segments :initarg :segments)
   (cellenv :accessor cenv-cellenv :initarg :cellenv)
   (tagenv :accessor cenv-tagenv :initarg :tagenv)))

(defmacro with-compilation-environment (cenv &body body)
  `(let* ((*compilation-environment* ,cenv)
          (*isa* (cenv-isa *compilation-environment*))
          (*tag-domain* (cenv-tagenv *compilation-environment*)))
     (declare (special *compilation-environment* *isa* *tag-domain*))
     (with-metaenvironment
       (with-environment ((optype-name (isa-gpr-optype *isa*)) (cenv-cellenv *compilation-environment*))
         (with-environment ('tags (cenv-tagenv *compilation-environment*))
           ,@body)))))

(defun save-compilation-environment (cellenv tagenv)
  (make-instance 'compilation-environment
                 :isa *isa*
                 :segments (list *segment*)
                 :cellenv (copy-environment cellenv)
                 :tagenv (copy-environment tagenv)))
