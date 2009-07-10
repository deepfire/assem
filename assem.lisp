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

;;;
;;; Environment-based evaluation and emission
;;;
(defvar *isa*)

(defmacro with-optype-pool ((isa optype) &body body)
  "The only custom optype syntactic hook."
  `(let* ((*isa* ,isa))
     (declare (special *isa*))
     (with-environment ((optype-name ,optype) (make-dynamic-pool (optype-allocatables ,optype)))
       ,@body)))

(defun eval-insn (env insn)
  (flet ((evaluate-and-subst-one-variable (iargs iargvar)
           (subst (evaluate-dynamic env iargvar) iargvar iargs)))
    (destructuring-bind (opcode &rest iargs) insn
      (cons opcode (reduce #'evaluate-and-subst-one-variable (insn-optype-variables *isa* (isa-gpr-optype *isa*) insn) :initial-value iargs)))))

;;;
;;; Tag environment
;;;
(defvar *tag-domain*)

(defclass tag-environment (dynamic-environment hash-table-environment) ())

(defmacro with-tag-domain (&body body)
  `(let ((*tag-domain* (make-instance 'tag-environment)))
     (declare (special *tag-domain*))
     (with-environment ('tags *tag-domain*)
       ,@body)))

(defmacro with-assem (isa &body body)
  (once-only (isa)
    `(with-metaenvironment
       (with-optype-pool (,isa (isa-gpr-optype ,isa))
         (with-tag-domain
           ,@body)))))

(defmethod bind :around ((o tag-environment) (name symbol) value)
  (when (name-bound-p o name)
    (error 'environment-name-already-bound :name name :env o))
  (call-next-method))

(defmethod do-unbind ((o tag-environment) (name symbol))
  (let ((tag (lookup-value o name)))
    (funcall (tag-finalizer tag) tag))
  (call-next-method))

(defmacro with-tags ((tag-env &rest tags) &body body)
  (with-gensyms (specials dynamic-renames globals)
    (once-only (tag-env)
      `(with-dynamic-frame-bindings (,tag-env ,@tags) (,specials ,dynamic-renames)
         (let ((,globals (append ,specials ,dynamic-renames)))
           (unwind-protect
                (progn
                  (mapcar (rcurry (curry #'bind ,tag-env) nil) ,globals)
                  ,@body)
             (mapcar (curry #'do-unbind ,tag-env) ,globals)))))))

;;;
;;; Segment emission
;;;
(defvar *segment*)

(defmacro with-segment-emission ((isa &optional (segment '(make-instance 'segment))) (&rest tags) &body body)
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(lret ((*segment* ,segment))
       (declare (special *segment*))
       (with-assem ,isa
         (with-tags (*tag-domain* ,@tags)
           ,@(when decls `((declare ,@decls)))
           ,@body)))))

(defun current-insn-count ()
  (segment-emitted-insn-count *segment*))

(defun current-segment-offset ()
  (length (segment-active-vector *segment*)))

(defun current-absolute-addr ()
  (+ (pinned-segment-base *segment*) (length (segment-active-vector *segment*))))

(defstruct segpoint
  (name nil :type symbol)
  (env nil :type environment)
  (segment nil :type pinned-segment)
  (offset nil :type unsigned-byte)
  (insn-nr nil :type unsigned-byte))

(defun segpoint-address (segpoint)
  (declare (type segpoint segpoint))
  (+ (pinned-segment-base (segpoint-segment segpoint)) (segpoint-offset segpoint)))

(defstruct (tag (:include segpoint) (:constructor make-tag (name env segment offset insn-nr finalizer)))
  (finalizer nil :type (function (tag) (values)))
  (references nil :type list))
(defstruct (ref (:include segpoint) (:constructor make-ref (name env segment offset insn-nr emitter)))
  (emitter nil :type (function (unsigned-byte unsigned-byte) unsigned-byte)))

(defun backpatch-tag-reference (tag ref)
  (setf (u8-vector-word32le (segment-data (ref-segment ref)) (ref-offset ref))
        (funcall (ref-emitter ref) (- (ref-offset ref) (tag-offset tag)) (- (ref-insn-nr ref) (tag-insn-nr tag)))))

(defun backpatch-tag-references (tag)
  (mapc (curry #'backpatch-tag-reference tag) (tag-references tag)))

(defun backpatch-outstanding-global-tag-references (tag-env)
  (map-environment tag-env #'backpatch-tag-references))

(defun %emit-global-tag (tag-env name)
  (lret ((tag (make-tag name tag-env *segment* (current-segment-offset) (current-insn-count) #'values)))
    (bind tag-env name tag)))

(defun %emit-tag (tag-env name)
  (lret ((tag (make-tag name tag-env *segment* (current-segment-offset) (current-insn-count) #'backpatch-tag-references)))
    (set-dynamic tag-env name tag)))

;;;
;;; Environment-relative tag
;;;
(defun emit-global-tag (name)
  (%emit-global-tag *tag-domain* name))

(defun emit-tag (name)
  (%emit-tag *tag-domain* name))

(defun tag-address (name)
  (segpoint-address (evaluate-dynamic *tag-domain* name)))

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
     (declare (special *compilation-environment* *isa*))
     (with-metaenvironment
       (with-environment ((optype-name (isa-gpr-optype *isa*)) (cenv-cellenv *compilation-environment*))
         (with-environment ('tags (cenv-tagenv *compilation-environment*))
           ,@body)))))

(defun save-compilation-environment (cellenv tagenv)
  (make-instance 'compilation-environment
                 :isa *isa*
                 :segments (list *segment*)
                 :cellenv cellenv
                 :tagenv tagenv))

;;;
;;; Misc
;;;
(defun extent-list-adjoin-segment (extent-list address segment)
  (extent-list-adjoin* extent-list 'extent (segment-active-vector segment) address))

(defmacro with-extentable-segment ((isa extentable addr) (&rest tags) &body body)
  (with-gensyms (retcell segment ret)
    (once-only (addr)
      `(lret* (,retcell
               (,segment (with-segment-emission (,isa (make-instance 'pinned-segment :base ,addr)) (,@tags)
                           ,@(butlast body)
                           (setf ,retcell ,(lastcar body))))
               (,ret ,retcell))
         (setf (extentable-u8-vector ,extentable ,addr) (segment-active-vector ,segment))))))
