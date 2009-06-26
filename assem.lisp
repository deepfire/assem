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
(defvar *isa* nil)
(defvar *optype* nil)
(defvar *tag-domain* nil)
(defvar *segment* nil)

(defmacro with-optype-pool ((isa optype) &body body)
  `(let* ((*isa* ,isa)
          (*optype* (optype *isa* ',optype)))
     (declare (special *isa* *optype*))
     (with-environment (',optype (make-top-level-pool (optype-allocatables *optype*)))
       ,@body)))

(defun eval-insn (env insn)
  (flet ((evaluate-and-subst-one-variable (iargs iargvar)
           (subst (evaluate env iargvar) iargvar iargs)))
    (destructuring-bind (opcode &rest iargs) insn
      (cons opcode (reduce #'evaluate-and-subst-one-variable (insn-optype-variables *isa* *optype* insn) :initial-value iargs)))))

(defmacro with-tag-domain (&body body)
  `(let ((*tag-domain* (make-top-level-tracker)))
     (declare (special *tag-domain*))
     (with-environment ('tags *tag-domain*)
       ,@body)))

(defun %add-global-tag (tag-env name address)
  (tracker-add-global-key-value-and-finalizer tag-env name #'values address))

(defun %emit-global-tag (tag-env name)
  (tracker-add-global-key-value-and-finalizer tag-env name (make-tag-backpatcher tag-env name) (current-insn-count)))

(defun %emit-tag (tag-env name)
  (tracker-set-key-value-and-finalizer tag-env name (make-tag-backpatcher tag-env name) (current-insn-count)))

(defun %map-tags (tag-env fn)
  (map-tracked-keys tag-env fn))

(defun add-global-tag (name address)
  (tracker-add-global-key-value-and-finalizer *tag-domain* name #'values address))

(defun emit-global-tag (name)
  (tracker-add-global-key-value-and-finalizer *tag-domain* name (make-tag-backpatcher *tag-domain* name) (current-insn-count)))

(defun emit-tag (name)
  (tracker-set-key-value-and-finalizer *tag-domain* name (make-tag-backpatcher *tag-domain* name) (current-insn-count)))

(defun map-tags (fn)
  (map-tracked-keys *tag-domain* fn))

(defmacro with-tags ((tag-env &rest tags) &body body)
  `(with-tracked-set (,tag-env ,@tags)
     ,@body))

(defmacro with-assembly ((isa optype) &body body)
  `(with-metaenvironment
     (with-optype-pool (,isa ,optype)
       (with-tag-domain
           ,@body))))

(defmacro with-segment-emission ((isa &optional (segment '(make-instance 'segment))) optype (&rest tags) &body body)
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(lret ((*segment* ,segment))
       (declare (special *segment*))
       (with-assembly (,isa ,optype)
         (with-tags (*tag-domain* ,@tags)
           ,@(when decls `((declare ,@decls)))
           ,@body)))))

(defun make-tag-backpatcher (tag-env tag-name)
  (declare (special *segment*))
  (lambda (tag-insn-nr)
    (map-tracker-key-references
     tag-env tag-name
     (lambda (reference-value)
       (destructuring-bind (referencer-insn-nr . reference-emitter) reference-value
         (setf (u8-vector-word32le (segment-data *segment*) (* 4 referencer-insn-nr))
               (funcall reference-emitter (- referencer-insn-nr tag-insn-nr))))))))

(defun current-insn-count ()
  (segment-emitted-insn-count *segment*))

(defun current-insn-addr ()
  (+ (pinned-segment-base *segment*) (length (segment-active-vector *segment*))))

(defun backpatch-outstanding-global-tag-references (tag-env)
  (map-tracked-keys tag-env (curry #'tracker-release-key-and-process-references tag-env)))

;;;
;;; Compilation environment
;;;
(defclass compilation-environment ()
  ((isa :accessor cenv-isa :initarg :isa)
   (optype :accessor cenv-optype :initarg :optype)
   (segments :accessor cenv-segments :initarg :segments)
   (cellenv :accessor cenv-cellenv :initarg :cellenv)
   (tagenv :accessor cenv-tagenv :initarg :tagenv)))

(defmacro with-compilation-environment (cenv &body body)
  (once-only (cenv)
    `(let ((*compilation-environment* ,cenv)
           (*isa* (cenv-isa ,cenv))
           (*optype* (cenv-optype ,cenv)))
       (declare (special *compilation-environment* *isa* *optype*))
       (with-environment ((optype-name *optype*) (cenv-env *compilation-environment*))
         ,@body))))

(defun save-compilation-environment (cellenv tagenv)
  (make-instance 'compilation-environment
                 :isa *isa*
                 :optype *optype*
                 :segments (list *segment*)
                 :cellenv cellenv
                 :tagenv tagenv))

;;;
;;; Misc
;;;
(defun extent-list-adjoin-segment (extent-list address segment)
  (extent-list-adjoin* extent-list 'extent (segment-active-vector segment) address))

(defmacro with-extentable-segment ((isa extentable addr) optype (&rest tags) &body body)
  (with-gensyms (retcell segment ret)
    (once-only (addr)
      `(lret* (,retcell
               (,segment (with-segment-emission (,isa (make-instance 'pinned-segment :base ,addr)) ,optype (,@tags)
                           ,@(butlast body)
                           (setf ,retcell ,(lastcar body))))
               (,ret ,retcell))
         (setf (extentable-u8-vector ,extentable ,addr) (segment-active-vector ,segment))))))
