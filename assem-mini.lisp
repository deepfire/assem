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

(in-package :assem-mini)

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
  (asm:disassemble isa (segment-active-vector segment)))

(defun %emit32le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word32le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 4))

(defun %emit64le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word64le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 8))

(defmacro with-optype-allocator ((isa optype) &body body)
  `(with-allocator (,optype (asm:optype-allocatables (asm:optype ,isa ',optype)))
     ,@body))

(defun optype-key-allocation (optype optype-var)
  (eval-allocated optype optype-var))

(defun eval-insn (isa optype insn)
  (flet ((subst-variable (iargs iargvar)
           (subst (eval-allocated optype iargvar) iargvar iargs)))
    (destructuring-bind (opcode &rest iargs) insn
      (cons opcode (reduce #'subst-variable (asm:insn-optype-variables isa optype insn) :initial-value iargs)))))

(defmacro with-tags ((&rest tags) &body body)
  `(tracker-let (tags ,@tags)
     ,@body))

(defmacro with-tag-domain ((&rest tags) &body body)
  `(with-tracker tags
     (with-tags ,tags
       ,@body)))

(defvar *isa* nil)
(defvar *optype* nil)
(defvar *segment* nil)

(defun make-tag-backpatcher (tag-name)
  (declare (special *segment*))
  (lambda (tag-insn-nr)
    (map-tracker-key-references
     'tags tag-name
     (lambda (reference-value)
       (destructuring-bind (referencer-insn-nr . reference-emitter) reference-value
         (setf (u8-vector-word32le (segment-data *segment*) (* 4 referencer-insn-nr))
               (funcall reference-emitter (- referencer-insn-nr tag-insn-nr))))))))

(defun add-global-tag (name address)
  (tracker-add-global-key-value-and-finalizer 'tags name #'values address))

(defun emit-global-tag (name)
  (tracker-add-global-key-value-and-finalizer 'tags name (make-tag-backpatcher name) (current-insn-count)))

(defun backpatch-outstanding-global-tag-references ()
  (map-tracked-keys 'tags (curry #'tracker-release-key-and-process-references 'tags)))

(defun emit-tag (name)
  (tracker-set-key-value-and-finalizer 'tags name (make-tag-backpatcher name) (current-insn-count)))

(defun map-tags (fn)
  (map-tracked-keys 'tags fn))

(defmacro emit-ref (name (delta-var-name) &body insn)
  (with-gensyms (delta)
    `(tracker-reference-key 'tags ,name (cons (segment-emitted-insn-count *segment*)
                                              (lambda (,delta &aux (,delta-var-name (logand (- #xffff ,delta) #xffff)))
                                                (declare (type (signed-byte 16) ,delta))
                                                (asm:encode-insn *isa* (list ,@insn)))))))

(defmacro with-assem ((isa optype) &body body)
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(let ((*isa* ,isa)
           (*optype* ',optype))
       (declare (special *isa* *optype*))
       (with-optype-allocator (*isa* ,optype)
         (with-tag-domain ()
           ,@body)))))

(defmacro with-segment-emission ((isa &optional (segment '(make-instance 'segment))) optype (&rest tags) &body body)
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(lret ((*segment* ,segment))
       (declare (special *segment*))
       (with-assem (,isa ,optype)
         (with-tags (,@tags)
           ,@(when decls `((declare ,@decls)))
           ,@body)))))

(defun emit (insn)
  (declare (special *isa* *optype* *segment*))
  (%emit32le *segment* (asm:encode-insn *isa* (eval-insn *isa* *optype* insn)))
  (incf (segment-emitted-insn-count *segment*)))

(defun emit* (&rest insn)
  (declare (special *isa* *optype* *segment* *lexicals*))
  (%emit32le *segment* (asm:encode-insn *isa* (eval-insn *isa* *optype* insn)))
  (incf (segment-emitted-insn-count *segment*)))

(defun current-insn-count ()
  (segment-emitted-insn-count *segment*))

(defun current-insn-addr ()
  (+ (pinned-segment-base *segment*) (length (segment-active-vector *segment*))))

;;;
;;; Misc
;;;
(defun extent-list-adjoin-segment (extent-list address segment)
  (extent-list-adjoin* extent-list 'extent (segment-active-vector segment) address))

(defmacro with-extentable-segment ((isa extentable addr) optype (&rest tags) &body body)
  (with-gensyms (segment)
    (once-only (addr)
      `(lret ((,segment (with-segment-emission (,isa (make-instance 'pinned-segment :base ,addr)) ,optype (,@tags)
                          ,@body)))
         (setf (extentable-u8-vector ,extentable ,addr) (segment-active-vector ,segment))))))