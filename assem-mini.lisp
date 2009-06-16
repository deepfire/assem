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
   (current-index :type (unsigned-byte 32) :initform 0)))

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

(defun %emit32le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word32le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 4))

(defun %emit64le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word64le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 8))

(defmacro with-optype-allocator (optype &body body)
  `(with-allocator (,optype ',(asm:optype-allocatables (asm:optype optype)))
     ,@body))

(defun eval-insn (isa optype insn)
  (flet ((subst-variable (iargs iargvar)
           (subst (eval-allocated optype iargvar) iargvar iargs)))
    (destructuring-bind (opcode &rest iargs) insn
      (cons opcode (reduce #'subst-variable (asm:insn-optype-variables isa optype insn) :initial-value iargs)))))

(defvar *isa* nil)
(defvar *optype* nil)
(defvar *segment* nil)

(defmacro with-segment-emission ((isa &optional (segment '(make-instance 'segment))) (optype &rest bound-set) &body body)
  (when (and bound-set (not optype))
    (asm:assembly-error "~@<Requested to bind allocatables with no pool specified.~:@>"))
  (multiple-value-bind (decls body) (destructure-binding-form-body body)
    `(lret ((*isa* ,isa)
            (*optype* ',optype)
            (*segment* ,segment))
       (declare (special *isa* *optype* *segment*))
       (with-optype-allocator ,optype
         (allocate-let (',optype ,@bound-set)
           ,@(when decls `((declare ,@decls)))
           (flet ((emitted-insn-count () (/ (segment-current-index *segment*) 4)))
             (declare (ignorable #'emitted-insn-count))
             ,@body))))))

(defun emit (insn)
  (declare (special *isa* *optype* *segment*))
  (%emit32le *segment* (asm:encode-insn *isa* (eval-insn *isa* *optype* insn))))

(defun emit* (&rest insn)
  (declare (special *isa* *optype* *segment* *lexicals*))
  (%emit32le *segment* (asm:encode-insn *isa* (eval-insn *isa* *optype* insn))))

(defun segment-active-vector (segment)
  (declare (type segment segment))
  (subseq (segment-data segment) 0 (segment-current-index segment)))

(defun segment-disassemble (isa segment)
  (declare (type segment segment))
  (asm:disassemble isa (segment-active-vector segment)))

(defun segment-instruction-count (segment)
  (ash (segment-current-index segment) -2))

(defun extent-list-adjoin-segment (extent-list address segment)
  (extent-list-adjoin* extent-list 'extent (segment-active-vector segment) address))

(defmacro with-extentable-segment ((isa extentable addr) (optype &rest bound-set) &body body)
  (with-gensyms (segment)
    `(lret ((,segment (with-segment-emission (,isa) (,optype ,@bound-set)
                        ,@body)))
       (setf (extentable-u8-vector ,extentable ,addr) (segment-active-vector ,segment)))))