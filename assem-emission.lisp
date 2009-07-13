;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEM-EMISSION; Base: 10 -*-
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

(in-package :assem-emission)

(defun %emit32le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word32le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 4))

(defun %emit64le (segment insn)
  (declare (type segment segment))
  (setf (u8-vector-word64le (segment-data segment) (segment-current-index segment)) insn)
  (incf (segment-current-index segment) 8))

(defmacro emit-ref (tag-env name (delta-var-name) &body insn)
  (with-gensyms (tag offset-delta insn-nr-delta)
    (once-only (tag-env name)
      `(let ((,tag (lookup ,tag-env ,name)))
         (push (make-ref ,name ,tag-env *segment* (current-segment-offset) (current-insn-count)
                         (lambda (,offset-delta ,insn-nr-delta &aux (,delta-var-name (logand (- #xffff ,insn-nr-delta) #xffff)))
                           (declare (type (signed-byte 16) ,offset-delta ,insn-nr-delta) (ignorable ,offset-delta))
                           (encode-insn *isa* (list ,@insn))))
               (tag-references ,tag))))))

(defun emit (env insn)
  (declare (special *isa* *optype* *segment*))
  (%emit32le *segment* (encode-insn *isa* (eval-insn env insn)))
  (incf (segment-emitted-insn-count *segment*)))

(defun emit* (env &rest insn)
  (declare (special *isa* *optype* *segment* *lexicals*))
  (%emit32le *segment* (encode-insn *isa* (eval-insn env insn)))
  (incf (segment-emitted-insn-count *segment*)))
