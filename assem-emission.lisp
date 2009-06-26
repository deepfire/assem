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

(defun add-global-tag (tag-env name address)
  (tracker-add-global-key-value-and-finalizer tag-env name #'values address))

(defun emit-global-tag (tag-env name)
  (tracker-add-global-key-value-and-finalizer tag-env name (make-tag-backpatcher tag-env name) (current-insn-count)))

(defun emit-tag (tag-env name)
  (tracker-set-key-value-and-finalizer tag-env name (make-tag-backpatcher tag-env name) (current-insn-count)))

(defun map-tags (tag-env fn)
  (map-tracked-keys tag-env fn))

(defmacro emit-ref (tag-env name (delta-var-name) &body insn)
  (with-gensyms (delta)
    `(tracker-reference-key ,tag-env ',name (cons (segment-emitted-insn-count *segment*)
                                                  (lambda (,delta &aux (,delta-var-name (logand (- #xffff ,delta) #xffff)))
                                                    (declare (type (signed-byte 16) ,delta))
                                                    (encode-insn *isa* (list ,@insn)))))))

(defun emit (env insn)
  (declare (special *isa* *optype* *segment*))
  (%emit32le *segment* (encode-insn *isa* (eval-insn env insn)))
  (incf (segment-emitted-insn-count *segment*)))

(defun emit* (env &rest insn)
  (declare (special *isa* *optype* *segment* *lexicals*))
  (%emit32le *segment* (encode-insn *isa* (eval-insn env insn)))
  (incf (segment-emitted-insn-count *segment*)))
