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

(defmacro emit-mips (segment &body body)
  `(emit mips-assembly:*mips-isa* ,segment ,@body))

(defun emit-nops (segment count)
  (dotimes (i count)
    (emit-mips segment (:nop))))

(defun emit-set-gpr (segment gpr value)
  (declare (type segment segment) (type (unsigned-byte 32) value))
  (cond ((not (ldb-test (byte 16 16) value))
         (emit-mips segment
           (:ori gpr :zero value)))
        ((not (ldb-test (byte 16 0) value))
         (emit-mips segment
           (:lui gpr (ash value -16))))
        (t
         (emit-mips segment
           (:lui gpr (ash value -16))
           (:ori gpr gpr (logand #xffff value))))))

(defun emit-set-memory (segment basereg offset value &optional (proxy :t3))
  (declare (type segment segment) (type (unsigned-byte 16) offset) (type (unsigned-byte 32) value))
  (emit-set-gpr segment proxy value)
  (emit-mips segment
    (:sw proxy offset basereg)))

(defun emit-get-memory (segment reg addr &optional (proxy :t3))
  (declare (type segment segment) (type (unsigned-byte 32) addr))
  (emit-set-gpr segment proxy addr)
  (emit-mips segment
    (:nop)
    (:lw reg 0 proxy)))

(defun emit-register-jump (segment address &optional (proxy :t3))
  (declare (type segment segment) (type (unsigned-byte 32) address))
  (emit-set-gpr segment proxy address)
  (emit-mips segment
    (:nop)
    (:jr proxy)
    (:nop)))

(defun emit-busyloop (segment count reg)
  (emit-set-gpr segment reg count)
  (emit-mips segment
    (:bne reg :zero #xffff)
    (:addiu reg reg #xffff)))

(defun emit-set-cp0 (segment cp0 value &optional (proxy :t3))
  (declare (type segment segment))
  (emit-set-gpr segment proxy value)
  (emit-mips segment
    (:nop)
    (:mtc0 proxy cp0)))

(defun emit-set-tlb-entry (segment i value &optional (proxy :t3))
  (declare (type segment segment))
  (emit-set-cp0 segment :index i proxy)
  (emit-set-cp0 segment :entryhi (first value) proxy)
  (emit-set-cp0 segment :entrylo0 (second value) proxy)
  (emit-set-cp0 segment :entrylo1 (third value) proxy)
  (emit-mips segment
    (:nop)
    (:tlbwi)))
