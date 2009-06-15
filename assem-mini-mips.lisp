;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEM-MINI; Base: 10 -*-
;;;
;;;  (c) copyright 2006-2009 by
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

(defmacro with-extentable-mips-segment ((extentable addr) (optype &rest bound-set) &body body)
  `(with-extentable-segment (asm-mips:*mips-isa* ,extentable ,addr) (,optype ,@bound-set)
     ,@body))

(defun emit-nops (count)
  (dotimes (i count)
    (emit* :nop)))

(defmacro define-emitter (name lambda-list binding-spec &body body)
  (multiple-value-bind (docstring decls body) (destructure-def-body body)
    (multiple-value-bind (special-decls nonspecial-decls) (unzip (feq 'special) decls :key #'car)
      (emit-defun
       name (mapcar (compose #'car #'ensure-cons) lambda-list)
       `((allocate-let ,(when binding-spec `(',(car binding-spec) ,@(cdr binding-spec))) ,@special-decls ,@body))
       :documentation docstring
       :declarations (append nonspecial-decls
                             (iter (for paramspec in lambda-list)
                                   (destructuring-bind (paramname &optional paramwidth) (ensure-cons paramspec)
                                     (when paramwidth
                                       (unless (typep paramwidth '(unsigned-byte 6))
                                         (asm:assembly-error "~@<Error in DEFINE-LET-EMITTER ~A: bad parameter width ~S for parameter ~S.~:@>"
                                                             name paramwidth paramname))
                                       (collect `(type (unsigned-byte ,paramwidth) ,paramname))))))))))

(define-emitter emit-set-gpr (gpr (value 32)) nil
  (let ((hi (ldb (byte 16 16) value))
        (lo (ldb (byte 16 0) value)))
    ;; The first case also takes care of (ZEROP VALUE)
    (cond ((zerop hi) (emit* :ori gpr :zero lo))
          ((zerop lo) (emit* :lui gpr hi))
          (t          (emit* :lui gpr hi)
                      (emit* :ori gpr gpr lo)))))

;;;
;;; Register-based memory stores
;;;
(define-emitter emit-based-store32 ((value 32) basereg (offset 16)) (gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sw :proxy offset basereg))
(define-emitter emit-based-store16 ((value 16) basereg (offset 16)) (gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sh :proxy offset basereg))
(define-emitter emit-based-store8 ((value 8) basereg (offset 16)) (gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :sb :proxy offset basereg))

;;;
;;; Absolute memory stores
;;;
(define-emitter emit-store32 ((value 32) address) (gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store32 value :base (logand #xffff address)))
(define-emitter emit-store16 ((value 32) address) (gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store16 value :base (logand #xffff address)))
(define-emitter emit-store8 ((value 32) address) (gpr :base)
  (emit-set-gpr :base (logand #xffff0000 address))
  (emit-based-store8 value :base (logand #xffff address)))

;;;
;;; Register-based memory loads
;;;
(define-emitter emit-based-load32 (dstreg (offset 16) basereg) nil
  (emit* :lw dstreg offset basereg))
(define-emitter emit-based-load16 (dstreg (offset 16) basereg) nil
  (emit* :lh dstreg offset basereg))
(define-emitter emit-based-load8 (dstreg (offset 16) basereg) nil
  (emit* :lb dstreg offset basereg))

;;;
;;; Absolute, self-based memory loads
;;;
(define-emitter emit-load32 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load32 dstreg (logand addr #xffff) dstreg))
(define-emitter emit-load16 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load16 dstreg (logand addr #xffff) dstreg))
(define-emitter emit-load8 (dstreg (addr 32)) nil
  (emit-set-gpr dstreg (logand addr #xffff0000))
  (emit-based-load8 dstreg (logand addr #xffff) dstreg))

;;;
;;; Masking
;;;
(define-emitter emit-mask32 (dstreg srcreg (mask 32)) (gpr :mask)
  (emit-set-gpr :masker mask)
  (emit* :and dstreg :mask srcreg))
(define-emitter emit-mask16 (dstreg srcreg (mask 16)) nil
  (emit* :andi dstreg srcreg mask))

(define-emitter emit-long-jump ((address 32)) (gpr :proxy)
  (emit-set-gpr :proxy address)
  (emit* :nop)
  (emit* :jr :proxy)
  (emit* :nop))

(define-emitter emit-busyloop (count) (gpr :counter)
  (emit-set-gpr :counter count)
  (emit* :bne :counter :zero #xffff)
  (emit* :addiu :counter :counter #xffff))

(define-emitter emit-set-cp0 (cp0 (value 32)) (gpr :proxy)
  (emit-set-gpr :proxy value)
  (emit* :nop)
  (emit* :mtc0 :proxy cp0))

(define-emitter emit-set-tlb-entry (i value) nil
  (emit-set-cp0 :index i)
  (emit-set-cp0 :entryhi (first value))
  (emit-set-cp0 :entrylo0 (second value))
  (emit-set-cp0 :entrylo1 (third value))
  (emit* :nop)
  (emit* :tlbwi))
