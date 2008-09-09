(defpackage assem-mini
  (:nicknames #:assem)
  (:use :common-lisp :alexandria :pergamum :iterate)
  (:export
    #:segment #:emit #:emit-mips #:segment-active-vector #:segment-instruction-count
    #:extent-list-adjoin-segment #:with-extent-list-segment #:with-extentable-segment
    ;; assem-mini-mips.lisp
    #:emit-nops #:emit-set-memory #:emit-get-memory #:emit-set-gpr #:emit-register-jump #:emit-busyloop #:emit-set-cp0 #:emit-set-tlb-entry))

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

(defmacro emit (isa segment &body insns)
  (cond ((null insns))
        ((= 1 (length insns))
         `(%emit32le ,segment (asm:encode-insn ,isa ,@(first insns))))
        (t
         (once-only (isa segment)
           `(let ((insns (list ,@(iter (for insn in insns) (collect `(asm:encode-insn ,isa ,@insn))))))
              (dolist (insn insns) (%emit32le ,segment insn)))))))

(defun segment-active-vector (segment)
  (declare (type segment segment))
  (subseq (segment-data segment) 0 (segment-current-index segment)))

(defun segment-instruction-count (segment)
  (ash (segment-current-index segment) -2))

(defun extent-list-adjoin-segment (extent-list segment address)
  (extent-list-adjoin* extent-list 'extent (segment-active-vector segment) address))

(defmacro with-extent-list-segment (extent-list (segment address) &body body)
  `(let ((,segment (make-instance 'segment)))
     (progn-1
       ,@body
       (extent-list-adjoin-segment ,extent-list ,segment ,address))))

(defmacro with-extentable-segment ((extentable addr segment) &body body)
  `(let ((,segment (make-instance 'segment)))
     (progn-1
       ,@body
       (setf (extentable-u8-vector ,extentable ,addr) (segment-active-vector ,segment)))))
