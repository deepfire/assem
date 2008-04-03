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
           (:ori gpr :r0 value)))
        ((not (ldb-test (byte 16 0) value))
         (emit-mips segment
           (:lui gpr (ash value -16))))
        (t
         (emit-mips segment
           (:lui gpr (ash value -16))
           (:ori gpr gpr (logand #xffff value))))))

(defun emit-set-memory (segment basereg offset value &optional (proxy :r12))
  (declare (type segment segment) (type (unsigned-byte 16) offset) (type (unsigned-byte 32) value))
  (emit-set-gpr segment proxy value)
  (emit-mips segment
    (:sw proxy offset basereg)))

(defun emit-get-memory (segment reg addr &optional (proxy :r12))
  (declare (type segment segment) (type (unsigned-byte 32) addr))
  (emit-set-gpr segment proxy addr)
  (emit-mips segment
    (:nop)
    (:lw reg 0 proxy)))

(defun emit-register-jump (segment address &optional (proxy :r12))
  (declare (type segment segment) (type (unsigned-byte 32) address))
  (emit-set-gpr segment proxy address)
  (emit-mips segment
    (:nop)
    (:jr proxy)
    (:nop)))

(defun emit-busyloop (segment count reg)
  (emit-set-gpr segment reg count)
  (emit-mips segment
    (:bne reg :r0 #xffff)
    (:addiu reg reg #xffff)))

(defun emit-set-cp0 (segment cp0 value &optional (proxy :r12))
  (declare (type segment segment))
  (emit-set-gpr segment proxy value)
  (emit-mips segment
    (:nop)
    (:mtc0 proxy cp0)))

(defun emit-set-tlb-entry (segment i value &optional (proxy :r12))
  (declare (type segment segment))
  (emit-set-cp0 segment :index i proxy)
  (emit-set-cp0 segment :entryhi (first value) proxy)
  (emit-set-cp0 segment :entrylo0 (second value) proxy)
  (emit-set-cp0 segment :entrylo1 (third value) proxy)
  (emit-mips segment
    (:nop)
    (:tlbwi)))
