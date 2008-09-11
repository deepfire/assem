(in-package :unturing)

(defclass ivec (extent)
  ())

(defclass bb (ivec)
  ((ins :accessor bb-ins :type list :initarg :ins)
   (outs :accessor bb-outs :type list :initarg :outs))
  (:default-initargs
   :ins nil :outs nil))

(defun op-breaks-p (isa op)
  (insn-breaks-flow-p (insn isa op)))

(defun insn-vector-to-basic-blocks (isa ivec)
  (let* ((dis (disassemble-u8-sequence isa (extent-data ivec)))
         (exit-indices (nconc (iter (for (insn . nil) in dis)
                                    (for i from 0)
                                    (when (op-breaks-p isa insn)
                                      (collect i)))
                              (list (extent-length ivec)))))
    (iter )))