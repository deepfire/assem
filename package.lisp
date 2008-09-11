(in-package :common-lisp-user)

(defpackage #:assembly
  (:nicknames :asm) 
  (:use :common-lisp :alexandria :iterate :pergamum)
  (:export
   #:isa #:isa-final-discriminator #:validate-insn-parameter-spec #:encode-insn-param #:decode-insn-param #:encode-insn #:assemble-into-u8-vector #:decode-insn #:disassemble-u8-sequence #:defparamtype #:define-iformat-root #:defformat
   #:insn #:branch-insn #:cond-branch-insn #:abs-branch-insn #:rel-branch-insn #:exception-insn #:definsn #:branch-insn-dest-fn
   #:define-arch-flow-breaks))

(defpackage #:unturing
  (:use :common-lisp :alexandria :iterate :pergamum :assembly)
  (:export
   #:ivec #:bb #:bb-ins #:bb-outs
   #:insn-vector-to-basic-blocks))

(defpackage #:assem-mini
  (:nicknames #:assem)
  (:use :common-lisp :alexandria :pergamum :iterate)
  (:export
    #:segment #:emit #:emit-mips #:segment-active-vector #:segment-instruction-count
    #:extent-list-adjoin-segment #:with-extent-list-segment #:with-extentable-segment
    ;; assem-mini-mips.lisp
    #:emit-nops #:emit-set-memory #:emit-get-memory #:emit-set-gpr #:emit-register-jump #:emit-busyloop #:emit-set-cp0 #:emit-set-tlb-entry))