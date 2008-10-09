(in-package :common-lisp-user)

(defpackage #:assembly
  (:nicknames :asm) 
  (:use :common-lisp :alexandria :iterate :pergamum)
  (:shadow #:disassemble)
  (:export
   #:isa #:isa-final-discriminator #:isa-delay-slots #:validate-insn-parameter-spec #:encode-insn-param #:decode-insn-param #:encode-insn #:assemble-into-u8-vector #:decode-insn #:disassemble #:defparamtype #:define-iformat-root #:defformat
   #:insn #:definsn #:opcode #:mnemonics #:width #:insn-iformat #:insn-src/dst-spec
   #:unknown-insn #:pseudo-insn #:branch-insn #:nonbranch-insn #:branch-destination-fn #:make-pseudo-insn
   #:continue-mixin #:pure-continue-mixin #:dep-continue-mixin #:noncontinue-mixin
   #:branch-abs #:branch-rel #:branch-imm #:branch-reg #:branch-indef #:branch-cond #:branch-uncond))

(defpackage #:unturing
  (:use :common-lisp :alexandria :iterate :pergamum :assembly)
  (:shadowing-import-from :assembly #:disassemble)
  (:export
   #:ivec #:bb #:bb-ins #:bb-outs #:mapt-bb-paths #:find-bb-path #:do-path-internal-nodes #:mark-source-and-target #:bb-graph-within-distance-set
   #:linked-bb #:linked-addr #:linked-reg #:linked-to #:victim-bb #:aggressor-bb
   #:insn-vector-to-basic-blocks #:bbnet-tree))

(defpackage #:assem-mini
  (:nicknames #:assem)
  (:use :common-lisp :alexandria :pergamum :iterate)
  (:export
    #:segment #:emit #:emit-mips #:segment-active-vector #:segment-instruction-count
    #:extent-list-adjoin-segment #:with-extent-list-segment #:with-extentable-segment
    ;; assem-mini-mips.lisp
    #:emit-nops #:emit-set-memory #:emit-get-memory #:emit-set-gpr #:emit-register-jump #:emit-busyloop #:emit-set-cp0 #:emit-set-tlb-entry))

(defpackage #:mips-assembly
  (:nicknames :asm-mips) 
  (:use :common-lisp :alexandria :assembly :custom-harness :pergamum :iterate)
  (:shadowing-import-from :assembly #:disassemble)
  (:export
   #:*mips-isa*
   #:gpr #:cpsel #:encode-mips-insn #:decode-mips-insn))
