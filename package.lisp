(in-package :common-lisp-user)

(defpackage #:assembly
  (:nicknames :asm) 
  (:use :common-lisp :alexandria :iterate :pergamum :allocation-pool)
  (:shadow #:disassemble)
  (:export
   #:assembly-condition #:assembly-error #:simple-assembly-error
   #:isa #:isa-final-discriminator #:isa-delay-slots #:validate-insn-parameter-spec #:encode-insn-param #:decode-insn-param
   #:optype #:optype-name #:optype-width #:optype-set #:optype-rset #:optype-unallocatables #:optype-allocatables #:optype-mask
   #:define-optype #:define-enumerated-optype
   #:insn-optype-params #:insn-optype-variables #:encode-insn
   #:param-type-alist
   #:lookup-insn #:decode-insn #:disassemble #:defparamtype #:define-iformat-root #:defformat
   #:insn #:definsn #:opcode #:mnemonics #:width #:insn-iformat #:insn-src/dst-spec
   #:unknown-insn #:pseudo-insn #:branch-insn #:nonbranch-insn #:branch-destination-fn #:make-pseudo-insn
   #:continue-mixin #:pure-continue-mixin #:dep-continue-mixin #:noncontinue-mixin
   #:branch-abs #:branch-rel #:branch-imm #:branch-reg #:branch-indef #:branch-cond #:branch-uncond))

(defpackage #:unturing
  (:use :common-lisp :alexandria :iterate :pergamum :assembly)
  (:shadowing-import-from :assembly #:disassemble)
  (:export
   #:ivec #:bb #:bb-ins #:bb-outs
   #:bons #:bar #:bdr #:bons-path #:all-bons-paths #:shortest-bons-path #:bons-connected-p
   #:mapt-bb-paths #:do-path-internal-nodes #:bb-graph-within-distance-set
   #:linked-bb #:linked-addr #:linked-reg #:linked-to #:victim-bb #:aggressor-bb
   #:insn-vector-to-basic-blocks #:bbnet-tree))

(defpackage #:assem-mini
  (:nicknames #:assem)
  (:use :common-lisp :alexandria :iterate :pergamum :allocation-pool)
  (:export
    #:segment #:emit #:emit-mips #:segment-active-vector #:segment-disassemble #:segment-instruction-count
    #:extent-list-adjoin-segment #:with-extent-list-segment #:with-extentable-segment #:emitted-insn-count
    ;; assem-mini-mips.lisp
    #:emit-nops #:emit-set-gpr
    #:emit-store-word #:emit-load-word #:emit-store-halfword #:emit-load-halfword #:emit-store-byte #:emit-load-byte
    #:emit-register-jump #:emit-busyloop #:emit-set-cp0 #:emit-set-tlb-entry))

(defpackage #:mips-assembly
  (:nicknames :asm-mips) 
  (:use :common-lisp :alexandria :assembly :custom-harness :pergamum :iterate)
  (:shadowing-import-from :assembly #:disassemble)
  (:export
   #:*mips-isa*
   #:gpr #:cpsel #:encode-mips-insn #:decode-mips-insn
   #:with-gpr-pool #:allocate-gpr #:release-gpr))
