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
   ;; Take over the GPR symbol!
   #:gpr
   #:insn-optype-params #:insn-optype-variables #:encode-insn
   #:param-type-alist
   #:lookup-insn #:decode-insn #:disassemble #:define-iformat-root #:defformat
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
    #:segment #:pinned-segment #:segment-active-vector #:segment-disassemble #:segment-emitted-insn-count
    #:with-optype-allocator #:optype-key-allocation
    #:with-tags #:with-tag-domain #:add-global-tag #:emit-global-tag #:backpatch-outstanding-global-tag-references #:emit-tag #:map-tags #:emit-ref
    #:eval-insn
    #:*isa* #:*optype* #:*segment* #:with-assem #:allocated-cells #:with-segment-emission #:emitted-insn-count
    #:emit #:emit* #:current-insn-count #:current-insn-addr
    #:compilation-environment #:cenv-isa #:cenv-optype #:cenv-cells #:cenv-symtable #:cenv-segments
    #:extent-list-adjoin-segment #:with-extentable-segment
    ;; assem-mini-mips.lisp
    #:with-mips-assem #:with-extentable-mips-segment #:with-mips-gpri #:allocate-mips-gpr #:allocated-mips-gpri
    #:emit-nops #:emit-set-gpr
    #:emit-based-store8 #:emit-based-store16 #:emit-based-store32 #:emit-store8 #:emit-store16 #:emit-store32
    #:emit-based-load8 #:emit-based-load16 #:emit-based-load32 #:emit-load8 #:emit-load16 #:emit-load32
    #:emit-mask16 #:emit-mask32
    #:emit-set-cp0 #:emit-set-tlb-entry
    #:emit-long-jump
    #:emit-jump #:emit-jump-if-eq #:emit-jump-if-ne
    #:emitting-iteration
    #:with-function-calls #:with-function-definitions-and-calls #:emit-stack-push #:emit-stack-pop
    #:emit-near-function-call #:emitting-function #:emitting-predicate-function
    #:emit-succeed #:emit-fail #:emit-succeed-if-eq #:emit-succeed-if-ne #:emit-fail-if-eq #:emit-fail-if-ne #:emit-test-eq #:emit-test-ne
    #:emit-jump-if
    #:*initial-stack-top*))

(defpackage #:mips-assembly
  (:nicknames :asm-mips) 
  (:use :common-lisp :alexandria :assembly :custom-harness :pergamum :iterate)
  (:shadowing-import-from :assembly #:disassemble)
  (:export
   #:*mips-isa*
   #:gpr #:cpsel #:encode-mips-insn #:decode-mips-insn))
