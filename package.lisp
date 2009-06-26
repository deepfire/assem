(in-package :common-lisp-user)

(defpackage #:isa
  (:use :common-lisp :alexandria :iterate :pergamum)
  (:shadow #:disassemble)
  (:export
   #:assembly-condition #:assembly-error #:simple-assembly-error
   #:isa #:isa-final-discriminator #:isa-gpr-optype #:isa-delay-slots
   #:validate-insn-parameter-spec #:encode-insn-param #:decode-insn-param
   #:optype #:optype-name #:optype-width #:optype-set #:optype-rset #:optype-unallocatables #:optype-allocatables #:optype-mask #:optype-evaluate
   #:define-optype #:define-enumerated-optype #:define-enumerated-gpr-optype
   ;; Take over the GPR symbol!
   #:gpr
   #:insn-optype-params #:insn-optype-variables #:encode-insn
   #:param-type-alist
   #:lookup-insn #:decode-insn #:disassemble #:define-iformat-root #:defformat
   #:insn #:definsn #:opcode #:mnemonics #:width #:insn-iformat #:insn-src/dst-spec
   #:unknown-insn #:pseudo-insn #:branch-insn #:nonbranch-insn #:branch-destination-fn #:make-pseudo-insn
   #:continue-mixin #:pure-continue-mixin #:dep-continue-mixin #:noncontinue-mixin
   #:branch-abs #:branch-rel #:branch-imm #:branch-reg #:branch-indef #:branch-cond #:branch-uncond))

(defpackage #:assem
  (:nicknames #:assem)
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :tracker :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:segment #:segment-data #:segment-current-index #:segment-emitted-insn-count
   #:pinned-segment #:pinned-segment-base
   #:segment-active-vector #:segment-disassemble
   #:*isa* #:*tag-domain* #:*segment*
   #:with-optype-pool #:eval-insn       ; binds *isa*
   #:with-tag-domain #:add-global-tag #:emit-global-tag #:emit-tag #:map-tags #:with-tags ; binds *tag-domain*
   #:with-assem                         ; binds *isa* and *tag-domain*
   #:with-segment-emission              ; binds *segment*
   #:backpatch-outstanding-global-tag-references #:current-insn-count #:current-insn-addr
   #:compilation-environment #:cenv-isa #:cenv-optype #:cenv-segments #:cenv-cellenv #:cenv-tagenv
   #:with-compilation-environment #:save-compilation-environment
   #:extent-list-adjoin-segment #:with-extentable-segment))

(defpackage #:assem-emission
  (:nicknames :assem-emit)
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :tracker :isa :assem)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:emit-ref #:emit #:emit*))

(defpackage #:unturing
  (:use :common-lisp :alexandria :iterate :pergamum :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:ivec #:bb #:bb-ins #:bb-outs
   #:bons #:bar #:bdr #:bons-path #:all-bons-paths #:shortest-bons-path #:bons-connected-p
   #:mapt-bb-paths #:do-path-internal-nodes #:bb-graph-within-distance-set
   #:linked-bb #:linked-addr #:linked-reg #:linked-to #:victim-bb #:aggressor-bb
   #:insn-vector-to-basic-blocks #:bbnet-tree))

(defpackage #:isa-mips
  (:use :common-lisp :alexandria :custom-harness :pergamum :iterate :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:*mips-isa* #:encode-mips-insn #:decode-mips-insn))

(defpackage #:assem-mips
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :tracker :isa :isa-mips :assem)
  (:shadowing-import-from :isa #:disassemble)
  (:export
    #:with-mips-assem
    #:emit #:emit* #:emit-ref
    #:with-extentable-mips-segment #:with-mips-gpri #:allocate-mips-gpr #:release-mips-gpr
    #:emit-nops #:emit-set-gpr
    #:emit-based-store32 #:emit-based-store16 #:emit-based-store8 #:emit-store32 #:emit-store16 #:emit-store8
    #:emit-based-load32 #:emit-based-load16 #:emit-based-load8 #:emit-load32 #:emit-load16 #:emit-load8
    #:emit-mask32 #:emit-mask16
    #:emit-set-cp0 #:emit-set-tlb-entry
    #:emit-long-jump
    #:emit-jump #:emit-jump-if-eq #:emit-jump-if-ne
    #:ensure-cell #:cell-let
    #:emitting-iteration
    #:*initial-stack-top*
    #:with-function-calls #:with-function-definitions-and-calls #:emit-stack-push #:emit-stack-pop
    #:emit-near-function-call #:emitting-function #:emitting-predicate-function
    #:emit-succeed #:emit-fail #:emit-succeed-if-eq #:emit-succeed-if-ne #:emit-fail-if-eq #:emit-fail-if-ne #:emit-test-eq #:emit-test-ne
    #:emit-jump-if))
