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
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:segment #:segment-data #:segment-current-index #:segment-emitted-insn-count
   #:pinned-segment #:pinned-segment-base
   #:segment-active-vector #:segment-disassemble
   #:*isa* #:*tag-domain* #:*segment*
   #:with-optype-pool #:eval-insn       ; binds *isa*
   #:tag-environment #:env-global-frame #:env-functions #:env-forward-references
   #:envobject #:envobject-name #:envobject-env
   #:segpoint #:make-segpoint #:copy-segpoint #:segpoint-name #:segpoint-env #:segpoint-segment #:segpoint-offset #:segpoint-insn-nr
   #:tag #:make-tag #:copy-tag #:tag-name #:tag-env #:tag-segment #:tag-offset #:tag-insn-nr #:tag-finalizer #:tag-references
   #:func #:func-tag #:func-emitter
   #:ref #:make-ref #:copy-ref #:ref-name #:ref-env #:ref-segment #:ref-offset #:ref-insn-nr #:ref-emitter
   #:define-function #:current-function #:emit-function #:with-function-definition-and-emission
   #:with-tag-domain #:with-tags ; binds *tag-domain*
   #:with-ensured-assem                 ; binds *isa* and *tag-domain*
   #:with-segment-emission              ; binds *segment*
   #:current-insn-count #:current-segment-offset #:current-absolute-addr
   #:segpoint-address
   #:backpatch-tag-reference #:backpatch-tag-references
   #:emit-tag #:emit-global-tag #:find-tag #:tag-address
   #:compilation-environment #:cenv-isa #:cenv-optype #:cenv-segments #:cenv-cellenv #:cenv-tagenv
   #:with-compilation-environment #:save-compilation-environment
   #:with-bioable-segment))

(defpackage #:comp
  (:use :common-lisp :alexandria :iterate :pergamum :environment :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:shadow #:frame)
  (:export
   ))

(defpackage #:assem-emission
  (:nicknames :assem-emit)
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :isa :assem)
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
   #:insn-vector-to-basic-blocks #:bbnet-tree
   #:default-node-parameter-extractor #:pprint-node-graph-linear))

(defpackage #:isa-mips
  (:use :common-lisp :alexandria :custom-harness :pergamum :iterate :isa)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:*mips-isa* #:encode-mips-insn #:decode-mips-insn))

(defpackage #:assem-mips
  (:use :common-lisp :alexandria :iterate :pergamum :environment :allocation-pool :isa :isa-mips :assem)
  (:shadowing-import-from :isa #:disassemble)
  (:export
   #:*poison-mips-stack*
   #:with-mips-gpr-environment #:with-mips-assem #:with-bioable-mips-segment
   #:evaluate-mips-gpr #:with-mips-gpri #:allocate-mips-gpr #:release-mips-gpr
   #:emit #:emit* #:emit-ref
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
   #:with-function-calls #:emit-stack-push #:emit-stack-pop
   #:emit-near-function-call #:emit-long-function-call #:emitting-function #:emitting-predicate-function
   #:emit-succeed #:emit-fail #:emit-succeed-if-eq #:emit-succeed-if-ne #:emit-fail-if-eq #:emit-fail-if-ne #:emit-test-eq #:emit-test-ne
   #:emit-jump-if))
