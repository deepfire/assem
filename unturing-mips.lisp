(in-package :asm-mips)


(defun analyse-for-mc24rt-bug (netlist &optional (danger-window 10))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (lret ((load-list '(:lb :lh :lw :lbu :lhu :lwu :lwl :lwr :ll :l.s :l.d))
         hits)
    (labels ((insn-load-p (insn) (member (mnemonics insn) load-list))
             (bb-ins (bb) (unturing:bb-ins bb)) (bb-outs (bb) (unturing:bb-outs bb)))
      (iter (for bb in netlist)
            (let* ((endangered-regs (make-hash-table))
                   (protected-regs (make-hash-table))
                   max-danger)
              (labels ((insn-reg-list (role insn params)
                         ;; (format t "<~S~{ ~S~}>~%" insn (insn-src/dst-spec insn))
                         (iter (for src/dst-spec in (insn-src/dst-spec insn))
                               (for param in params)
                               (when (eq src/dst-spec role)
                                 (collect param))))
                       (collect-endangered-regs (bb allotment)
                         (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i
                                    downto (max 0 (- (extent-length bb) allotment)))
                               (dolist (prot (insn-reg-list :src insn params))
                                 (setf (gethash prot protected-regs) t))
                               ;;        <--i-->
                               ;; (------[.....o.....]------)
                               ;; <--dgr-left-->
                               ;; <-----allotment---->
                               (when (and (insn-load-p insn)
                                          ;; that's it -- in all mem->reg load insn formats the victim is 1st insn parameter
                                          (not (or (gethash (first params) protected-regs)
                                                   (gethash (first params) endangered-regs))))
                                 (setf (gethash (first params) endangered-regs)
                                       (list bb (- allotment (extent-length bb) (- i)))))))
                       (note-affected-insns (bb allotment &aux (used-danger (- max-danger allotment)))
                         ;; (format t "eyeing: ~S ~S~%" bb used-danger)
                         (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i)
                               (for danger-index from used-danger)
                               (for dstreg = (first (insn-reg-list :dst insn params))) ;; only care about single destreg
                               (when-let (vulnspec (and dstreg
                                                        (not (insn-load-p insn))
                                                        (gethash dstreg endangered-regs))) ;; vulnerable?
                                 (destructuring-bind (dmg-bb reg-safety-edge) vulnspec
                                   ;;        <--i---->
                                   ;; (------[..rse..d-idx.]----)
                                   ;; <-reg-dgr->
                                   ;;        <-----allotment---->
                                   ;; <-------max-danger-------->
                                   (when (and (< danger-index reg-safety-edge)
                                              (not (eq bb dmg-bb)))
                                     (push (change-class bb 'unturing:victim-bb
                                            :addr (+ (extent-base bb) i) :reg dstreg :aggressor dmg-bb)
                                           hits)))))))
                (unturing:mapt-bb-paths #'collect-endangered-regs danger-window bb :key #'bb-ins)
                (setf max-danger (or (iter (for (nil (nil danger-rest)) in-hashtable endangered-regs)
                                           (maximize danger-rest)) 0))
                (unturing:mapt-bb-paths #'note-affected-insns max-danger bb :key #'bb-outs)))))))

(defun lick-it (&optional (force-node-separation-p t) (suppress-p t) (filename "pestilence/to4fpu/preparee.o"))
  (let* ((b-p (symbol-function (find-symbol "PARSE" (find-package :bintype))))
         (e-e (find-symbol "EHDR" (find-package :elf)))
         (e-e-s (symbol-function (find-symbol "EHDR-SECTIONS" (find-package :elf))))
         (e-s-e-p (symbol-function (find-symbol "SHDR-EXECUTABLE-P" (find-package :elf))))
         (vector (pergamum:file-as-vector filename))
         (ehdr (funcall b-p e-e vector))
         (section (car (funcall e-e-s ehdr e-s-e-p)))
         (bbs (unturing:insn-vector-to-basic-blocks mips-assembly:*mips-isa* section)))
    ;; (dolist (o bbs)
    ;;   (unturing::pprint-object o t) (terpri))
    (unturing::check-graph-validity bbs #'unturing:bb-ins #'unturing:bb-outs)
    (unturing::pprint-bignode-graph-linear bbs
     :node-parameters-fn (curry #'unturing::dis-printer-parameters *mips-isa*)
     :force-node-separation-p force-node-separation-p
     :suppress-flow-aligned-edges-p suppress-p)
    (analyse-for-mc24rt-bug bbs)))
