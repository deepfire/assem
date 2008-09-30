(in-package :asm-mips)


(defun analyse-for-mc24rt-bug (netlist &optional (danger-window 10))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let ((load-list '(:lb :lh :lw :lbu :lhu :lwu :lwl :lwr :ll :l.s :l.d)))
    (labels ((insn-load-p (insn) (member (mnemonics insn) load-list))
             (bb-ins (bb) (unturing:bb-ins bb)) (bb-outs (bb) (unturing:bb-outs bb)))
      (iter (for bb in netlist)
            (let* ((endangered-regs (make-hash-table)) max-danger)
              (labels ((collect-endangered-regs (bb allotment)
                         (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i
                                    from (max 0 (- (extent-length bb) allotment)))
                               ;;        <--i-->
                               ;; (------[.....o.....]------)
                               ;; <--dgr-left-->
                               ;; <-----allotment---->
                               (when (insn-load-p insn)
                                 ;; that's it -- in all mem->reg load insn formats the victim is 1st insn parameter
                                 (unless (gethash (first params) endangered-regs) 
                                   (setf (gethash (first params) endangered-regs)
                                         (list bb (- allotment (extent-length bb) (- i))))))))
                       (insn-dstreg-list (insn params)
                         ;; (format t "<~S~{ ~S~}>~%" insn (insn-src/dst-spec insn))
                         (and (not (insn-load-p insn))
                              (iter (for src/dst-spec in (insn-src/dst-spec insn))
                                    (for param in params)
                                    (when (eq src/dst-spec :dst)
                                      (collect param)))))
                       (note-affected-insns (bb allotment &aux (used-danger (- max-danger allotment)) hits)
                         ;; (format t "eyeing: ~S ~S~%" bb used-danger)
                         (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i)
                               (for danger-index from used-danger)
                               (dolist (dstreg (insn-dstreg-list insn params))
                                 (when-let (vulnspec (gethash dstreg endangered-regs)) ;; vulnerable?
                                   (destructuring-bind (dmg-bb reg-safety-edge) vulnspec
                                     ;;        <--i---->
                                     ;; (------[..rse..d-idx.]----)
                                     ;; <-reg-dgr->
                                     ;;        <-----allotment---->
                                     ;; <-------max-danger-------->
                                     (when (and (< danger-index reg-safety-edge)
                                                (not (eq bb dmg-bb)))
                                       (push (list (+ (extent-base bb) i) dstreg dmg-bb) hits))))))
                         (when hits
                           (unturing::pprint-object bb t)
                           (format t "~%affect list:~:{~%addr ~S, reg ~S, damage-bb ~S~}~%~%" hits))))
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
