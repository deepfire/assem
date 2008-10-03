(in-package :asm-mips)

(defparameter *load-list* '(:lb :lh :lw :lbu :lhu :lwu :lwl :lwr :ll :l.s :l.d))

(defun insn-load-p (insn) (member (mnemonics insn) *load-list*))

(defun bb-ins (bb) (unturing:bb-ins bb))

(defun insn-reg-list (role insn params)
  (iter (for src/dst-spec in (insn-src/dst-spec insn))
        (for param in params)
        (when (eq src/dst-spec role)
          (collect param))))

(defun update-protected/endangered-sets (bb allotment protected endangered)
  "Update PROTECTED/ENDANGERED hash sets in an inwards-reverse walk from BB, with ALLOTMENT edge length left."
  (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i
             downto (max 0 (- (extent-length bb) allotment)))
        (dolist (prot (insn-reg-list :src insn params))
          (setf (gethash prot protected) t))
        ;;        <--i-->
        ;; (------[.....o.....]------)
        ;; <--dgr-left-->
        ;; <-----allotment---->
        (when (and (insn-load-p insn)
                   ;; in all mem->reg insn formats destreg is first parameter
                   (not (or (gethash (first params) protected)
                            (gethash (first params) endangered))))
          (setf (gethash (first params) endangered)
                (list bb (- allotment (extent-length bb) (- i)) (+ (extent-base bb) i))))))

(defun maximum-set-danger (set)
  "Find peak danger in SET."
  (or (iter (for (nil (nil danger-rest)) in-hashtable set)
            (maximize danger-rest)) 0))

(defun bb-endangered-p (bb max-danger protected endangered)
  ;; (format t "eyeing: ~S ~S~%" bb used-danger)
  (iter (for (nil nil insn . params) in-vector (extent-data bb))
        (for i below max-danger)
        (iter (for srcreg in (insn-reg-list :src insn params))
              (setf (gethash srcreg protected) t))
        (for dstreg = (first (insn-reg-list :dst insn params)))
        (when-let (vulnspec (and dstreg (not (insn-load-p insn))
                                 (not (gethash dstreg protected))
                                 (gethash dstreg endangered))) ;; vulnerable?
          (destructuring-bind (dmg-bb reg-safety-edge aggr-addr) vulnspec
            ;;        <--i---->
            ;; (------[..rse..d-idx.]----)
            ;; <-reg-dgr->
            ;;        <-----allotment---->
            ;; <-------max-danger-------->
            (when (and (< i reg-safety-edge)
                       (not (eq bb dmg-bb)))
              (return (values bb (+ (extent-base bb) i) dstreg dmg-bb aggr-addr)))))))

(defun bb-mc24rt2-victim-p (node &optional (danger-window 10))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let* ((endangered-regs (make-hash-table))
         (protected-regs (make-hash-table)))
    (dolist (entrant (bb-ins node))
      (unturing:mapt-bb-paths (rcurry #'update-protected/endangered-sets protected-regs endangered-regs)
                              danger-window entrant :key #'bb-ins))
    (let ((max-danger (maximum-set-danger endangered-regs)))
      (when (plusp max-danger)
        (bb-endangered-p node max-danger protected-regs endangered-regs)))))

(defun find-mc24rt2-victims (bbnet &optional (danger-window 10))
  (iter (for bb in bbnet)
        (for (values victim addr reg aggressor aggr-addr) = (bb-mc24rt2-victim-p bb danger-window))
        (when victim
          (unturing:mark-path (unturing:find-bb-path aggressor victim)
                              `(unturing:aggressor-bb :addr ,aggr-addr :reg ,reg :to ,victim)
                              `(unturing:linked-bb :addr ,addr :reg ,reg :to ,victim)
                              `(unturing:victim-bb :addr ,addr :reg ,reg :to ,aggressor))
          (collect victim))))

(defun mark-aggr-vic-reg-triplets (bbnet tlets)
  (labels ((bb (x) (find x bbnet :key #'extent-base)))
    (iter (for (a v r) in tlets)
          (if-let ((ag (bb a))
                   (vi (bb v)))
                  (if-let (path (unturing:find-bb-path ag vi))
                          (unturing:mark-path path
                                              `(unturing:aggressor-bb :addr ,a :reg ,r :to ,vi)
                                              `(unturing:linked-bb :addr ,v :reg ,r :to ,vi)
                                              `(unturing:victim-bb :addr ,v :reg ,r :to ,ag))
                          (format t "NOT marking ~X -> ~X: path not found~%" a v))
                  (format t "NOT marking ~X -> ~X: somebody not found~%" a v)))))

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
    (find-mc24rt2-victims bbs)))
