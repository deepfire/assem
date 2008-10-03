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

(defun recurse-protected/endangered-sets (bb allotment protected endangered)
  "Update PROTECTED/ENDANGERED hash sets in an inwards-reverse walk from BB, with ALLOTMENT edge length left."
  (iter (for (nil nil insn . params) in-vector (extent-data bb) with-index i
             downto (max 0 (- (extent-length bb) allotment)))
        (dolist (prot (insn-reg-list :src insn params))
          (pushnew prot protected))
        ;;        <--i-->
        ;; (------[.....o.....]------)
        ;; <--dgr-left-->
        ;; <-----allotment---->
        (when-let* ((load-p (insn-load-p insn))
                    ;; in all mem->reg insn formats destreg is first parameter
                    (dstreg-unprotected-p (null (find (first params) protected)))
                    (this-danger (- allotment (extent-length bb) (- i)))
                    (more-dangerous-p (> this-danger (or (second (gethash (first params) endangered)) 0))))
          (setf (gethash (first params) endangered) (list bb this-danger (+ (extent-base bb) i)))))
  (when-let* ((allotment-left (- allotment (extent-length bb)))
              (there-is-more-to-danger-than-meets-the-mind (plusp allotment-left)))
    (iter (for entrant in (bb-ins bb))
          (recurse-protected/endangered-sets entrant allotment-left protected endangered))))

(defun maximum-set-danger (set)
  "Find peak danger in SET."
  (or (iter (for (nil (nil danger-rest)) in-hashtable set)
            (maximize danger-rest)) 0))

(defun bb-endangered-p (bb max-danger endangered)
  ;; (format t "eyeing: ~S ~S~%" bb used-danger)
  (iter (with protected = nil)
        (for (nil nil insn . params) in-vector (extent-data bb))
        (for i below max-danger)
        (iter (for srcreg in (insn-reg-list :src insn params))
              (pushnew srcreg protected))
        (for dstreg = (first (insn-reg-list :dst insn params)))
        (when-let (vulnspec (and dstreg (not (insn-load-p insn))
                                 (not (find dstreg protected))
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

(defun path-hurt-by-mc24rt2-p (path &optional (danger-window 10) &aux (rpath (reverse path)))
  (let ((endangered-regs (make-hash-table))
        (protected-regs (make-hash-table)))
    (dolist (in (rest rpath))
      (update-protected/endangered-sets in danger-window protected-regs endangered-regs))
    (bb-endangered-p (first rpath) (maximum-set-danger endangered-regs) endangered-regs)))

(defun bb-mc24rt2-victim-p (node &optional (danger-window 10))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let* ((endangered-regs (make-hash-table)))
    (dolist (entrant (bb-ins node))
      (recurse-protected/endangered-sets entrant danger-window nil endangered-regs))
    (let ((max-danger (maximum-set-danger endangered-regs)))
      (when (plusp max-danger)
        (bb-endangered-p node max-danger endangered-regs)))))

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

(defun lick-it (&optional (force-node-separation-p t) (suppress-p t) (filename "pestilence/to4fpu/to_mcs.o"))
  (let* ((e-f-s (symbol-function (find-symbol "ELF-FILE-SECTION" (find-package :elf))))
         (section (funcall e-f-s filename (intern ".TEXT" (find-package :elf))))
         (bbnet (unturing:insn-vector-to-basic-blocks mips-assembly:*mips-isa* section)))
    ;; (dolist (o bbnet)
    ;;   (unturing::pprint-object o t) (terpri))
    ;; (unturing::check-graph-validity bbnet #'unturing:bb-ins #'unturing:bb-outs)
    ;; (unturing::pprint-bignode-graph-linear bbnet
    ;;   :node-parameters-fn (curry #'unturing::dis-printer-parameters *mips-isa*)
    ;;   :force-node-separation-p force-node-separation-p
    ;;   :suppress-flow-aligned-edges-p suppress-p)
    (let* ((vnet-10 (find-mc24rt2-victims bbnet 10))
           (hurtpath-10-10 (remove-if-not (rcurry #'path-hurt-by-mc24rt2-p 10)
                                          (mapcar #'unturing:find-bb-path (mapcar #'unturing:linked-to vnet-10) vnet-10)))
           ;; don't mind the fixorage
           (vnet-12 (remove-if-not (rcurry #'typep 'unturing:victim-bb) (find-mc24rt2-victims bbnet 12)))
       
           (hurtpath-12-10 (remove-if-not (rcurry #'path-hurt-by-mc24rt2-p 10)
                                          (mapcar #'unturing:find-bb-path (mapcar #'unturing:linked-to vnet-12) vnet-12))))
      (set-difference hurtpath-10-10 hurtpath-12-10 :test #'equal))))
