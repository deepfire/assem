(in-package :unturing)

(defclass ivec (extent)
  ())

(defclass disivec (extent)
  ())

(defclass bb (ivec)
  ((ins :accessor bb-ins :type list :initarg :ins)
   (outs :accessor bb-outs :type list :initarg :outs))
  (:default-initargs
   :ins nil :outs nil))

(defun bb-tail-insn (isa bb)
  "The type of BB is determined by its tail instruction."
  (third (elt (extent-data bb) (if (> (extent-length bb) (isa-delay-slots isa))
                                   (- (extent-length bb) (1+ (isa-delay-slots isa)))
                                   0))))

(defun bb-typep (isa bb type)
  (typep (bb-tail-insn isa bb) type))

(defun bb-branches-p (isa bb)
  (bb-typep isa bb 'branch-insn))

(defun link-bbs (from to)
  (push from (bb-ins to))
  (push to (bb-outs from)))

(defun insn-vector-to-basic-blocks (isa ivec &aux (*print-circle* nil))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let* ((dis (make-extent 'disivec 0 (coerce (disassemble-u8-sequence isa (extent-data ivec)) 'vector)))
         (tree (octree-1d:make-tree :length (extent-length ivec)))
         roots)
    (labels ((insn (i)
               (destructuring-bind (opcode width insn . params) (elt (extent-data dis) i)
                 (declare (ignore opcode width))
                 (values insn params)))
             (next-outgoing-branch (bb-start)
               "Find the closest outgoing branch after bb-start."
               (iter (for i from bb-start below (extent-length dis))
                     (for (values insn params) = (insn i))
                     (when (typep insn 'branch-insn)
                       (return (values i insn params)))))
             (new-bb (start end &rest rest)
               (declare (type (integer 0) start end))
               (lret ((bb (apply #'make-instance 'bb :base start
                           :data (make-array (- end start) :adjustable t
                                             :initial-contents (subseq (extent-data dis) start end))
                           rest)))
                 (octree-1d:insert start bb tree)))
             (new-linked-bb (chain-bb start end)
               "Create and chain/insert a BB START<->END, if only its length would be positive."
               (declare (type (or null bb) chain-bb) (type (integer 0) start end))
               (lret ((bb (new-bb start end)))
                 (if chain-bb
                     (link-bbs chain-bb bb)
                     (push bb roots))))
             (flow-split-bb-at (bb at)
               (declare (type bb bb) (type (integer 0) at))
               (lret* ((old-end (extent-end bb))
                       (new (new-bb at old-end :ins (list bb) :outs (bb-outs bb))))
                 (setf (bb-outs bb) (list new)
                       (extent-data bb) (adjust-array (extent-data bb) (- at (extent-base bb)))))))
      (format t "total: ~X~%content: ~S~%" (extent-length dis) (extent-data dis))
      (let* (forwards
             (outgoings (iter (with bb-start = 0) (while (< bb-start (extent-length dis)))
                              (when bb (format t "last bb: ~X ~S~%" (extent-base bb) (extent-data bb)))
                              (for chain-bb = (when (and bb (bb-typep isa bb 'pure-continue-mixin))
                                                bb))
                              (for (values outgoing insn params) = (next-outgoing-branch bb-start))
                              (when outgoing (format t "got: ~X -> ~X~%"
                                                     bb-start (+ outgoing (isa-delay-slots isa))))
                              (for bb = (new-linked-bb chain-bb bb-start
                                                       (if outgoing
                                                           (+ outgoing 1 (isa-delay-slots isa))
                                                           (extent-length dis))))
                              (multiple-value-bind (destinated-at-us destinated-further)
                                  (unzip (curry #'point-in-extent-p bb) forwards :key #'car)
                                (when destinated-at-us
                                  (iter (for (target srcbb) in (sort destinated-at-us #'< :key #'car))
                                        ;; watch the code below carefully for "coincidences"...
                                        (format t "resolved forward: ~X -> ~X~%" (extent-base srcbb) target)
                                        (with target-bb = bb)
                                        (let* ((split-p (not (= target (extent-base target-bb))))
                                               (link-target (if split-p
                                                                (flow-split-bb-at target-bb target)
                                                                target-bb)))
                                          (link-bbs srcbb link-target)
                                          (when split-p
                                            (setf target-bb link-target
                                                  bb target-bb)))))
                                (setf forwards destinated-further))
                              (while outgoing)
                              ;; we deal only with
                              ;; relative, specified, local branches
                              (when-let* ((relative-p (typep insn 'rel-branch-insn))
                                          (dest-fn (branch-destination-fn insn)))
                                (format t "processing a branch: [~X...] -> +~X, ~S,~%"
                                        (extent-base bb)
                                        (apply dest-fn params)
                                        (type-of (bb-tail-insn isa bb)))
                                (when-let* ((delta (apply dest-fn params))
                                            (target (+ outgoing delta))
                                            (branch-local-p (point-in-extent-p dis target)))
                                  (cond ((>= delta (isa-delay-slots isa)) ;; past this bb?
                                         (format t "pushing a forward: ~X -> ~X~%" (extent-base bb) target)
                                         (push (list target bb) forwards))
                                        ((< delta 0) ;; a back reference...
                                         (let* ((target-bb (oct-1d:resolve target tree))
                                                (split-p (not (= target (extent-base target-bb))))
                                                (link-target-bb (if split-p
                                                                    (flow-split-bb-at target-bb target)
                                                                    target-bb))
                                                (hit-self-p (eq target-bb bb))
                                                (self-superseded-p (and split-p hit-self-p))
                                                (source-bb (if self-superseded-p link-target-bb bb)))
                                           (format t "split back: ~X -> ~X~%"
                                                   (extent-base source-bb) (extent-base link-target-bb))
                                           (link-bbs source-bb link-target-bb)
                                           (when self-superseded-p
                                             (setf bb source-bb)))) ;; the chain-bb of the next turn..
                                        ((= delta 0))))) ;; is a NOP branch?
                              (collect (list outgoing insn params))
                              (setf bb-start (+ outgoing 1 (isa-delay-slots isa))))))
        (format t "unresolved forwards: ~S, ~S~%" (length forwards) (mapcar #'car forwards))
        (format t "bbs: ")
        (oct-1d:do-tree-values (bb tree)
          (format t "[~S ~S] " (extent-base bb) (1- (extent-end bb))))
        (format t "~%")
        (oct-1d:tree-list tree)))))

;; OUTFWD: allocate fwd, will be collected later
;; INBACK: allocate back, will be collected later
;; OUTBACK: release back
;; INFWD: release fwd
;;                                       
;;      OOO<---,                                                            
;;      OOO   ||                           
;;      OOO   ||                           
;; ,----OOO   ||                           
;; ||         ||                          
;; ||   OOO<-,||                            
;; ||   OOO  |||                            
;; ||   OOO  |||                            
;; ||,--OOO--||'                            
;; |||       ||                             
;; '|-->OOO  ||
;;  |   OOO  ||                             
;;  |   OOO  ||                            
;;  |,--OOO--'|                             
;;  ||        |                           
;;  '-->OOO   |
;;      OOO   |                             
;;      OOO   |                            
;;      OOO---'                                                           
;;                                       
(defun pprint-bignode-graph-linear (nodelist &key (stream t)
                                    (node-line-fn (constantly "foobar"))
                                    (node-width (+ (length "foobar") 2))
                                    (node-separator "~%"))
  (let ((fwd-limit 0)
        (back-limit 0)
        fwds backs)
    (labels ((later-p (a b)
               (>= (extent-base a) (extent-end b)))
             (node-ins (node)
               (bb-ins node))
             (node-outs (node)
               (bb-outs node))
             (refedby-p (who by)
               (find by (bb-ins who)))
             (refs-p (who what)
               (find what (bb-outs who))))
      (iter (for node in nodelist)
;;;;;;;;;;;; _this__ is about something started earlier, guaranteed to be an earlier node
            (for (values f-at-us f-pending) = (unzip (curry #'refedby-p node) fwds))
;;;;;;;;;;;; _this____ is about something yet to be started, guaranteed to be an earlier node
            (for (values b-at-us b-pending) =  (unzip (rcurry #'refs-p node) backs))
            (let ((new-fwds (remove-if (curry #'later-p node) (node-outs node)))
                  (new-backs (remove-if (curry #'later-p node) (node-ins node))))
              (maximize (length fwds) into max-fwds)
              (maximize (+ (length f-pending) (length new-fwds)) into max-fwds)
              (maximize (+ (length backs) (length new-backs)) into max-backs)
              (setf backs (nconc (delete node new-backs) b-pending)
                    fwds (nconc new-fwds f-pending)))
            (finally (setf (values fwd-limit back-limit) (values max-fwds max-backs))))
      ;;       (iter (for node in nodelist)
      ;;             (iter (for nodeline = (funcall node-line-fn))
      ;;                   (while nodeline))
      ;;             (format stream node-separator))
      (format t "processed ~D nodes, limits: fwd: ~D, back: ~D~%"
              (length nodelist) fwd-limit back-limit))))
