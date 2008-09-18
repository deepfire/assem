(in-package :unturing)

(defclass ivec (extent)
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
  (let* ((dis (coerce (disassemble-u8-sequence isa (extent-data ivec)) 'vector))
         (tree (octree-1d:make-tree :length (extent-length ivec)))
         roots)
    (labels ((insn (i)
               (destructuring-bind (opcode width insn . params) (elt dis i)
                 (declare (ignore opcode width))
                 (values insn params)))
             (next-outgoing-branch (bb-start)
               "Find the closest outgoing branch after bb-start."
               (iter (for i from bb-start below (length dis))
                     (for (values insn params) = (insn i))
                     (when (typep insn 'branch-insn)
                       (return (values i insn params)))))
             (new-bb (start end &rest rest)
               (declare (type (integer 0) start end))
               (lret ((bb (apply #'make-instance 'bb :base start
                           :data (make-array (- end start) :adjustable t
                                                           :initial-contents (subseq dis start end))
                           rest)))
                 (octree-1d:insert start bb tree)))
             (maybe-new-bb (chain-bb start end &aux (end (or end (length dis))))
               "Create and chain/insert a BB START<->END, if only its length would be positive."
               (declare (type (or null bb) chain-bb) (type (integer 0) start end))
               (when-let* ((length (- end start))
                           (nonzero-p (plusp length))
                           (bb (new-bb start end)))
                 (if chain-bb
                     (link-bbs chain-bb bb)
                     (push bb roots))
                 bb))
             (flow-split-bb-at (bb at)
               (declare (type bb bb) (type (integer 0) at))
               (lret* ((old-end (extent-end bb))
                       (new (new-bb at old-end :ins (list bb) :outs (bb-outs bb))))
                 (setf (bb-outs bb) (list new)
                       (extent-data bb) (adjust-array (extent-data bb) (- at (extent-base bb)))))))
      (format t "total: ~X~%content: ~S~%" (length dis) dis)
      (let* (forwards
             (outgoings (iter (with bb-start = 0) (while (< bb-start (length dis)))
                              (when bb (format t "last bb: ~X ~S~%" (extent-base bb) (extent-data bb)))
                              (for chain-bb = (when (and bb (bb-typep isa bb 'cond-branch-mixin))
                                                bb))
                              (for (values outgoing insn params) = (next-outgoing-branch bb-start))
                              (when outgoing (format t "got: ~X -> ~X~%"
                                                     bb-start (+ outgoing (isa-delay-slots isa))))
                              (for bb = (maybe-new-bb chain-bb bb-start
                                                      (if outgoing
                                                          (+ outgoing 1 (isa-delay-slots isa))
                                                          (length dis))))
                              (when bb ;; see maybe we're in forwards list, link, split and remove then
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
                                  (setf forwards destinated-further)))
                              (while outgoing)
                              ;; we deal only with
                              ;; relative, specified, local branches
                              (when-let* ((relative-p (typep insn 'rel-branch-mixin))
                                          (dest-fn (branch-destination-fn insn)))
                                (when bb (format t "processing a branch: [~X...] -> +~X, ~S,~%"
                                                 (extent-base bb)
                                                 (apply dest-fn params)
                                                 (type-of (bb-tail-insn isa bb))))
                                (when-let* ((delta (apply dest-fn params))
                                            (target (+ outgoing delta))
                                            (branch-local-p (and (>= target 0) (< target (length dis)))))
                                  (cond ((> delta 0) ;; is a forward reference? (past self)
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
        (format t "~%")))))

;; (defun lick-it ()
;;   (insn-vector-to-basic-blocks
;;    mips-assembly:*mips-isa*
;;    (car (elf:ehdr-sections (bintype:parse 'elf:ehdr (file-as-vector "pestilence/to4fpu/preparee.o"))
;;                            #'elf:shdr-executable-p))))