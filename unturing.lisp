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

(defmethod print-object ((o bb) s &aux (*print-level* nil) (*print-length* nil))
  (print-unreadable-object (o s :identity t)
    (format s "base: ~X, len: ~X, ins: ~{~X ~}, outs: ~{~X ~}"
            (extent-base o) (extent-length o)
            (mapcar #'extent-base (bb-ins o)) (mapcar #'extent-base (bb-outs o)))))

(defmethod pprint-object ((o bb) s &aux (*print-level* nil) (*print-length* nil))
  (print-unreadable-object (o s :identity t)
    (iter (for (nil nil mnemo . params) in-vector (extent-data o) with-index i)
          (pprint-logical-block (s nil)
            (format s "~8,'0X " (+ (extent-base o) i))
            (write mnemo :stream s :circle nil) (write #\Space :stream s :escape nil) 
            (dolist (p params)
              (write #\Space :stream s :escape nil) (write p :stream s :circle nil))
            (pprint-newline :mandatory s)))
    (format s "ins: ~S, outs: ~S" (mapcar #'extent-base (bb-ins o)) (mapcar #'extent-base (bb-outs o)))))

(defun bb-branchly-large-p (isa bb)
  (> (extent-length bb) (1+ (isa-delay-slots isa))))

;;; An important statement: we don't chop off BB's delay slots, so that the following invariant holds:
;;; (or (not (bb-typep bb 'branch-insn)) (and there-is-only-one-branch-exactly-where-expected))
(defun bb-branch-posn (isa bb)
  (- (extent-length bb) (1+ (isa-delay-slots isa))))

(defun bb-insn (bb i)
  (declare (type bb bb) (type (integer 0) i))
  (third (aref (extent-data bb) i)))

(defun bb-tail-insn (isa bb)
  "The type of BB is determined by its branch-posn instruction, or is PLAIN."
  (bb-insn bb (if (bb-branchly-large-p isa bb)
                  (bb-branch-posn isa bb)
                  (1- (extent-length bb)))))

(defun bb-typep (isa bb type)
  (typep (bb-tail-insn isa bb) type))

(defun bb-branch-p (isa bb)
  (bb-typep isa bb 'branch-insn))

(defun bb-leaf-p (isa bb)
  (not (bb-typep isa bb 'continue-mixin)))

(defun link-bbs (from to)
  (push from (bb-ins to))
  (push to (bb-outs from)))

(defun dis-printer-parameters (isa disivec)
  (values (bb-leaf-p isa disivec)
          (lambda (i)
            (format nil "~8,'0X " (+ (extent-base disivec) i)))
          (lambda (i)
            (format nil "~S" (cddr (aref (extent-data disivec) i))))
          (extent-length disivec)))

(defun insn-vector-to-basic-blocks (isa ivec &aux (*print-circle* nil))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let* ((dis (make-extent 'disivec 0 (coerce (disassemble-u8-sequence isa (extent-data ivec)) 'vector)))
         (tree (octree-1d:make-tree :length (extent-length ivec)))
         roots forwards)
    (labels ((insn (i)
               (destructuring-bind (opcode width insn . params) (aref (extent-data dis) i)
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
               (format t "new: ~X -> ~X, chain: ~S~%" start end (and chain-bb (extent-base chain-bb)))
               (lret ((bb (new-bb start end)))
                 (if chain-bb
                     (link-bbs chain-bb bb)
                     (push bb roots))))
             (flow-split-bb-at (bb at)
               "Splitting at delay slot is interesting."
               (declare (type bb bb) (type (integer 0) at))
               (lret* ((old-end (extent-end bb))
                       (delay-chop-p (and (bb-branch-p isa bb)
                                          (> at (+ (extent-base bb) (bb-branch-posn isa bb)))))
                       (new (new-bb at old-end :ins (list bb) :outs (bb-outs bb))))
                 ;; should be keep our invariant? two instances of code...
                 ;; bb outlinks to its chopped-off delay slot...
                 ;; hmm triple branches...
                 (unless delay-chop-p
                   (iter (for (fwd . rest) on forwards) ;; sift through forwards, updating for the split
                         (when (eq (second fwd) bb)
                           (setf (second fwd) new)))
                   (dolist (out (bb-outs bb))
                     (push new (bb-ins out)) ;; whoever bb outlinked to, new does, bb does not anymore
                     (removef (bb-ins out) bb))
                   (setf (bb-outs bb) nil
                         (extent-data bb) (adjust-array (extent-data bb) (- at (extent-base bb)))))
                 (push new (bb-outs bb)))))
      (format t "total: ~X~%content: ~S~%" (extent-length dis) (extent-data dis))
      (let* ((outgoings (iter (with bb-start = 0) (while (< bb-start (extent-length dis)))
                              (when bb (format t "last bb: ~S~%" bb))
                              (for chain-bb = (when (and bb (bb-typep isa bb 'pure-continue-mixin))
                                                bb))
                              (for (values outgoing insn params) = (next-outgoing-branch bb-start))
                              (for tail = (if outgoing (+ outgoing 1 (isa-delay-slots isa)) (extent-length dis)))
                              (for bb = (new-linked-bb chain-bb bb-start tail))
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
;;;                                            (format t "split back: ~X -> ~X~%"
;;;                                                    (extent-base source-bb) (extent-base link-target-bb))
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
(defun check-graph-validity (nodelist node-ins-fn node-outs-fn)
  "Validate NODELIST as a complete list of doubly-linked graph nodes, 
   with NODE-INS-FN and NODE-OUTS-FN serving as accessor functions."
  (labels ((node-ins (node) (funcall node-ins-fn node))
           (node-outs (node) (funcall node-outs-fn node))
           (node-listed-p (ref node)
             (unless (find node nodelist)
               (error "node ~S, as linked from known node~%~S~%... is missing from the specified nodelist.~%"
                      node ref)))
           (node-link-sanity-p (a b ins-p)
             (let ((refs (funcall (if ins-p #'node-outs #'node-ins) a))
                   (backrefs (funcall (if ins-p #'node-ins #'node-outs) b)))
               (unless (find a backrefs)
                 (error "node ~S,~%is missing a backref to ~S~%" b a)))))
    (iter (for node in nodelist)
          (dolist (out (node-outs node))
            (node-listed-p node out) (node-link-sanity-p node out t))
          (dolist (in (node-ins node))
            (node-listed-p node in) (node-link-sanity-p node in nil)))))

(defun pprint-bignode-graph-linear (nodelist &key node-parameters-fn (stream t)
                                    (node-width 30) suppress-flow-aligned-edges-p)
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let (fwds backs)
    (labels ((later-p (a b)
               (if (> (extent-length a) 1)
                   (>= (extent-base a) (extent-end b))
                   ;;; This is a DISGUSTING HACK! we should switch to chopping off delay slots, really...
                   ;;; patching up inconsistent graphs is just stupid. maybe.
                   (>= (extent-base a) (1- (extent-end b)))))
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
            (finally (setf (values fwds backs)
                           (values (make-array max-fwds :initial-element nil)
                                   (make-array max-backs :initial-element nil)))))
      (labels ((mark (pool from to &aux (slot (position from pool)))
                 (setf (aref pool slot) to)
                 slot)
               (render (in prepend marksyms reverse-p)
                 (let ((syms (if (listp marksyms) marksyms (make-circular-list 1 :initial-element marksyms)))
                       (stopdash (or (position :mark in :from-end t) 0)))
                   (coerce (funcall (if reverse-p #'nreverse #'identity)
                                    (append prepend (iter (for elt in-vector in with-index i)
                                                          (collect (cond ((null elt) (if (< i stopdash) #\- #\Space))
                                                                         ((eq elt :mark) (pop syms))
                                                                         (t #\|))))))
                           'string)))
               (trans-render (in from to sym has-p src-p mirror-p)
                 (mapc (rcurry (curry #'mark in) :mark) from)
                 (prog1 (render in (cond ((not has-p) '(#\Space #\Space))
                                         (src-p '(#\- #\-))
                                         (mirror-p '(#\> #\-))
                                         (t  '(#\< #\-))) sym mirror-p)
                   (mapc (curry #'mark in :mark) to)))
               (nil-extend (l to &aux
                              (missing (- to (length l)))
                              (ext (when (plusp missing) (make-list missing :initial-element nil))))
                 (if ext (nconc l ext) l))
               (nil-normalise (a b &aux (alen (length a)) (blen (length b)))
                 (cond ((= alen blen) (values a b))
                       ((> alen blen) (values a (nil-extend b alen)))
                       (t             (values (nil-extend a blen) b))))
               (mklist (for &optional stub) (make-list for :initial-element stub))
               (mkstub (list &optional stub) (mklist (length list) stub))
               (graph-slee (entry exit sym-entry sym-exit sym-both)
                 "Select characters for a single-line entry-exit join point."
                 (let ((enlen (length entry)) (exlen (length exit)))
                   (append (mklist (min enlen exlen) sym-both)
                           (mklist (abs (- enlen exlen)) (if (> enlen exlen) sym-entry sym-exit)))))
               (print-line (pre-pre pre core post)
                 (format stream (format nil "~~~DA~~~DA~~~DA~~~DA~%"
                                        9 (length fwds) node-width (length backs))
                         pre-pre pre core post)))
        (iter (for rest-nodes on nodelist) (for node = (car rest-nodes))
              (for (values separate-p preline-fn line-fn total) = (funcall node-parameters-fn node))
              (for (values ifree iall) = (unzip (curry #'later-p node) (node-ins node)))
              (for (values ofree oall) = (unzip (curry #'later-p node) (node-outs node)))
;;               (format t "bb ~D ~S~%" total node)
              (with suppressed-flow-aligned-edge = nil)
              (when suppress-flow-aligned-edges-p
                (removef ifree suppressed-flow-aligned-edge)
                (removef oall (second rest-nodes))
                (setf suppressed-flow-aligned-edge node))
              (iter (for i from 1 below total)
                    (initially
                     (if (= total 1) ;; i.e. totally run-in-hit-run-out specialcase...
                         (multiple-value-bind (nifree noall) (nil-normalise (mkstub ifree node) oall)
                           (multiple-value-bind (nofree niall) (nil-normalise (mkstub ofree node) iall)
                             (print-line (funcall preline-fn 0)
                                         (trans-render fwds nifree noall (graph-slee ifree oall #\` #\, #\>)
                                                       (or ifree oall) nil t)
                                         (funcall line-fn 0)
                                         (trans-render backs nofree niall (graph-slee ofree iall #\' #\. #\<)
                                                       (or ofree iall) t nil))))
                         (print-line (funcall preline-fn 0)
                                     (trans-render fwds (mkstub ifree node) (mkstub ifree) #\` ifree nil t)
                                     (funcall line-fn 0)
                                     (trans-render backs (mkstub iall) iall #\. iall nil nil)))
                     (when (or iall ifree)
                       (setf pre-line (render fwds '(#\Space #\Space) nil t))
                       (setf post-line (render backs '(#\Space #\Space) nil nil))))
                    (for indexline = (funcall preline-fn i))
                    (with pre-line = (render fwds '(#\Space #\Space) nil t))
                    (for nodeline = (funcall line-fn i))
                    (with post-line = (render backs '(#\Space #\Space) nil nil))
                    (if (or (= i (- total 1 1 #| (isa-delay-slots isa) |#))
                            (= total 2)) ;; can have a jump out
                        (progn
                          (print-line indexline (trans-render fwds (mkstub oall) oall #\, oall t t)
                                      nodeline (trans-render backs (mkstub ofree node) (mkstub ofree) #\' ofree t nil))
                          (when (or oall ofree)
                            (setf pre-line (render fwds '(#\Space #\Space) nil t))
                            (setf post-line (render backs '(#\Space #\Space) nil nil))))
                        (print-line indexline pre-line nodeline post-line))
                    (finally (when (or t separate-p)
                               (print-line "" pre-line "" post-line))))))
      (format t "processed ~D nodes, limits: fwd: ~D, back: ~D~%"
              (length nodelist) (length fwds) (length backs)))))
