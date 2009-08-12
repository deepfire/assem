;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: UNTURING; Base: 10 -*-
;;;
;;;  (c) copyright 2007-2008 by
;;;           Samium Gromoff (_deepfire@feelingofgreen.ru)
;;;
;;; This library is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU Library General Public
;;; License as published by the Free Software Foundation; either
;;; version 2 of the License, or (at your option) any later version.
;;;
;;; This library is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Library General Public License for more details.
;;;
;;; You should have received a copy of the GNU Library General Public
;;; License along with this library; if not, write to the
;;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;;; Boston, MA  02111-1307  USA.

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

(defstruct (bons (:constructor bons (bar bdr)) (:conc-name nil))
  (bar nil :type (or null bb)) (bdr nil :type (or null bb)))

(defun bons-path (bons &aux (seen (make-hash-table :test #'eq)))
  (labels ((rec (at)
             (unless (gethash at seen)
               (setf (gethash at seen) t)
               (if (eq at (bdr bons))
                   (list at)
                   (iter (for try in (unturing:bb-outs at))
                         (when-let (out (rec try))
                           (return (cons at out))))))))
    (rec (bar bons))))

(defun all-bons-paths (bons &aux (seen (make-hash-table :test #'eq)))
  (labels ((finder-rec (at)
             (unless (gethash at seen)
               (setf (gethash at seen) t)
               (if (eq at (bdr bons))
                   (list at)
                   (iter (for try in (unturing:bb-outs at))
                         (when-let (out (finder-rec try))
                           (collect (cons at out))))))))
    (lret ((tree (finder-rec (bar bons)))
           paths)
      (labels ((decoder-rec (at acc)
                 (if (eq (car at) (bdr bons))
                     (push (reverse (nconc at acc)) paths)
                     (iter (for (node . paths) in at)
                           (decoder-rec paths (cons node acc))))))
        (decoder-rec tree nil)))))

(defun shortest-bons-path (bons)
  (first (sort (all-bons-paths bons) #'< :key #'length)))

(defun bons-connected-p (bons)
  (not (null (bons-path bons))))

(defclass linked-bb (bb)
  ((addr :accessor linked-addr :initarg :addr)
   (reg :accessor linked-reg :initarg :reg)
   (to :accessor linked-to :initarg :to)))

(defmethod print-object ((o bb) s &aux (*print-level* nil) (*print-length* nil))
  (print-unreadable-object (o s :identity t)
    (format s "base: ~X, len: ~X, ins: ~{~X ~}, outs: ~{~X ~}"
            (base o) (size o)
            (mapcar #'base (bb-ins o)) (mapcar #'base (bb-outs o)))))

(defgeneric pprint-object (object stream))
(defmethod pprint-object ((o bb) s &aux (*print-level* nil) (*print-length* nil))
  (print-unreadable-object (o s :identity t)
    (loop :for (nil nil mnemo . params) :across (extent-data o)
          :for i :from 0 :do
       (pprint-logical-block (s nil)
         (format s "~8,'0X " (+ (base o) i))
         (write mnemo :stream s :circle nil) (write #\Space :stream s :escape nil) 
         (dolist (p params)
           (write #\Space :stream s :escape nil) (write p :stream s :circle nil))
         (pprint-newline :mandatory s)))
    (format s "ins: ~S, outs: ~S" (mapcar #'base (bb-ins o)) (mapcar #'base (bb-outs o)))))

(defun make-pseudo-bb (mnemonics start)
  (make-instance 'bb :base start :data (make-array 1 :initial-contents (list `(0 0 ,(make-pseudo-insn mnemonics))))))

(defun bb-branchly-large-p (isa bb)
  (> (size bb) (isa-delay-slots isa)))

;;; An important statement: we don't chop off BB's delay slots, so that the following invariant holds:
;;; (or (not (bb-typep bb 'branch-insn)) (and there-is-only-one-branch-exactly-where-expected))
;;; An important result: this policy appears to be very costly.
(defun bb-branch-posn (isa bb)
  (- (size bb) (1+ (isa-delay-slots isa))))

(defun bb-insn (bb i)
  (declare (type bb bb) (type (integer 0) i))
  (third (aref (extent-data bb) i)))

(defun bb-tail-insn (isa bb)
  "The type of BB is determined by its branch-posn instruction, or is PLAIN."
  (bb-insn bb (if (bb-branchly-large-p isa bb)
                  (bb-branch-posn isa bb)
                  (1- (size bb)))))

(defun bb-typep (isa bb type)
  (typep (bb-tail-insn isa bb) type))

(defun bb-branch-p (isa bb)
  (bb-typep isa bb 'branch-insn))

(defun bb-leaf-p (isa bb)
  (not (bb-typep isa bb 'continue-mixin)))

(defun link-bbs (from to)
  (push from (bb-ins to))
  (push to (bb-outs from)))

;; (defun maptree-bb-backpaths (fn bb allotment &aux (this-len (size bb)))
;;   (if (or (<= allotment this-len) (null (bb-ins bb)))
;;       (list (funcall fn bb allotment))
;;       (iter (with this-edge = (funcall fn bb this-len))
;;             (for in in (mappend (rcurry #'map-bb-backpaths (- allotment this-len)) (bb-ins bb)))
;;             (collect (cons this-edge in)))))

(defun mapt-bb-paths (fn allotment bb &key (key #'bb-outs) &aux (this-len (size bb)))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (funcall fn bb allotment)
  (when (> allotment this-len)
    (dolist (bb (funcall key bb))
      (mapt-bb-paths fn (- allotment this-len) bb :key key))))

(defmacro do-path-internal-nodes ((nodevar path) &body body)
  (with-gensyms (rest)
    `(iter (for (,nodevar . ,rest) on (rest ,path))
           (when ,rest
             ,@body))))

(defun bb-graph-within-distance-set (nodelist distance)
  "Expand NODELIST with set of nodes within DISTANCE."
  (remove-duplicates
   (lret (bbs)
     (labels ((note-bb (bb rest-distance)
                (declare (ignore rest-distance))
                (push bb bbs)))
       (dolist (start-node nodelist)
         (note-bb start-node 0)
         (mapt-bb-paths #'note-bb distance start-node :key #'bb-ins)
         (mapt-bb-paths #'note-bb distance start-node :key #'bb-outs))))))

(defun default-node-parameter-extractor (isa disivec)
  (values (bb-leaf-p isa disivec)
          (size disivec)
          (lambda (i)
            (format nil "~8,'0X " (+ (base disivec) i)))
          (lambda (i)
            (format nil "~S" (cddr (aref (extent-data disivec) i))))
          (constantly "")))

(defun insn-vector-to-basic-blocks (isa ivec &aux (*print-circle* nil))
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let* ((dis (make-extent 'disivec (ash (base ivec) -2) ;; the assumption for fixed-opcode-length 32bit arch..
                           (coerce (disassemble isa ivec) 'vector)))
         (tree (octree-1d:make-tree :start (1- (base dis)) :length (+ (size dis) 2)))
         roots forwards)
    (labels ((insn (i)
               (destructuring-bind (opcode width insn . params) (aref (extent-data dis) (- i (base dis)))
                 (declare (ignore opcode width))
                 (values insn params)))
             (next-outgoing-branch (bb-start)
               "Find the closest outgoing branch after bb-start."
               (iter (for i from bb-start below (end dis))
                     (for (values insn params) = (insn i))
                     (when (typep insn 'branch-insn)
                       (return (values i insn params)))))
             (new-bb (start end &rest rest &key (data (make-array (- end start) :adjustable t
                                                                  :initial-contents (subseq (extent-data dis) 
                                                                                            (- start (base dis))
                                                                                            (- end (base dis)))))
                      &allow-other-keys)
               (declare (type integer start end))
               (lret ((bb (apply #'make-instance 'bb :base start :data data (remove-from-plist rest :data))))
                 (octree-1d:insert start bb tree)))
             (new-pseudo-bb (mnemonics at) (lret ((bb (make-pseudo-bb mnemonics at))) (octree-1d:insert at bb tree)))
             (new-linked-bb (chain-bb start end)
               "Create and chain/insert a BB START<->END, if only its length would be positive."
               (declare (type (or null bb) chain-bb) (type (integer 0) start end))
               (lret ((bb (new-bb start end)))
                 (if chain-bb
                     (link-bbs chain-bb bb)
                     (push bb roots))))
             (flow-split-bb-at (bb at)
               "Splitting at delay slot is interesting."
               (declare (type bb bb) (type (integer 0) at))
               (let* ((old-end (end bb))
                      (delay-chop-p (and (bb-branch-p isa bb)
                                         (> at (+ (base bb) (bb-branch-posn isa bb)))))
                      (new (new-bb at old-end :ins (list bb) :outs (bb-outs bb))))
                 ;; (format t "SPLIT  pre bb: ~S~%" bb)
                 ;; (format t "SPLIT  pre outs: ~{~S~_ ~}~%" (bb-outs bb))
                 ;; should be keep our invariant? two instances of code...
                 ;; bb outlinks to its chopped-off delay slot...
                 ;; hmm triple branches...
                 (if (unless delay-chop-p
                       (iter (for (fwd . rest) on forwards) ;; sift through forwards, updating for the split
                             (when (eq (second fwd) bb)
                               (setf (second fwd) new)))
                       (dolist (out (bb-outs bb))
                         (push new (bb-ins out)) ;; whoever bb outlinked to, new does, bb does not anymore
                         (removef (bb-ins out) bb))
                       (setf (bb-outs bb) nil
                             (extent-data bb) (adjust-array (extent-data bb) (- at (base bb)))))
                     t (format t "delay chop: ~S~%" bb))
                 (push new (bb-outs bb))
                 ;; (format t "SPLIT post b : ~S~%" bb)
                 ;; (format t "SPLIT post  b: ~S~%" new)
                 ;; (format t "SPLIT post outs: ~{~S~_ ~}~%" (bb-outs new))
                 (values new delay-chop-p))))
      ;; (format t "total: ~X~%content: ~S~%" (size dis) (extent-data dis))
      (let* (minus-infinity plus-infinity)
        (iter (with bb-start = (base dis)) (while (< bb-start (end dis)))
              (with last-branch-was-nop-p = nil)
              (for chain-bb = (when (and bb (or (bb-typep isa bb 'pure-continue-mixin) last-branch-was-nop-p))
                                (setf last-branch-was-nop-p nil)
                                bb))
              (for (values outgoing insn params) = (next-outgoing-branch bb-start))
              (for tail = (if outgoing (+ outgoing 1 (isa-delay-slots isa)) (end dis)))
              (for bb = (new-linked-bb chain-bb bb-start tail))
              (multiple-value-bind (destinated-at-us destinated-further)
                  (unzip (curry #'inp bb) forwards :key #'car)
                (when destinated-at-us
                  (iter (for (target srcbb) in (sort destinated-at-us #'< :key #'car))
                        ;; watch the code below carefully for "coincidences"...
                        ;; (format t "resolved forward: ~X -> ~X~%" (base srcbb) target)
                        (with target-bb = bb)
                        (let ((split-p (not (= target (base target-bb)))))
                          (multiple-value-bind (link-target delay-chop-p)
                              (if split-p
                                  (flow-split-bb-at target-bb target)
                                  target-bb)
                            (link-bbs srcbb link-target)
                            (when split-p
                              (setf target-bb link-target)
                              (unless delay-chop-p ;; heck, is it worth the complications, already...
                                (setf bb target-bb)))))))
                (setf forwards destinated-further))
              (while outgoing)
              ;; we deal only with
              ;; relative, specified, local branches
              (when-let* ((immediate-p (typep insn 'branch-imm))
                          (dest-fn (branch-destination-fn insn)))
                ;; (format t "processing a branch: [~X...] -> +~X, ~S,~%"
                ;;         (base bb)
                ;;         (apply dest-fn params)
                ;;         (type-of (bb-tail-insn isa bb)))
                (when-let* ((delta (apply dest-fn outgoing params))
                            (target (+ outgoing delta)))
                  (cond ((>= target (end dis))
                         (let ((inf (or plus-infinity
                                        (setf plus-infinity (new-pseudo-bb :tail (end dis))))))
                           (link-bbs bb inf)))
                        ((< target (base dis))
                         (let ((inf (or minus-infinity
                                        (setf minus-infinity (new-pseudo-bb :head (1- (base dis)))))))
                           (link-bbs bb inf)))
                        ((> delta (isa-delay-slots isa)) ;; past this bb?
                         ;; (format t "pushing a forward: ~X -> ~X~%" (base bb) target)
                         (push (list target bb) forwards))
                        ((< delta 0) ;; a back reference...
                         (let* ((target-bb (oct-1d:tree-left target tree))
                                (split-p (not (= target (base target-bb))))
                                (link-target-bb (if split-p
                                                    (flow-split-bb-at target-bb target)
                                                    target-bb))
                                (hit-self-p (eq target-bb bb))
                                (self-superseded-p (and split-p hit-self-p))
                                (source-bb (if self-superseded-p link-target-bb bb)))
                           ;; (format t "split back: ~X -> ~X~%"
                           ;;         (base source-bb) (base link-target-bb))
                           (link-bbs source-bb link-target-bb)
                           (when self-superseded-p
                             (setf bb source-bb)))) ;; the chain-bb of the next turn..
                        ((= delta (isa-delay-slots isa))
                         (setf last-branch-was-nop-p t))))) ;; is a NOP branch? should just ignore them.
              (collect (list outgoing insn params))
              (setf bb-start (+ outgoing 1 (isa-delay-slots isa))))
        (when forwards
          (format t "unresolved forwards: ~S, ~S~%" (length forwards) (mapcar #'car forwards)))
        (values (oct-1d:tree-list tree) tree)))))

(defun bbnet-tree (bbnet)
  "Reconstruct the octree for the BB netlist."
  (lret (tree)
    (iter (for bb in bbnet)
          (minimize (base bb) into base)
          (maximize (end bb) into end)
          (finally (setf tree (oct-1d:make-tree :start base :length (- end base)))))
    (iter (for bb in bbnet)
        (oct-1d:insert (base bb) bb tree))))

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
             (unless (find a (funcall (if ins-p #'node-ins #'node-outs) b))
               (error "node ~S,~%is missing a backref to ~S~%" b a))))
    (iter (for node in nodelist)
          (dolist (out (node-outs node))
            (node-listed-p node out) (node-link-sanity-p node out t))
          (dolist (in (node-ins node))
            (node-listed-p node in) (node-link-sanity-p node in nil)))))

(defun pprint-node-graph-linear (nodelist &key node-parameters-fn (stream t)
                                    (node-width 30) suppress-flow-aligned-edges-p force-node-separation-p)
  (declare (optimize (speed 0) (space 0) (debug 3) (safety 3)))
  (let (fwds backs)
    (labels ((later-p (a b)
               (if (> (size a) 1)
                   (>= (base a) (end b))
                   ;;; This is a DISGUSTING HACK! we should switch to chopping off delay slots, really...
                   ;;; patching up inconsistent graphs is just stupid. maybe.
                   (>= (base a) (1- (end b)))))
             (node-ins (node)
               (bb-ins node))
             (node-outs (node)
               (bb-outs node)))
      (iter (for node in nodelist)
            (for (values nil f-pending) = (unzip (curry #'eq node) fwds))
            (for (values nil b-pending) =  (unzip (curry #'eq node) backs))
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
               (print-line (prefix left-graph node right-graph suffix)
                 (format stream (format nil "~~~DA~~~DA~~~DA~~~DA~~A~~%"
                                        9 (length fwds) node-width (length backs))
                         prefix left-graph node right-graph suffix)))
        (iter (for rest-nodes on nodelist) (for node = (car rest-nodes))
              (for (values separate-p total prefix-string-fn node-string-fn suffix-string-fn) = (funcall node-parameters-fn node))
              (for (values ifree iall) = (unzip (curry #'later-p node) (node-ins node)))
              (for (values ofree oall) = (unzip (curry #'later-p node) (node-outs node)))
;;               (format t "bb ~D ~S~%" total node)
;;               (format t "bb ~S~%backpaths: " node) (mapt-bb-backpaths (curry (formatter "~S:~S ") t) node 10) (terpri)
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
                             (print-line (funcall prefix-string-fn 0)
                                         (trans-render fwds nifree noall (graph-slee ifree oall #\` #\, #\>)
                                                       (or ifree oall) nil t)
                                         (funcall node-string-fn 0)
                                         (trans-render backs nofree niall (graph-slee ofree iall #\' #\. #\<)
                                                       (or ofree iall) t nil)
                                         (funcall suffix-string-fn 0))))
                         (print-line (funcall prefix-string-fn 0)
                                     (trans-render fwds (mkstub ifree node) (mkstub ifree) #\` ifree nil t)
                                     (funcall node-string-fn 0)
                                     (trans-render backs (mkstub iall) iall #\. iall nil nil)
                                     (funcall suffix-string-fn 0)))
                     (when (or iall ifree)
                       (setf left-graph-string (render fwds '(#\Space #\Space) nil t)
                             right-graph-string (render backs '(#\Space #\Space) nil nil))))
                    (for line-prefix-string = (funcall prefix-string-fn i))
                    (with left-graph-string = (render fwds '(#\Space #\Space) nil t))
                    (for node-string = (funcall node-string-fn i))
                    (with right-graph-string = (render backs '(#\Space #\Space) nil nil))
                    (for line-suffix-string = (funcall suffix-string-fn i))
                    (if (or (= i (- total 1 1 #| (isa-delay-slots isa) |#))
                            (= total 2)) ;; can have a jump out
                        (progn
                          (print-line line-prefix-string (trans-render fwds (mkstub oall) oall #\, oall t t)
                                      node-string (trans-render backs (mkstub ofree node) (mkstub ofree) #\' ofree t nil)
                                      line-suffix-string)
                          (when (or oall ofree)
                            (setf left-graph-string (render fwds '(#\Space #\Space) nil t)
                                  right-graph-string (render backs '(#\Space #\Space) nil nil))))
                        (print-line line-prefix-string left-graph-string node-string right-graph-string line-suffix-string))
                    (finally (when (or force-node-separation-p separate-p)
                               (print-line "" left-graph-string "" right-graph-string ""))))))
;;       (format t "processed ~D nodes, limits: fwd: ~D, back: ~D~%"
;;               (length nodelist) (length fwds) (length backs))
      )))
