;;
;;  Copyright (C) 2007  Samium Gromoff
;;
;; This piece of code is licenced under the terms of the Lesser GNU Public Licence.
;;
;; See:
;;   http://www.gnu.org/licenses/lgpl-3.0.txt
;;
;; The ISA is specified in terms of sewn bitrees[1].
;;
;; Bitree nodes specify:
;;  o  parent reference (that's the sewedness part),
;;  o  value completing the parent's bit-extent context into a bitree key[2],
;;  o  bit-extent context for childs.
;;
;; [1] The choice of name is somewhat arbitrary, for the lack of a better one.
;; [2] This implies that the root node doesn't have a meaningful bitree key.
;;
;; A bitree example:
;; 
;; -  context: #xff000000, value meaningless
;;  - value #xab, context #x00ff0000 => bitree key #xab000000
;;   - value #xf0, context #x0000ffff => bitree key #x00f00000
;;    - value #xdead, context meaningless => bitree key #x0000dead, resulting value #xabf0dead
;;    - value #xfeed, context meaningless => bitree key #x0000feed, resulting value #xabf0feed
;;  - value #xba, context #x00ff0000 => bitree key #xba000000
;;   - value #xad, context #x0000ffff => bitree key #x00ad0000
;;    - if there are no childs, this specifies just #xbaad----,
;;      where the dash-marks mean lack of specification.
;;      In fact the 32..infinity bits are unspecified just as well.
;;
(in-package :assembly)

(defstruct (node (:copier bitree-node-copy))
  parent
  (val 0 :type (unsigned-byte 64))
  (shift 0 :type (unsigned-byte 7))
  (mask 0 :type (unsigned-byte 64))
  childs
  contribution)

;; Shakey we are here...
(defun bitree-more-specific-p (s1 s2)
  "S1 has something more to inquire about, while S2 is final."
  (and (null (node-contribution s1))
       (node-contribution s2)))

(defun assemble-bitree-node-value (node)
  (labels ((node-bitlength (node) (+ (node-shift node) (integer-length (node-mask node))))
           (value-in-node (node val) (ash val (node-shift node)))
           (iterate (node id acc bitlength)
                    (cond ((null node)        (values 0 bitlength))
                          ((node-parent node) (iterate (node-parent node) (node-val node) (logior acc (value-in-node node id)) (max bitlength (node-bitlength node))))
                          (t                  (values (logior acc (value-in-node node id)) (max bitlength (node-bitlength node)))))))
    (iterate (node-parent node) (node-val node) 0 0)))

(defun value-bitree-node-tag (node val)
  (logand (node-mask node) (ash val (- (node-shift node)))))

(defun bitree-childs-matching-tag (node val)
  (remove val (node-childs node) :test (complement #'=) :key #'node-val))

(defun value-bitree-node-matches (node val)
  (bitree-childs-matching-tag node (value-bitree-node-tag node val)))

(defun bitree-node-set-contribution (node tag val)
  (when (node-contribution node)
    (error "~@<attempt to set contribution of node ~S, where it already has one~:@>" node))
  (first (push (make-node :val tag :parent node :contribution val) (node-childs node))))

(defun node-extraction (node &optional (pfc 7))
  (when node
    (list* (when-let ((parent (node-parent node)))
             (list (node-mask parent) (node-shift parent)))
           (node-val node)
           (when (plusp pfc)
             (append
              (when (first (node-childs node)) (list :fc (node-extraction (first (node-childs node)) (1- pfc))))
              (when (second (node-childs node)) (list :sc (node-extraction (second (node-childs node)) (1- pfc))))))
           (when-let ((c (node-contribution node)))
             (list
              (etypecase c
                (insn (insn-mnemonics c))
                (iformat (iformat-mnemonics c))))))))

(defun bitree-insert-spec (bitree spec-list &key dont-coalesce)
  (labels ((iterate (bitree spec-list contributing-nodes)
             (cond
               ((endp spec-list) (nreverse contributing-nodes))
               (t
                (destructuring-bind ((id shift mask &key contribution (dont-coalesce dont-coalesce)) . rest) spec-list
                  (let ((choice (or (and (not dont-coalesce) (first (remove-if-not (lambda (node) (and (= shift (node-shift node))
                                                                                                   (= mask (node-mask node))))
                                                                               (bitree-childs-matching-tag bitree id))))
                                    (first (push (make-node :val id :parent bitree :shift shift :mask mask :contribution contribution)
                                                 (node-childs bitree)))))
                        (*print-right-margin* 140))
                    (iterate choice rest (prepend (when contribution choice) contributing-nodes))))))))
    (iterate bitree spec-list nil)))

(defun bitree-leaf-nconc-node (where what)
  "Nconc WHAT at the bitree leaf WHERE."
  (when (node-childs where)
    (error "~@<node ~S is not a leaf~:@>" where))
  (when-let ((parent (node-parent what)))
    (copy-slots where parent '(shift mask)))
  (setf (node-parent what) where)
  (push what (node-childs where)))

(defstruct mnemonicable
  (mnemonics nil :type keyword))

(defun bitree-discriminate-value (node value &key (test nil testp))
  "Given a bitree NODE, yield the list of all contributing nodes down the discrimination path for VALUE."
  (declare (type function test))
;;;   (format t "discriminating ~X~%" value)
  (labels ((discriminate (node acc)
             (let ((acc (prepend node acc :test #'node-contribution)))
;;;                (when (node-contribution node)
;;;                  (format t "acc is now ~S~%" (mapcar (compose #'mnemonicable-mnemonics #'node-contribution) acc)))
               (if (null (node-childs node))
                   acc
                   (let ((partial-matches (sort (copy-list (value-bitree-node-matches node value)) #'bitree-more-specific-p)))
;;           (format t "going within mask ~X << ~D: ~S~%" (node-mask node) (node-shift node)
;;                   (mapcar #'node-val (value-bitree-node-matches node value))
;;                   #+nil (mapcar #'node-val partial-matches))
                     (iter (for partial-match in partial-matches)
                           (for match = (discriminate partial-match acc))
                           (finding match such-that (maybecall (and match testp) (curry test value) match))))))))
    (nreverse (discriminate node nil))))

(defun make-node-spec (&rest params &key (val 0) (shift 0) (mask 0) &allow-other-keys)
  (list* val shift mask (remove-from-plist params :val :shift :mask)))

(defstruct (mnemocode (:include mnemonicable))
  (opcode 0 :type (unsigned-byte 64)))

(defstruct (insn (:include mnemocode))
  (width 0 :type integer)
  (node nil :type (or null node)))

(defmethod print-object ((o insn) stream)
  (write (insn-mnemonics o) :stream stream :circle nil))

(defstruct (unknown-insn (:include insn (mnemonics :unknown))))

(defstruct (branch-insn (:include insn))
  (dest-fn #'values :type (or null function)))

(defstruct (cond-branch-insn (:include branch-insn)))
(defstruct (abs-branch-insn (:include branch-insn)))
(defstruct (rel-branch-insn (:include branch-insn)))
(defstruct (exception-insn (:include branch-insn)))

(defstruct (iformat (:include mnemocode))
  (width 0 :type integer)
  (node nil :type (or null node))
  (params () :type list))

(defclass isa ()
  ((insn-defines-format-p :accessor isa-insn-defines-format-p :initarg :insn-defines-format-p)
   (insn-root :accessor isa-insn-root)
   (iformat-root :accessor isa-iformat-root)
   (paramtype# :accessor isa-paramtype# :initarg :paramtype#)
   (insn# :accessor isa-insn# :initarg :insn#)
   (final-discriminator :accessor isa-final-discriminator :initarg :final-discriminator)
   (iformat# :accessor isa-iformat# :initarg :iformat#)
   (delay-slots :accessor isa-delay-slots :initarg :delay-slots))
  (:default-initargs
   :insn-defines-format-p nil
   :final-discriminator #'values
   :paramtype# (make-hash-table :test #'eq)
   :insn# (make-hash-table :test #'equal)
   :iformat# (make-hash-table :test #'eq)))

(defmethod initialize-instance :after ((isa isa) &key insn-defines-format-p root-shift root-mask format-root-shift format-root-mask &allow-other-keys)
  (declare (type unsigned-byte root-shift root-mask))
  (setf (isa-insn-root isa) (make-node :val 0 :shift root-shift :mask root-mask))
  (unless insn-defines-format-p
    (setf (isa-iformat-root isa) (make-node :val 0 :shift format-root-shift :mask format-root-mask))))

(defgeneric validate-insn-parameter-spec (isa insn param-spec))
(defgeneric encode-insn-param (isa val type))
(defgeneric decode-insn-param (isa val type))

(defun paramtype-width (isa mnemonics) (or (gethash mnemonics (isa-paramtype# isa)) (error "unknown PARAMTYPE ~S" mnemonics)))
(defun iformat (isa mnemonics) (gethash mnemonics (isa-iformat# isa)))
(defun insn (isa mnemonics) (gethash mnemonics (isa-insn# isa)))

(defun define-iformat (isa mnemonics spec params &key dont-coalesce)
  (let* ((iformat (make-iformat :mnemonics mnemonics :params params))
         (node (if (isa-insn-defines-format-p isa)
                   (make-node :contribution iformat)
                   (first (bitree-insert-spec (isa-iformat-root isa) (append spec (list (make-node-spec :contribution iformat))) :dont-coalesce dont-coalesce)))))
    (multiple-value-bind (opcode discrim-width) (assemble-bitree-node-value node)
      (setf (iformat-node iformat) node
            (iformat-opcode iformat) opcode
            (iformat-width iformat) (max discrim-width (or (first (sort (mapcar (lambda (p) (+ (paramtype-width isa (car p)) (cadr p))) params) #'>)) 0))
            (gethash mnemonics (isa-iformat# isa)) iformat))))

;; opcode spec is a list of:
;;	either (PARENT-CONTEXT-VALUE CHILD-CONTEXT-SHIFT . CHILD-CONTEXT-MASK)
;;	or PARENT-CONTEXT-VALUE
(defun define-insn (isa type mnemonics spec &rest rest &key format-name dont-coalesce &allow-other-keys)
  (let* ((insn (apply (case type
                        (insn #'make-insn)
                        (branch-insn (error "BRANCH-INSN is an intermediate type and should not be used"))
                        (cond-branch-insn #'make-cond-branch-insn)
                        (abs-branch-insn #'make-abs-branch-insn)
                        (rel-branch-insn #'make-rel-branch-insn)
                        (exception-insn #'make-exception-insn))
                :mnemonics mnemonics (remove-from-plist rest :format-name :dont-coalesce)))
         (spec (append spec (list (make-node-spec :contribution insn))))
         (node (first (bitree-insert-spec (isa-insn-root isa) spec :dont-coalesce dont-coalesce)))
         (iformat (iformat isa format-name)))
    (cond (format-name
           (unless iformat
             (error "in DEFINE-INSN ~S: format ~S unknown" mnemonics format-name))
           (unless (isa-insn-defines-format-p isa)
             (error "in DEFINE-INSN ~S: specified format ~S, but the ISA ~S does too" mnemonics format-name isa)))
          ((isa-insn-defines-format-p isa)
           (error "in DEFINE-INSN ~S: format neither specified directly, nor deducible by ISA" mnemonics)))
    (multiple-value-bind (opcode discrim-width) (assemble-bitree-node-value node)
      (setf (insn-node insn) node
            (insn-opcode insn) opcode
            (insn-width insn) discrim-width
            (gethash mnemonics (isa-insn# isa)) insn))
    (bitree-leaf-nconc-node node (bitree-node-copy (if (isa-insn-defines-format-p isa)
                                                       (iformat-node iformat)
                                                       (isa-iformat-root isa))))))

(defun defparamtype (isa mnemonics width)
  (setf (gethash mnemonics (isa-paramtype# isa)) width))

(defmacro defformat (isa mnemonics format-spec param-spec &key dont-coalesce)
  `(define-iformat ,isa ,mnemonics ,format-spec (list ,@(iter (for (type offt) in param-spec)
                                                              (collect `(list ',type ,offt))))
                   ,@(when dont-coalesce `(:dont-coalesce ,dont-coalesce))))

;;; Bogus wrapper? Maybe not, futurewise.
(defmacro definsn (isa type mnemonics opcode-spec &rest rest)
  `(define-insn ,isa ,type ,mnemonics ,opcode-spec ,@rest))

(defun encode-insn (isa id &rest params)
  (if-let* ((insn (insn isa id))
            (iformat (if (isa-insn-defines-format-p isa)
                         (node-contribution (first (node-childs (insn-node insn))))
                         (iformat isa :empty))))
	  (iter (for param in params)
                (for (type offt) in (iformat-params iformat))
                (unless (typep param type)
                  (error "~@<opcode ~S expects parameters ~S, got ~S~:@>" id (mapcar #'car (iformat-params iformat)) params))
                (for acc initially (insn-opcode insn) then (logior acc (ash (encode-insn-param isa param type) offt)))
                (finally (return acc)))
	  (error "~@<ISA ~S does not specify insn ~S~:@>" isa id)))

(defmacro assemble-into-u8-vector ((isa base vector) &body insns)
  (once-only (isa vector)
    `(let ((insns (list ,@(iter (for insn in insns) (collect `(list ,@insn))))))
       (iter (for insn in insns) (for offset from ,base by 4)
	     (setf (u8-vector-word32le ,vector offset) (apply #'encode-insn ,isa insn))))))

(defun decode-iformat-params (isa iformat opcode)
  (iter (for (type shift) in (iformat-params iformat))
        (collect (decode-insn-param isa (ash opcode (* -1 shift)) type))))

(defun decode-insn (isa opcode)
  (if-let ((ret (bitree-discriminate-value (isa-insn-root isa) opcode :test (isa-final-discriminator isa))))
          (destructuring-bind (insn-node iformat-node) ret
            (let ((insn (node-contribution insn-node))
                  (iformat (node-contribution iformat-node)))
;;               (format t "insn ~S, iformat ~S~%" (insn-mnemonics insn) (iformat-mnemonics iformat))
              (values (cons (insn-mnemonics insn) (decode-iformat-params isa iformat opcode))
                      (max (insn-width insn) (iformat-width iformat)))))
          (values (list :unknown opcode) 32)))

(defun disassemble-u8-sequence (isa seq &aux (length (length seq)))
  (iter (with offt = 0) (until (>= offt length))
        (for piece = (min 8 (- length offt)))
        (for opcode = (ecase piece
                        (4 (u8-seq-word32le seq offt))
                        (8 (u8-seq-word64le seq offt))))
        (for (values (mnemonics . params) insn-width) = (decode-insn isa opcode))
        (for step = (ash (1+ (ash (or (1- insn-width) 32) -5)) 2))
        (incf offt step)
	(collect (list* (logand (1- (ash 1 (ash step 3))) opcode) step mnemonics params))))
