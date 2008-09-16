(in-package :unturing)

(defclass ivec (extent)
  ())

(defclass bb (ivec)
  ((ins :accessor bb-ins :type list :initarg :ins)
   (outs :accessor bb-outs :type list :initarg :outs))
  (:default-initargs
   :ins nil :outs nil))

(defun bb-tail-insn (bb)
  (elt (extent-data bb) (- (extent-length bb) 2)))

(defun bb-branches-p (bb)
  (typep (bb-tail-insn bb) 'branch-insn))

(defun link-bbs (from to)
  (push from (bb-ins to))
  (push to (bb-outs from)))

(defun insn-vector-to-basic-blocks (isa ivec &aux (*print-circle* nil))
  (let* ((dis (coerce (disassemble-u8-sequence isa (extent-data ivec)) 'vector))
         (tree (octree-1d:make-tree :length (extent-length ivec)))
         roots)
    (labels ((insn (i)
               (destructuring-bind (opcode width insn . params) (elt dis i)
                 (declare (ignore opcode width))
                 (values insn params)))
             (next-outgoing-branch (start)
               (iter (for i from start below (length dis))
                     (for (values insn params) = (insn i))
                     (when (typep insn 'branch-insn)
                       (return (values i insn params))))))
      (format t "total: ~X~%content: ~X~%" (length dis) dis)
      (let (forwards
            (outgoings (iter (with start = 0)
                             (when bb
                               (format t "bb: ~S ~S~%" (extent-base bb) (extent-data bb)))
                             (for chain-bb = (when (and bb (typep (bb-tail-insn bb) 'cond-branch-mixin))
                                               bb))
                             (for (values outgoing insn params) = (next-outgoing-branch start))
                             ;; see maybe we're in forwards list, link and remove then
                             (while outgoing)
                             ;; split backwards and stuff up forwards for later
                             (format t "got: ~S -> ~S~%" start outgoing)
                             (for bb = (make-instance 'bb
                                        :base start
                                        :data (apply #'subseq dis start
                                                     (when outgoing (list (+ outgoing 2))))))
                             (octree-1d:insert start bb tree)
                             (if chain-bb
                                 (link-bbs chain-bb bb)
                                 (push bb roots))
                             (collect (list outgoing insn params))
                             (format t "setting start from ~S to ~S~%" start (+ outgoing 2))
                             (setf start (+ outgoing 2)))))
        
        (format t "dis: ~S~%outgoings:~S~%" dis outgoings)))))

;; (defun lick-it ()
;;   (insn-vector-to-basic-blocks
;;    mips-assembly:*mips-isa*
;;    (car (elf:ehdr-sections (bintype:parse 'elf:ehdr (file-as-vector "pestilence/to4fpu/preparee.o"))
;;                            #'elf:shdr-executable-p))))