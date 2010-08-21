;;; -*- Mode: LISP; Syntax: COMMON-LISP; Package: ASSEMBLY; Base: 10 -*-
;;;
;;;  (c) copyright 2010 by
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

(in-package :isa-amd64)

(defclass newisa ()
  ((name           :reader isa-name        :initarg :name)
   (format-type    :reader isa-format-type :initarg :format-type)
   (noop           :reader isa-noop        :initarg :noop)
   (delay-slots    :reader isa-delay-slots :initarg :delay-slots)
   (root           :reader isa-root)
   (id->attrset                            :initarg :id->attrset)
   (id->argtype                            :initarg :id->argtype)
   (id->uformat                            :initarg :id->uformat)
   (id->format                             :initarg :id->format)
   (mnemo/opcode->format                   :initarg :mnemo/opcode->format)
   (mnemo/arglist->formats                 :initarg :mnemo/arglist->formats)
   (id->correspondence                     :initarg :id->correspondence))
  (:default-initargs
   :id->attrset              (make-hash-table :test 'eq)
   :id->argtype              (make-hash-table :test 'eq)
   :id->uformat              (make-hash-table :test 'eq)
   :id->format               (make-hash-table :test 'equal)
   :mnemo/opcode->format     (make-hash-table :test 'equal)
   :mnemo/arglist->formats   (make-hash-table :test 'equal)
   :id->correspondence       (make-hash-table :test 'eq)))

(defvar *isa*)

(defmacro define-isa (name (&optional (superclasses '(newisa))) (&key (format-type 'instruction-format) (noop :nop) (delay-slots 0))
                      (&rest slots)
                      &body options)
  (let ((default-initargs (list* :format-type `',format-type
                                 :noop noop
                                 :delay-slots delay-slots
                                 (cdr (assoc :default-initargs options :key #'car))))
        (global-name (format-symbol (symbol-package name) "*~A*" (symbol-name name))))
    `(progn
       (defclass ,name (,@superclasses)
         (,@slots)
         (:default-initargs ,@default-initargs)
         ,@(remove :default-initargs options :key #'car))
       (defparameter ,global-name (make-instance ',name))
       (setf *isa* ,global-name))))

(define-isa amd64-isa () ()
  ())

#|

Verbal description of how we will go.

|#

(defstruct (attribute-set (:conc-name attrset-))
  (name       nil                            :type symbol     :read-only t)
  (key->value (make-hash-table :test 'eq)    :type hash-table :read-only t)
  (value->key (make-hash-table :test 'equal) :type hash-table :read-only t))

(define-subcontainer attrset :type attribute-set :container-slot id->attrset :if-exists :continue)

(define-subcontainer value :type t      :container-slot key->value :if-exists :continue)
(define-subcontainer key   :type symbol :container-slot value->key :if-exists :continue)

(defun ensure-attribute-set (isa name key/value-pairs)
  (let ((a (make-attribute-set :name name)))
    (iter (for (key . value) in key/value-pairs)
          (setf (value a key) value
                (key a value) key))
    (setf (attrset isa name) a)))

(defmacro define-attribute-set (name &body attrset-spec)
  `(ensure-attribute-set *isa* ,name ',attrset-spec))


(define-attribute-set :nrex
  (:nrex0 . #b0000) (:nrex1 . #b0001) (:nrex2 . #b0010) (:nrex3 . #b0011)
                    (:nrex5 . #b0101) (:nrex6 . #b0110) (:nrex7 . #b0111)
  (:nrex8 . #b1000) (:nrex9 . #b1001) (:nrexa . #b1010) (:nrexb . #b1011)
  (:nrexc . #b1100) (:nrexd . #b1101) (:nrexe . #b1110) (:nrexf . #b1111))
(define-attribute-set :rex
  (:rex4 .  #b0100))
(define-attribute-set :opersz/p
  (:opersz .        #x66))
(define-attribute-set :addrsz
  (:addrsz .        #x67))
(define-attribute-set :overseg
  (:cs .            #x2e)
  (:ds .            #x3e)
  (:es .            #x26)
  (:fs .            #x64)
  (:gs .            #x65)
  (:ss .            #x36))
(define-attribute-set :lock
  (:lock .          #xf0))
(define-attribute-set :rep/p
  (:rep .           #xf3))
(define-attribute-set :repn/p
  (:repn .          #xf2))
(define-attribute-set :xop
  (:xop .           #x0f))
(define-attribute-set :3dnow
  (:3dnow .         #x0f))

(define-attribute-set :all-rex
  :rex :nrex)

(define-attribute-set :all-legacy
  :opersz/p :addrsz :overseg :lock :rep/p :repn/p)

(defstruct (microformat (:conc-name uformat-))
  "Connect sub-byte bit-structurings to attributes."
  (id    nil :type symbol :read-only t)
  (names nil :type list   :read-only t)
  (bytes nil :type list   :read-only t))

(define-subcontainer uformat :type microformat :container-slot id->uformat :if-exists :continue)

(defun ensure-microformat (isa name name/byte-pairs)
  (let ((u (make-microformat :id name :names (mapcar #'car name/byte-pairs) :names (mapcar #'cdr name/byte-pairs))))
    (setf (uformat isa name) u)))

(defmacro define-microformat (name &body name/byte-pairs)
  `(ensure-microformat *isa* ,name ',name/byte-pairs))

(define-microformat :uf-rex
  (:w     (1 0))
  (:r     (1 1))
  (:x     (1 2))
  (:b     (1 3)))

(define-microformat :uf-modrm
  (:r/m   (3 0))
  (:reg   (3 3))
  (:mod   (2 6)))

(define-microformat :uf-sib
  (:base  (3 0))
  (:index (3 3))
  (:scale (2 6)))

(defclass node ()
  ((name :accessor node-name :initarg :name)
   (shift :reader node-shift :initarg :shift)
   (width :reader node-width :initarg :width)
   (allowed :reader node-allowed :initarg :allowed)
   (directives :reader node-directives :initarg :directives)
   (declared :reader node-declared :initarg :declared)
   (discmap :initarg :discmap))
  (:default-initargs
   :discmap (make-hash-table))
  (:documentation
   "This is a node within a core structure, the discrimination tree."))

(define-subcontainer childs :type list :container-slot discmap :if-exists :continue)

(defstruct (argument-type (:conc-name argtype-))
  (name        nil :type keyword         :read-only t)
  (immediatep  nil :type boolean         :read-only t)
  (elementp    nil :type boolean         :read-only t)
  (width       0   :type (or null (integer 1 128)))
  (phys-parent nil :type (or null argument-type))
  (phys-childs nil :type list)
  (set-parents nil :type list)
  (set-childs  nil :type list))

(define-subcontainer argtype :type argument-type :container-slot id->argtype :if-exists :continue :coercer t)

(defun ensure-argument-type (isa name immediatep elementp width &optional phys-parent &aux
                             (phys-parent (when phys-parent
                                            (coerce-to-argument-type isa phys-parent))))
  (let ((a (make-argument-type :name name :immediatep immediatep :elementp elementp :width width :phys-parent phys-parent)))
    (when phys-parent
      (removef (argtype-phys-childs phys-parent) name :key #'argtype-name :test #'eq)
      (push a (argtype-phys-childs phys-parent)))
    (setf (argtype isa name) a)))

(defun ensure-argument-type-physical-tree (isa argtype-tree)
  (labels ((rec (phys-parent tree)
             (when tree
               (destructuring-bind (name width &rest childs) tree
                 (lret ((a (ensure-argument-type isa name nil t width phys-parent)))
                   (setf (slot-value a 'phys-childs) (mapcar (curry #'rec a) childs)))))))
    (rec nil argtype-tree)))

(defun ensure-argument-type-set (isa name width element-names register-elements)
  (let* ((elements (if register-elements
                       (iter (for name in element-names)
                             (collect (ensure-argument-type isa name nil t width nil)))
                       (mapcar (curry #'argtype isa) element-names)))
         (a (make-argument-type :name name :width width)))
    (dolist (elt elements)
      (push a (argtype-set-parents elt)))
    ;; I no longer understand why the commented checks were supposed to be there.
    ;; (unless (every #'argtype-elementp elements)
    ;;   (error "~@<in ENSURE-ARGUMENT-TYPE-SET: set elements must be actually elements.~:@>"))
    ;; (when (some #'argtype-immediatep elements)
    ;;   (error "~@<in ENSURE-ARGUMENT-TYPE-SET: set elements cannot be immediate.~:@>"))
    (unless (or (not width)
                (every (compose (curry #'= width) #'argtype-width) elements))
      (error "~@<in ENSURE-ARGUMENT-TYPE-SET: all set elements must have the same width: ~D bits.~:@>" width))
    (setf (argtype-set-childs a) elements
          (argtype isa name) a)))

(defmacro define-argument-types (() &body argtype-specs)
  `(iter (for (type width) in ',argtype-specs)
         (ensure-argument-type *isa* type nil t width)))

(defmacro define-immediate-argument-types (() &body argtype-specs)
  `(progn
     ,@(iter (for (name width) in argtype-specs)
             (collect `(ensure-argument-type *isa* ',name t t ,width)))))

(defmacro define-argument-type-physical-hierarchy (() argtype-spec-tree)
  `(ensure-argument-type-physical-tree *isa* ',argtype-spec-tree))

(defmacro define-argument-type-set (name width (&key register-members) &body element-names)
  `(ensure-argument-type-set *isa* ',name ,width ',element-names ,register-members))

(define-immediate-argument-types ()
    (:imm8 8) (:imm16 16) (:imm32 32) (:imm64 64))

(define-argument-type-physical-hierarchy () (:rax 64 (:eax  32 (:ax   16 (:al   8) (:ah 8)))))
(define-argument-type-physical-hierarchy () (:rbx 64 (:ebx  32 (:bx   16 (:bl   8) (:bh 8)))))
(define-argument-type-physical-hierarchy () (:rcx 64 (:ecx  32 (:cx   16 (:cl   8) (:ch 8)))))
(define-argument-type-physical-hierarchy () (:rdx 64 (:edx  32 (:dx   16 (:dl   8) (:dh 8)))))
(define-argument-type-physical-hierarchy () (:rsi 64 (:esi  32 (:si   16 (:sil  8)))))
(define-argument-type-physical-hierarchy () (:rdi 64 (:edi  32 (:di   16 (:dil  8)))))
(define-argument-type-physical-hierarchy () (:rsp 64 (:esp  32 (:sp   16 (:spl  8)))))
(define-argument-type-physical-hierarchy () (:rbp 64 (:ebp  32 (:bp   16 (:bpl  8)))))
(define-argument-type-physical-hierarchy () (:r8  64 (:r8d  32 (:r8w  16 (:r8b  8)))))
(define-argument-type-physical-hierarchy () (:r9  64 (:r9d  32 (:r9w  16 (:r9b  8)))))
(define-argument-type-physical-hierarchy () (:r10 64 (:r10d 32 (:r10w 16 (:r10b 8)))))
(define-argument-type-physical-hierarchy () (:r11 64 (:r11d 32 (:r11w 16 (:r11b 8)))))
(define-argument-type-physical-hierarchy () (:r12 64 (:r12d 32 (:r12w 16 (:r12b 8)))))
(define-argument-type-physical-hierarchy () (:r13 64 (:r13d 32 (:r13w 16 (:r13b 8)))))
(define-argument-type-physical-hierarchy () (:r14 64 (:r14d 32 (:r14w 16 (:r14b 8)))))
(define-argument-type-physical-hierarchy () (:r15 64 (:r15d 32 (:r15w 16 (:r15b 8)))))

(define-argument-type-set :reg8 8 ()
    :al :ah :bl :bh :cl :spl :bpl :sil :dil :ch :dl :dh :r8b  :r9b :r10b :r11b :r12b :r13b :r14b :r15b)

(define-argument-type-set :reg16 16 ()
    :ax  :bx  :cx  :dx  :sp  :bp  :si  :di  :r8w  :r9w :r10w :r11w :r12w :r13w :r14w :r15w)

(define-argument-type-set :reg32 32 ()
    :eax :ebx :ecx :edx :esp :ebp :esi :edi :r8d  :r9d :r10d :r11d :r12d :r13d :r14d :r15d)

(define-argument-type-set :reg64 64 ()
    :rax :rbx :rcx :rdx :rsp :rbp :rsi :rdi :r8   :r9  :r10  :r11  :r12  :r13  :r14  :r15)

(define-argument-type-set :base32 32 ()
    :eax :ecx :edx :ebx           :esi :edi :r8d  :r9d :r10d :r11d             :r14d :r15d)

(define-argument-type-set :base64 64 ()
    :rax :rcx :rdx :rbx           :rsi :rdi :r8   :r9  :r10  :r11              :r14  :r15)

(define-argument-type-set :base32+ 32 ()
    :eax :ecx :edx :ebx      :ebp :esi :edi :r8d  :r9d :r10d :r11d             :r14d :r15d)

(define-argument-type-set :base64+ 64 ()
    :rax :rcx :rdx :rbx      :rbp :rsi :rdi :r8   :r9  :r10  :r11              :r14  :r15)

(define-argument-type-set :base32+2 32 ()
    :eax :ecx :edx :ebx      :ebp :esi :edi :r8d  :r9d :r10d :r11d :r12d       :r14d :r15d)

(define-argument-type-set :base64+2 64 ()
    :rax :rcx :rdx :rbx      :rbp :rsi :rdi :r8   :r9  :r10  :r11  :r12        :r14  :r15)

(define-argument-type-set :cr 32 (:register-members t)
    :cr0 :cr1 :cr2 :cr3 :cr4 :cr5 :cr6 :cr7 :cr8 :cr9 :cr10 :cr11 :cr12 :cr13 :cr14 :cr15)

(define-argument-type-set :dr 32 (:register-members t)
    :dr0 :dr1 :dr2 :dr3 :dr4 :dr5 :dr6 :dr7 :dr8 :dr9 :dr10 :dr11 :dr12 :dr13 :dr14 :dr15)

(define-argument-type-set :mmx 64 (:register-members t)
    :mmx0 :mmx1 :mmx2 :mmx3 :mmx4 :mmx5 :mmx6 :mmx7)

(define-argument-type-set :xmm 128 (:register-members t)
    :xmm0 :xmm1 :xmm2 :xmm3 :xmm4 :xmm5 :xmm6 :xmm7 :xmm8 :xmm9 :xmm10 :xmm11 :xmm12 :xmm13 :xmm14 :xmm15)

(define-argument-type-set :segreg 16 (:register-members t)
    :es :cs :ss :ds :fs :gs)

(define-argument-types ()
  (:rflags 32))

(defclass argument/attribute-correspondence ()
  ((name          :reader corr-name :initarg :name)
   (set->argvalue                   :initarg :set->argvalue)
   (argvalue->set                   :initarg :argvalue->set))
  (:default-initargs
   :set->argvalue (make-hash-table :test 'equal)
   :argvalue->set (make-hash-table :test 'eq))
  (:documentation
   "These maps are used in final instruction formats,
so as to resolve argument or address sizes, for example."))

(define-subcontainer correspondence :type argument/attribute-correspondence :container-slot id->correspondence :if-exists :continue :coercer t)

(define-subcontainer corr-argvalue :type keyword :container-slot set->argvalue :if-exists :continue)
(define-subcontainer corr-set      :type list    :container-slot argvalue->set :if-exists :continue)

(defun ensure-argument/attribute-correspondence (isa name corr-spec)
  (let ((c (make-instance 'argument/attribute-correspondence :name name)))
    (iter (for (set . argvalue) in corr-spec)
          (let ((set (ensure-list set)))
            (setf (corr-argvalue c set) argvalue
                  (corr-set c argvalue) set)))
    (ensure-argument-type-set isa name nil (mapcar #'cdr corr-spec) nil)
    (setf (correspondence isa name) c)))

(defmacro define-format-argument/attribute-correspondence (name () &body corr-spec)
  `(ensure-argument/attribute-correspondence *isa* ,name ',corr-spec))

(define-format-argument/attribute-correspondence :segreg-over ()
  (:es . :es) (:cs . :cs) (:ss . :ss) (:ds . :ds) (:fs . :fs) (:gs . :gs))

(define-format-argument/attribute-correspondence :regx ()
  ((:opersz/p) .        :reg16)
  (() .                 :reg32)
  ((:rex-w :opersz/p) . :reg64)
  ((:rex-w) .           :reg64))

(define-format-argument/attribute-correspondence :basex ()
  ((:addrsz/p) .        :base32)
  (() .                 :base64))

(define-format-argument/attribute-correspondence :basex+ ()
  ((:addrsz/p) .        :base32+)
  (() .                 :base64+))

(define-format-argument/attribute-correspondence :basex+2 ()
  ((:addrsz/p) .        :base32+2)
  (() .                 :base64+2))

(define-format-argument/attribute-correspondence :xax ()
  ((:opersz/p) .        :ax)
  (() .                 :eax)
  ((:rex-w :opersz/p) . :rax)
  ((:rex-w) .           :rax))

(define-format-argument/attribute-correspondence :immx ()
  ((:opersz/p) .        :imm16)
  (() .                 :imm32)
  ((:rex-w :opersz/p) . :imm32)
  ((:rex-w) .           :imm32))

(define-format-argument/attribute-correspondence :immxf ()
  ((:opersz/p) .        :imm16)
  (() .                 :imm32)
  ((:rex-w :opersz/p) . :imm64)
  ((:rex-w) .           :imm64))

;; (defun make-dispatch-alternate (sixty-four-p)
;;   `(((active-set :all-legacy :all-rex :xop
;;                   :opcode ,(if sixty-four-p
;;                                :opcode-longmode
;;                                :opcode-compatmode)
;;                   ;; ...and the modrm-extended points of bastardisation
;;                   (#x80 #x81 ,@(unless sixty-four-p '(#x82)) #x83 #x8f #xc0 #xc1 #xd0 #xd1 #xd2 #xd3 #xf6 #xf7 #xfe #xff #xc6 #xc7))
;;      (window 08 00)
;;      (dispatch :window))
;;     (:all-legacy ((dispatch :window)
;;                   (seek 08))
;;                  (:addrsz   ((ban-sets :addrsz)
;;                              (recurse)))
;;                  (:overseg  ((ban-sets :overseg)
;;                              (recurse)))
;;                  (:lock     ((ban-sets :lock)
;;                              (recurse)))
;;                  (:opersz/p ((ban-sets :xopcode-unprefixed :opersz/p)
;;                              (allow-sets-at-subtree :xop-tree :xopcode-opersz (#x78))
;;                              (recurse)))
;;                  (:rep/p    ((ban-sets :xopcode-unprefixed :rep/p :repn/p)
;;                              (allow-sets-at-subtree :xop-tree :xopcode-rep)
;;                              (recurse)))
;;                  (:repn/p   ((ban-sets :xopcode-unprefixed :rep/p :repn/p)
;;                              (allow-sets-at-subtree :xop-tree :xopcode-repn)
;;                              (recurse))))
;;     (:all-rex    ((microformat :uf-rex 04 00)
;;                   (ban-sets :rex :addrsz :overseg :lock :opersz/p :rep/p :repn/p)
;;                   (seek 08)
;;                   (recurse)))
;;     (:xop        ((active-set :xopcode
;;                                ,@(unless sixty-four-p
;;                                          `(:xopcode-compatmode))
;;                                :xopcode-unprefixed :xopcode-unprefixed-modrm
;;                                ;; ...and the modrm-extended points of bastardisation
;;                                (#x0f00 #x0f01 #x0fba #x0fc7 #x0fb9 #x0f71 #x0f72 #x0f73 #x0fae #x0f18 #x0f0d))
;;                   (insert :xop-tree)
;;                   (dispatch ((08 00) :window))
;;                   (seek 08)))
;;     (:opcode     ((insert :op-tree)))))
;;;;               
;;;;   +------------+                                                                      +----------------------------+ 
;;;;   |    legacy  |              REX                  op                ModRM            |            SIB             |    displacement        immediate
;;;;   v  +-------+ |    +------+---+---+---+---+    +------+    +-------+-------+-------+ |  +-------+-------+-------+ v   +------------+     +------------+   
;;;; ---->|   8   |-+-+->| 0100 | w | r | x | b |--->| 8/16 |-+->| 2 mod | 3 reg | 3 r/m |-+->| 2 sca | 3 idx | 3 bas |---+-| 8/16/32/64 |---+-| 8/16/32/64 |---->
;;;;   |  +-------+ ^ |  +------+---+---+---+---+ ^  +------+ |  +-------+-------+-------+    +-------+-------+-------+ ^ | +------------+ ^ | +------------+ ^ 
;;;;   +------------+ +---------------------------+           +---------------------------------------------------------+ +----------------+ +----------------+ 
;;;;
;;;; The assumptions:
;;;;    1. the "default operand size" for compat modes is assumed to designate a 32-bit operand size.
;;;;    2. 16-bit addressing does not exist, period.
;;;;
(defun make-root-tree (sixty-four-p)
  `(nil ((active-set :rex :nrex)
         (window 04 04)
         (dispatch :window))
        (:rex ((ban-sets :rex :addrsz :overseg :lock :opersz/p :rep/p :repn/p)
               (microformat :uf-rex 04 00)
               (seek 08)
               (insert-subtree :nrex)))
        (:nrex ((active-set :opersz/p :rep/p :repn/p :addrsz :overseg :lock
                             :opcode :opcode-modrmless-regspec
                             ,@(if sixty-four-p
                                   '(:opcode-longmode)
                                   '(:opcode-compatmode :opcode-modrmless-regspec-compatmode))
                             (#x80 #x81 ,@(unless sixty-four-p '(#x82)) #x83 #x8f #xc0 #xc1 #xd0 #xd1 #xd2 #xd3 #xf6 #xf7 #xfe #xff #xc6 #xc7))
                (window 08 00)
                (dispatch :window)
                (seek 08))
               (:addrsz   ((ban-sets :addrsz)
                           (insert-subtree nil)))
               (:overseg  ((ban-sets :overseg)
                           (insert-subtree nil)))
               (:lock     ((ban-sets :lock)
                           (insert-subtree nil)))
               (:opersz/p ((ban-sets :xopcode-unprefixed :opersz/p)
                           (allow-sets-at-subtree :xop :xopcode-opersz (#x78))
                           (insert-subtree nil)))
               (:rep/p    ((ban-sets :xopcode-unprefixed :rep/p :repn/p)
                           (allow-sets-at-subtree :xop :xopcode-rep)
                           (insert-subtree nil)))
               (:repn/p   ((ban-sets :xopcode-unprefixed :rep/p :repn/p)
                           (allow-sets-at-subtree :xop :xopcode-repn)
                           (insert-subtree nil)))
               (:opcode                               ((mnemonic :window))
                                                      ;; what do we dispatch on, here?
                                                      )
               (:opcode-modrmless-regspec             ((active-set :opcode-modrmless-regspec-internal)
                                                       (mnemonic (05 03))
                                                       (format :window)
                                                       (argument 0 (:b (03 00)))))
               (:opcode-modrmless-regspec-compatmode  ((active-set :opcode-modrmless-regspec-compatmode-internal)
                                                       (mnemonic (05 03))
                                                       (format :window)
                                                       (argument 0 (:b (03 00)))))
               (:opcode-longmode                      ((mnemonic :window))
                                                      )
               (:opcode-compatmode                    ((mnemonic :window))
                                                      )
               (#x80 ((active-set :grp1-80)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp1-80 ()
                               (mnemonic/format :window :reg :mod)))
               (#x81 ((active-set :grp1-81)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp1-81 ()
                               (mnemonic/format :window :reg :mod)))
               ,@(unless sixty-four-p
                         `((#x82 ((active-set :grp1-82-compatmode)
                                  (microformat :uf-modrm 08 00)
                                  (dispatch :window :reg))
                                 (:grp1-82-compatmode ()
                                                     ))))
               (#x83 ((active-set :grp1-83)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp1-83 ()
                               (mnemonic/format :window :reg :mod)))
               (#x8f ((active-set :grp1-8f)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp1-8f ()
                               ))
               (#xc0 ((active-set :grp2-c0)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-c0 ()
                               ))
               (#xc1 ((active-set :grp2-c1)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-c1 ()
                               ))
               (#xd0 ((active-set :grp2-d0)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-d0 ()
                               ))
               (#xd1 ((active-set :grp2-d1)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-d1 ()
                               ))
               (#xd2 ((active-set :grp2-d2)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-d2 ()
                               ))
               (#xd3 ((active-set :grp2-d3)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp2-d3 ()
                               ))
               (#xf6 ((active-set :grp3-f6)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp3-f6 ()
                               ))
               (#xf7 ((active-set :grp3-f7)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp3-f7 ()
                               ))
               (#xfe ((active-set :grp4-fe)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp4-fe ()
                               ))
               (#xff ((active-set :grp5-ff)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp5-ff ()
                               ))
               (#xc6 ((active-set :grp11-c6)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp11-c6 ()
                                ))
               (#xc7 ((active-set :grp11-c7)
                      (microformat :uf-modrm 08 00)
                      (dispatch :window :reg))
                     (:grp11-c7 ()
                                ))
               (:xop ((active-set :xopcode
                                   ,@(unless sixty-four-p
                                             `(:xopcode-compatmode))
                                   :xopcode-unprefixed :xopcode-unprefixed-modrm
                                   (#x0f00 #x0f01 #x0fba #x0fc7 #x0fb9 #x0f71 #x0f72 #x0f73 #x0fae #x0f18 #x0f0d))
                      (dispatch ((08 00) :window))
                      (seek 08))
                     (:xopcode                    ((mnemonic :window)
                                                   (format :window))
                                                  )
                     (:xopcode-modrmless-regspec  ((active-set :xopcode-modrmless-regspec-internal)
                                                   (mnemonic (05 03))
                                                   (format :window)
                                                   (argument 0 (:b (03 00)))))
                     (:xopcode-unprefixed         ((mnemonic :window)
                                                   (format :window))
                                                  )
                     (:xopcode-opersz             ((mnemonic :window)
                                                   (format :window))
                                                  )
                     (:xopcode-rep                ((mnemonic :window)
                                                   (format :window))
                                                  )
                     (:xopcode-repn               ((mnemonic :window)
                                                   (format :window))
                                                  )
                     (#x0f00 ((active-set :grp6-0f-00)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp6-0f-00 ()
                                          ))
                     (#x0f01 ((active-set :grp7-0f-01 ((#x0f01 1) (#x0f01 3) (#x0f01 7)))
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp7-0f-01 () ; modulo 1 4 7
                                          )
                             ((#x0f01 1) ((active-set :grp7-0f-01-1-0 (#x0f01 1 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-1-0 ()
                                               )
                              ((#x0f01 1 3) ((active-set :grp7-0f-01-1-3))
                               (:grp7-0f-01-1-3 ()
                                                )))
                             ((#x0f01 3) ((active-set :grp7-0f-01-3-0 (#x0f01 3 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-3-0 ()
                                               )
                              ((#x0f01 3 3) ((active-set :grp7-0f-01-3-3)
                                             (dispatch :window :reg))
                               (:grp7-0f-01-3-3 ()
                                                )))
                             ((#x0f01 7) ((active-set :grp7-0f-01-7-0 (#x0f01 7 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-7-0 ()
                                               )
                              ((#x0f01 7 3) ((active-set :grp7-0f-01-7-3)
                                             (dispatch :window :reg))
                               (:grp7-0f-01-7-3 ()
                                                ))))
                     (#x0fba ((active-set :grp8-0f-ba)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp8-0f-ba ((mnemonic/format :window :reg :mod))
                                          ))
                     (#x0fc7 ((active-set :grp9-0f-c7)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp9-0f-c7 ()
                                          ))
                     (#x0fb9 ((active-set :grp10-0f-b9)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp10-0f-b9 ()
                                           ))
                     ;; XXX: yeah, the only place we bastardise the opcode...
                     (#x0f71 ((active-set (#x00f71 #x10f71))
                              (dispatch (:opersz/p :window)))
                             (#x00f71 ((active-set :grp12-0f-71)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp12-0f-71 ()
                                                    ))
                             (#x10f71 ((active-set :grp12-0f-71-op)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp12-0f-71-op ()
                                                       )))
                     (#x0f72 ((active-set (#x00f72 #x10f72))
                              (dispatch (:opersz/p :window)))
                             (#x00f72 ((active-set :grp13-0f-72)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp13-0f-72 ()
                                                    ))
                             (#x10f72 ((active-set :grp13-0f-72-op)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp13-0f-72-op ()
                                                       )))
                     (#x0f73 ((active-set (#x00f73 #x10f73)
                              (dispatch (:opersz/p :window))))
                             (#x00f73 ((active-set :grp14-0f-73)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp14-0f-73 ()
                                                    ))
                             (#x10f73 ((active-set :grp14-0f-73-op)
                                       (microformat :uf-modrm 08 00)
                                       (dispatch :window :reg))
                                      (:grp14-0f-73-op ()
                                                       )))
                     (#x0fae ((active-set :grp15-0f-ae ((#x0fae 5) (#x0fae 6) (#x0fae 7)))
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp15-0f-ae ()
                                           )
                             ((#x0fae 5) ((active-set :grp15-0f-ae-5)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-5 () ; lfence
                                              ))
                             ((#x0fae 6) ((active-set :grp15-0f-ae-6)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-6 () ; mfence
                                              ))
                             ((#x0fae 7) ((active-set :grp15-0f-ae-7)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-7 () ; sfence, clflush
                                              )))
                     (#x0f18 ((active-set :grp16-0f-18)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp16-0f-18 ()
                                           ))
                     (#x0f78 ((active-set :grp17-0f-78-op)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grp17-0f-78 ()
                                           ))
                     (#x0f0d ((active-set :grpp-0f-0d)
                              (microformat :uf-modrm 08 00)
                              (dispatch :window :reg))
                             (:grpp-0f-0d ()
                                          ))))))

;;;;
;;;; "modrmless" argument register specification:
;;;; universal push 5, xchg 9, mov b | pop 5, mov b
;;;; compat    inc 4                 | dec 4
;;;;                                 | bswap 0fc
;;;;
;;;; Warning: all these excessive modrmless-regspec tables are a bit ugly, definitely pending a nicer way to describe it...
;;;;
(define-attribute-set :push
  (:push .      #x50) (:push .    #x51) (:push .     #x52) (:push .      #x53) (:push .      #x54) (:push .      #x55) (:push .    #x56) (:push .     #x57))
(define-attribute-set :xchg
  (:xchg .      #x90) (:xchg .    #x91) (:xchg .     #x92) (:xchg .      #x93) (:xchg .      #x94) (:xchg .      #x95) (:xchg .    #x96) (:xchg .     #x97))
(define-attribute-set :mov0-7
  (:mov .       #xb0) (:mov .     #xb1) (:mov .      #xb2) (:mov .       #xb3) (:mov .       #xb4) (:mov .       #xb5) (:mov .     #xb6) (:mov .      #xb7))
(define-attribute-set :inc
  (:inc .       #x40) (:inc .     #x41) (:inc .      #x42) (:inc .       #x43) (:inc .       #x44) (:inc .       #x45) (:inc .     #x46) (:inc .      #x47))
(define-attribute-set :pop
  (:pop .       #x58) (:pop .     #x59) (:pop .      #x5a) (:pop .       #x5b) (:pop .       #x5c) (:pop .       #x5d) (:pop .     #x5e) (:pop .      #x5f))
(define-attribute-set :mov8-f
  (:mov .       #xb8) (:mov .     #xb9) (:mov .      #xba) (:mov .       #xbb) (:mov .       #xbc) (:mov .       #xbd) (:mov .     #xbe) (:mov .      #xbf))
(define-attribute-set :dec
  (:dec .        #x8) (:dec .     #x49) (:dec .      #x4a) (:dec .       #x4b) (:dec .       #x4c) (:dec .       #x4d) (:dec .     #x4e) (:dec .      #x4f))
(define-attribute-set :bswap
  (:bswap .   #x0fc8) (:bswap . #x0fc9) (:bswap .  #x0fca) (:bswap .   #x0fcb) (:bswap .   #x0fcc) (:bswap .   #x0fcd) (:bswap . #x0fce) (:bswap .  #x0fcf))

(define-attribute-set :opcode-modrmless-regspec
  :push :xchg :mov0-7 :pop :mov8-f)
 
(define-attribute-set :opcode-modrmless-regspec-compatmode
  :inc :dec)
 
(define-attribute-set :xopcode-modrmless-regspec
  :bswap)

(define-attribute-set :opcode-modrmless-regspec-internal
  (:push . #x10) (:xchg . #x18) (:mov . 22) (:pop . 11) (:mov . 23))

(define-attribute-set :opcode-modrmless-regspec-compatmode-internal
  (:inc . 8) (:dec . 9))

(define-attribute-set :xopcode-modrmless-regspec-internal
  (:bswap . #x505))

(define-attribute-set :opcode
  (:add .       #x00) (:add .     #x01) (:add .      #x02) (:add .       #x03) (:add .       #x04) (:add .       #x05)  #| 32bit mode|#   #| 32bit mode  |#
  (:adc .       #x10) (:adc .     #x11) (:adc .      #x12) (:adc .       #x13) (:adc .       #x14) (:adc .       #x15)  #| 32bit mode|#   #| 32bit mode  |#
  (:and .       #x20) (:and .     #x21) (:and .      #x22) (:and .       #x23) (:and .       #x24) (:and .       #x25)  #| ES seg    |#   #| 32bit mode  |#
  (:xor .       #x30) (:xor .     #x31) (:xor .      #x32) (:xor .       #x33) (:xor .       #x34) (:xor .       #x35)  #| SS seg    |#   #| 32bit mode  |#
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#   #|    rex      |#
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
   #| 32bit mode  |#   #| 32bit mode|#   #| 32bit mode |#   #| 64bit mode  |#   #|   FS seg    |#   #|   GS seg    |#   #| oper size |#   #| addr size   |#
  (:jo .        #x70) (:jno .     #x71) (:jb .       #x72) (:jnb .       #x73) (:jz .        #x74) (:jnz .       #x75) (:jbe .     #x76) (:jnbe .      #x77)
   #|   grp1      |#   #|   grp1    |#   #| 32bit grp  |#   #|   grp1      |#  (:test .      #x84) (:test .      #x85) (:xchg .    #x86) (:xchg .      #x87)
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
  (:mov .       #xa0) (:mov .     #xa1) (:mov .      #xa2) (:mov .       #xa3) (:movsb .     #xa4) (:movsw/d/q . #xa5) (:cmpsb .   #xa6) (:cmpsw/d/q . #xa7)
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
   #|   grp2      |#   #|   grp2    |#  (:ret-near . #xc2) (:ret-near .  #xc3)  #| 32bit mode  |#   #| 32bit mode  |#   #|   grp11   |#   #|   grp11     |#
   #|   grp2      |#   #|   grp2    |#   #|   grp2     |#   #|   grp2      |#   #| 32bit mode  |#   #| 32bit mode  |#   #| 32bit mode|#  (:xlat .      #xd7)
  (:loopne/nz . #xe0) (:loope/z . #xe1) (:loop .     #xe2) (:jxcxz .     #xe3) (:in .        #xe4) (:in .        #xe5) (:out .     #xe6) (:out .       #xe7)
   #|  lock       |#  (:int1 .    #xf1)  #|   repn     |#   #|   rep       |#  (:hlt .       #xf4) (:cmc .       #xf5)  #|   grp3    |#   #|   grp3      |#
  (:or .        #x08) (:or .      #x09) (:or .       #x0a) (:or .        #x0b) (:or .        #x0c) (:or .        #x0d)  #| 32bit mode|#   #| xop         |#
  (:sbb .       #x18) (:sbb .     #x19) (:sbb .      #x1a) (:sbb .       #x1b) (:sbb .       #x1c) (:sbb .       #x1d)  #| 32bit mode|#   #| 32bit mode  |# 
  (:sub .       #x28) (:sub .     #x29) (:sub .      #x2a) (:sub .       #x2b) (:sub .       #x2c) (:sub .       #x2d)  #| CS seg    |#   #| 32bit mode  |# 
  (:cmp .       #x38) (:cmp .     #x39) (:cmp .      #x3a) (:cmp .       #x3b) (:cmp .       #x3c) (:cmp .       #x3d)  #| DS seg    |#   #| 32bit mode  |# 
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#  #|    rex       |#
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
  (:push .      #x68) (:imul .    #x69) (:push .     #x6a) (:imul .      #x6b) (:insb .      #x6c) (:insw/d .    #x6d) (:outsb .   #x6e) (:outsw/d .   #x6f)
  (:js .        #x78) (:jns .     #x79) (:jp .       #x7a) (:jnp .       #x7b) (:jl .        #x7c) (:jnl .       #x7d) (:jle .     #x7e) (:jnle .      #x7f)
  (:mov .       #x88) (:mov .     #x89) (:mov .      #x8a) (:mov .       #x8b) (:mov .       #x8c) (:lea .       #x8d) (:mov .     #x8e)  #|   grp1      |#
  (:cbwde/qe .  #x98) (:cwdqo .   #x99)  #| 32bit mode |#  (:f/wait .    #x9b) (:pushf/d/q . #x9c) (:popf/d/q .  #x9d) (:sahf .    #x9e) (:lahf .      #x9f)
  (:test .      #xa8) (:test .    #xa9) (:stosb .    #xaa) (:stosw/d/q . #xab) (:lodsb .     #xac) (:lodsw/d/q . #xad) (:scasb .   #xae) (:scasw/d/q . #xaf)
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
  (:enter .     #xc8) (:leave .   #xc9) (:ret .      #xca) (:ret .       #xcb) (:int3 .      #xcc) (:int .       #xcd)  #| 32bit mode|#  (:iret/d/q .  #xcf)
   #|   x87       |#   #|   x87     |#   #|   x87      |#   #|   x87       |#   #|   x87       |#   #|   x87       |#   #|   x87     |#  #|    x87       |#
  (:call .      #xe8) (:jmp .     #xe9)  #| 32bit mode |#  (:jmp .       #xeb) (:in .        #xec) (:in .        #xed) (:out .     #xee) (:out .       #xef)
  (:clc .       #xf8) (:stc .     #xf9) (:cli .      #xfa) (:sti .       #xfb) (:cld .       #xfc) (:std .       #xfd)  #| 64bit mode|#   #|   grp5      |#)
  
(define-attribute-set :opcode-longmode
   #|  .........           .......           ........  |#  (:movsxd .    #x63)) #|  .........           .........           .......           .........  |#

(define-attribute-set :opcode-compatmode
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-es . #x06) (:pop-es .    #x07)
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ss . #x16) (:pop-ss .    #x17)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:daa .       #x27)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aaa .       #x37)
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
  (:pusha/d .   #x60) (:popa/d .  #x61) (:bound .    #x62) (:arpl .      #x63)  #|  .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:les .       #xc4) (:lds .       #xc5)  #|  .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:aam .       #xd4) (:aad .       #xd5) (:salc .    #xd6)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-cs . #x0e)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ds . #x1e) (:pop-ds .    #x1f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:das .       #x2f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aas .       #x3f)
   #|  modrmless          modrmless          modrmless          modrmless           modrmless           modrmless          modrmless          modrmless  |#
   #|  .........           .......  |#  (:call .     #x9a)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:into .    #xce)  #|  .........  |#
   #|  .........           .......  |#  (:jmp .      #xea)  #|  .........           .........           .........           .......           .........  |#)

(define-attribute-set :xopcode
   #|      grp6                grp7       |#  (:lar .       #x0f02) (:lsl .      #x0f03)  #|   invalid    |#  (:syscall .  #x0f05) (:clts .    #x0f06) (:sysret .   #x0f07)
  ;; 1[0-7]: prefixable
  (:mov .       #x0f20) (:mov .       #x0f21) (:mov .       #x0f22) (:mov .      #x0f23)  #|   invalid    |#   #|   invalid    |#   #|   invalid    |#   #|   invalid    |#
  (:wrmsr .     #x0f30) (:rstsc .     #x0f31) (:rdmsr .     #x0f32) (:rdpmc .    #x0f33)  #|  32bit mode  |#   #|  32bit mode  |#   #|   invalid    |#   #|   invalid    |#
  (:cmovo .     #x0f40) (:cmovno .    #x0f41) (:cmovb .     #x0f42) (:cmovnb .   #x0f43) (:cmovz .    #x0f44) (:cmovnz .   #x0f45) (:cmovbe .   #x0f46) (:cmovnbe .  #x0f47)
  ;; 5[0-7]: prefixable
  ;; 6[0-7]: prefixable
  ;; 7[0-7]: prefixable
  (:jo .        #x0f80) (:jno .       #x0f81) (:jb .        #x0f82) (:jnb .      #x0f83) (:jz .       #x0f84) (:jnz .      #x0f85) (:jbe .      #x0f86) (:jnbe .     #x0f87)
  (:seto .      #x0f90) (:setno .     #x0f91) (:setb .      #x0f92) (:setnb .    #x0f93) (:setz .     #x0f94) (:setnz .    #x0f95) (:setbe .    #x0f96) (:setnbe .   #x0f97)
  (:push .      #x0fa0) (:pop .       #x0fa1) (:cpuid .     #x0fa2) (:bt .       #x0fa3) (:shld .     #x0fa4) (:shld .     #x0fa5)  #|   invalid    |#   #|   invalid    |#
  (:cmpxchg .   #x0fb0) (:cmpxchg .   #x0fb1) (:lss .       #x0fb2) (:btr .      #x0fb3) (:lfs .      #x0fb4) (:lgs .      #x0fb5) (:movzx .    #x0fb6) (:movzx .    #x0fb7)
  ;; c[0-7]: prefixable
  ;; d[0-7]: prefixable
  ;; e[0-7]: prefixable
  ;; f[0-7]: prefixable
  (:invd .      #x0f08) (:wbinvd .    #x0f09)  #|    invalid    |#  (:ud2 .      #x0f0b)  #|   invalid    |#   #|    grp p     |#  (:femms .    #x0f0e)  #|    3dnow     |#
   #|  modrm group  |#  (:nop .       #x0f19) (:nop .       #x0f1a) (:nop .      #x0f1b) (:nop .      #x0f1c) (:nop .      #x0f1d) (:nop .      #x0f1e) (:nop .      #x0f1f)
  ;; 2[8-f]: prefixable
  ;; 3[8-f]: invalid
  (:cmovs .     #x0f48) (:cmovns .    #x0f49) (:cmovp .     #x0f4a) (:cmovnp .   #x0f4b) (:cmovl .    #x0f4c) (:cmovnl .   #x40fd) (:cmovle .   #x40fe) (:cmovnle .  #x0f4f)
  ;; 5[8-f]: prefixable
  ;; 6[8-f]: prefixable
  ;; 7[8-f]: prefixable
  (:js .        #x0f88) (:jns .       #x0f89) (:jp .        #x0f8a) (:jnp .      #x0f8b) (:jl .       #x0f8c) (:jnl .      #x0f8d) (:jle .      #x0f8e) (:jnle .     #x0f8f)
  (:sets .      #x0f98) (:setns .     #x0f99) (:setp .      #x0f9a) (:setnp .    #x0f9b) (:setl .     #x0f9c) (:setnl .    #x0f9d) (:setle   .  #x0f9e) (:setnle .   #x0f9f)
  (:push .      #x0fa8) (:pop .       #x0fa9) (:rsm .       #x0faa) (:bts .      #x0fab) (:shrd .     #x0fac) (:shrd .     #x0fad) (:grp15-ae . #x0fae) (:imul .     #x0faf)
  ;; b[8-f]: prefixable
   #|    modrmless            modrmless             modrmless             modrmless           modrmless            modrmless             modrmless           modrmless   |#
  ;; d[8-f]: prefixable
  ;; e[8-f]: prefixable
  ;; f[8-f]: prefixable
  )

(define-attribute-set :xopcode-compatmode
  #|    .........             .........             .........             ........    |#  (:sysenter .  #x0f34) (:sysexit .  #x0f35)  #|    .......             ........    |#)

(define-attribute-set :xopcode-unprefixed
  (:movups .    #x0f10) (:movups .    #x0f11) (:movl/hlps . #x0f12) (:movlps .    #x0f13) (:unpcklps .  #x0f14) (:unpckhps . #x0f15) (:movh/lhps . #x0f16) (:movhps .   #x0f17)
  (:movmskps .  #x0f50) (:sqrtps .    #x0f51) (:rsqrtps .   #x0f52) (:rcpps .     #x0f53) (:andps .     #x0f54) (:andnps .   #x0f55) (:orps .      #x0f56) (:xorps .    #x0f57)
  (:punpcklbw . #x0f60) (:punpcklwd . #x0f61) (:punpckldq . #x0f62) (:packsswb .  #x0f63) (:pcmpgtb .   #x0f64) (:pcmpgtw .  #x0f65) (:pcmpgtd .   #x0f66) (:packuswb . #x0f67)
  (:pshufw .    #x0f70)  #|    grp12      |#   #|     grp13     |#   #|    grp14      |#  (:pcmpeqb .   #x0f74) (:pcmpeqw .  #x0f75) (:pcmpeqd .   #x0f76) (:emss .     #x0f77)
  (:xadd .      #x0fc0) (:xadd .      #x0fc1) (:cmpps .     #x0fc2) (:movnti .    #x0fc3) (:pinsrw .    #x0fc4) (:pextsrw .  #x0fc5) (:shufps .    #x0fc6)  #|    grp9      |#
   #|    invalid    |#  (:psrlw .     #x0fd1) (:psrld .     #x0fd2) (:psrlq .     #x0fd3) (:paddq .     #x0fd4) (:pmullw .   #x0fd5)  #|    invalid    |#  (:pmovmskb . #x0fd7)
  (:pavgb .     #x0fe0) (:psraw .     #x0fe1) (:psrad .     #x0fe2) (:pavgw .     #x0fe3) (:pmulhuw .   #x0fe4) (:pmulhw .   #x0fe5)  #|    invalid    |#  (:movntq .   #x0fe7)
   #|    invalid    |#  (:psllw .     #x0ff1) (:pslld .     #x0ff2) (:psllq .     #x0ff3) (:pmuludq .   #x0ff4) (:pmaddwd .  #x0ff5) (:psadbw .    #x0ff6) (:maskmovq . #x0ff7)
  (:movaps .    #x0f28) (:movaps .    #x0f29) (:cvtpi2ps .  #x0f2a) (:movntps .   #x0f2b) (:cvttps2pi . #x0f2c) (:cvtps2pi . #x0f2d) (:ucomiss .   #x0f2e) (:comiss .   #x0f2f)
  (:addps .     #x0f58) (:mulps .     #x0f59) (:cvtps2pd .  #x0f5a) (:cvtdq2ps .  #x0f5b) (:subps .     #x0f5c) (:minps .    #x0f5d) (:divps .     #x0f5e) (:maxps .    #x0f5f)
  (:punpckhwb . #x0f68) (:punpckhwd . #x0f69) (:punpckhdq . #x0f6a) (:packssdw .  #x0f6b)  #|    invalid    |#   #|   invalid    |#  (:movd .      #x0f6e) (:movq .     #x0f6f)
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|   invalid    |#  (:movd .      #x0f7e) (:movq .     #x0f7f)
   #|    reserved   |#   #|    grp10      |#   #|    grp8       |#  (:btc .       #x0fbb) (:bsf .       #x0fbc) (:bsr .      #x0fbd) (:movsx .     #x0fbe) (:movsx .    #x0fbf)
  (:psubusb .   #x0fd8) (:psubusw .   #x0fd9) (:pminub .    #x0fda) (:pand .      #x0fdb) (:paddusb .   #x0fdc) (:paddusw .  #x0fdd) (:pmaxub .    #x0fde) (:pandn .    #x0fdf)
  (:psubsb .    #x0fe8) (:psubsw .    #x0fe9) (:pminsw .    #x0fea) (:por .       #x0feb) (:paddsb .    #x0fec) (:paddsw .   #x0fed) (:pmaxsw .    #x0fee) (:pxor .     #x0fef)
  (:psubb .     #x0ff8) (:psubw .     #x0ff9) (:psubd .     #x0ffa) (:psubq .     #x0ffb) (:padb .      #x0ffc) (:padw .     #x0ffd) (:padd .      #x0ffe)  #|   invalid    |#)

(define-attribute-set :xopcode-rep
  (:movss .   #x0f10) (:movss .   #x0f11) (:movsldup . #x0f12)  #|   invalid     |#   #|   invalid     |#   #|  invalid     |#  (:movshdup . #x0f16)  #|   invalid  |#
   #|   invalid   |#  (:sqrtss .  #x0f51) (:rsqrtss .  #x0f52) (:rcpss .     #x0f53)  #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
  (:pshufhw . #x0f70) #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
  (:xadd .    #x0fc0) (:xadd .    #x0fc1) (:cmpss .    #x0fc2)  #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#  (:movq2dq .  #x0fd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#  (:cvtdq2pd . #x0fe6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#  (:cvtsi2ss . #x0f2a) (:movntss .   #x0f2b) (:cvttss2si . #x0f2c) (:cvtss2si . #x0f2d)  #|   invalid    |#   #|   invalid  |#
  (:addss .   #x0f58) (:mulss .   #x0f59) (:cvtss2sd . #x0f5a) (:cvttps2dq . #x0f5b) (:subss .     #x0f5c) (:minss .    #x0f5d) (:divss .    #x0f5e) (:maxss .  #x0f5f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|   invalid    |#   #|   invalid    |#  (:movdqu . #x0f6f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|   invalid    |#  (:movq .     #x0f7e) (:movdqu . #x0f7f)
  (:popcnt .  #x0fb8) #|    reserved  |#   #|   reserved   |#   #|   reserved    |#   #|   reserved    |#  (:lzcnt .    #x0fbd)  #|   reserved   |#   #|   reserved |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
  )

(define-attribute-set :xopcode-opersz
  (:movupd .    #x0f10) (:movupd .    #x0f11) (:movlpd .    #x0f12) (:movlpd .    #x0f13) (:unpcklpd .   #x0f14) (:unpckhpd .   #x0f15) (:movhpd .   #x0f16) (:movhpd .   #x0f17)
  (:movmskpd .  #x0f50) (:sqrtpd .    #x0f51)  #|   invalid     |#   #|   invalid     |#  (:andpd .      #x0f54) (:andnpd .     #x0f55) (:orpd .     #x0f56) (:xorpd .    #x0f57)
  (:punpcklbw . #x0f60) (:punpcklwd . #x0f61) (:punpckldq . #x0f62) (:packsswb .  #x0f63) (:pcmpgtb .    #x0f64) (:pcmpgtw .    #x0f65) (:pcmpgtd .  #x0f66) (:packuswb . #x0f67)
  (:pshufd .    #x0f70)  #|   grp12       |#   #|   grp13       |#   #|   grp14       |#  (:pcmpeqb .    #x0f74) (:pcmpeqw .    #x0f75) (:pcmpeqd .  #x0f76)  #|   invalid    |#
  (:xadd .      #x0fc0) (:xadd .      #x0fc1) (:cmppd .     #x0fc2)  #|   invalid     |#  (:pinsrw .     #x0fc4) (:pextsrw .    #x0fc5) (:shufpd .   #x0fc6)  #|   invalid    |#
  (:addsubpd .  #x0fd0) (:psrlw .     #x0fd1) (:psrld .     #x0fd2) (:psrlq .     #x0fd3) (:paddq .      #x0fd4) (:pmullw .     #x0fd5) (:movq .     #x0fd6) (:pmovmskb . #x0fd7)
  (:pavgb .     #x0fe0) (:psraw .     #x0fe1) (:psrad .     #x0fe2) (:pavgw .     #x0fe3) (:pmulhuw .    #x0fe4) (:pmulhw .     #x0fe5) (:cvttpd2d . #x0fe6) (:movntdq .  #x0fe7)
   #|   invalid     |#  (:psllw .     #x0ff1) (:pslld .     #x0ff2) (:psllq .     #x0ff3) (:pmuludq .    #x0ff4) (:pmaddwd .    #x0ff5) (:psadbw .   #x0ff6) (:maskmovdqu . #x0ff7)
  (:movapd .    #x0f28) (:movapd .    #x0f29) (:cvtpi2pd .  #x0f2a) (:movntpd .   #x0f2b) (:cvttpd2pi .  #x0f2c) (:cvtpd2pi .   #x0f2d) (:ucomisd .  #x0f2e) (:comisd .   #x0f2f)
  (:addpd .     #x0f58) (:mulpd .     #x0f59) (:cvtpd2ps .  #x0f5a) (:cvtps2dq .  #x0f5b) (:subpd .      #x0f5c) (:minpd .      #x0f5d) (:divpd .    #x0f5e) (:maxpd .    #x0f5f)
  (:punpckhwb . #x0f68) (:punpckhwd . #x0f69) (:punpckhdq . #x0f6a) (:packssdw .  #x0f6b) (:punpcklqdq . #x0f6c) (:punpckhqdq . #x0f6d) (:movd .     #x0f6e) (:movdqa .   #x0f6f)
   #|   grp17       |#  (:extrq .     #x0f79)  #|   invalid     |#   #|   invalid     |#  (:haddpd .     #x0f7c) (:hsubpd .     #x0f7d) (:movd .     #x0f7e) (:movdqa .   #x0f7f)
  ;; b[8-f]: strange irregularity (heh) -- absence..
  (:psubusb .   #x0fd8) (:psubusw .   #x0fd9) (:pminub .    #x0fda) (:pand .      #x0fdb) (:paddusb .    #x0fdc) (:paddusw .    #x0fdd) (:pmaxub .   #x0fde) (:pandn .    #x0fdf)
  (:psubsb .    #x0fe8) (:psubsw .    #x0fe9) (:pminsw .    #x0fea) (:por .       #x0feb) (:paddsb .     #x0fec) (:paddsw .     #x0fed) (:pmaxsw .   #x0fee) (:pxor .     #x0fef)
  (:psubb .     #x0ff8) (:psubw .     #x0ff9) (:psubd .     #x0ffa) (:psubq .     #x0ffb) (:padb .       #x0ffc) (:padw .       #x0ffd) (:padd .     #x0ffe)  #|   invalid    |#)

(define-attribute-set :xopcode-repn
  (:movsd .     #x0f10) (:movsd .     #x0f11) (:movddup .   #x0f12)  #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#  (:sqrtsd .    #x0f51)  #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:pshuflw .   #x0f70)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:xadd .      #x0fc0) (:xadd .      #x0fc1) (:cmpsd .     #x0fc2)  #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:addsubps .  #x0fd0)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#  (:movdq2q .  #x0fd6)  #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#  (:cvtpd2dq . #x0fe6)  #|   invalid    |#
  (:lddqu .     #x0ff0)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#  (:cvtsi2sd .  #x0f2a) (:movntsd .   #x0f2b) (:cvttsd2si .  #x0f2c) (:cvtsd2si .   #x0f2d)  #|   invalid    |#   #|   invalid    |#
  (:addsd .     #x0f58) (:mulsd .     #x0f59) (:cvtsd2ss .  #x0f5a)  #|    invalid    |#  (:subsd .      #x0f5c) (:minsd .      #x0f5d) (:divsd .    #x0f5e) (:maxsd .    #x0f5f)
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:insertq .   #x0f78) (:insertq .   #x0f79)  #|    invalid    |#   #|    invalid    |#  (:haddps .     #x0f5c) (:hsubps .     #x0f5d)  #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#)

(define-attribute-set :grp1-80
  (:add .    (#x80 0)) (:or .     (#x80 1)) (:adc .    (#x80 2)) (:sbb .   (#x80 3)) (:and .     (#x80 4)) (:sub .    (#x80 5)) (:xor .     (#x80 6)) (:cmp .  (#x80 7)))
(define-attribute-set :grp1-81
  (:add .    (#x81 0)) (:or .     (#x81 1)) (:adc .    (#x81 2)) (:sbb .   (#x81 3)) (:and .     (#x81 4)) (:sub .    (#x81 5)) (:xor .     (#x81 6)) (:cmp .  (#x81 7)))
(define-attribute-set :grp1-82-compatmode
  (:add .    (#x82 0)) (:or .     (#x82 1)) (:adc .    (#x82 2)) (:sbb .   (#x82 3)) (:and .     (#x82 4)) (:sub .    (#x82 5)) (:xor .     (#x82 6)) (:cmp .  (#x82 7)))
(define-attribute-set :grp1-83
  (:add .    (#x83 0)) (:or .     (#x83 1)) (:adc .    (#x83 2)) (:sbb .   (#x83 3)) (:and .     (#x83 4)) (:sub .    (#x83 5)) (:xor .     (#x83 6)) (:cmp .  (#x83 7)))
(define-attribute-set :grp1-8f
  (:pop .    (#x8f 0))  #|   invalid    |#   #|    invalid   |#   #|   invalid   |#   #|    invalid    |#   #|   invalid    |#   #|   invalid     |#   #|   invalid   |#)
(define-attribute-set :grp2-c0
  (:rol .    (#xc0 0)) (:ror .    (#xc0 1)) (:rcl .    (#xc0 2)) (:rcr .   (#xc0 3)) (:shl/sal . (#xc0 4)) (:shr .    (#xc0 5)) (:shl/sal . (#xc0 6)) (:sar .  (#xc0 7)))
(define-attribute-set :grp2-c1
  (:rol .    (#xc1 0)) (:ror .    (#xc1 1)) (:rcl .    (#xc1 2)) (:rcr .   (#xc1 3)) (:shl/sal . (#xc1 4)) (:shr .    (#xc1 5)) (:shl/sal . (#xc1 6)) (:sar .  (#xc1 7)))
(define-attribute-set :grp2-d0
  (:rol .    (#xd0 0)) (:ror .    (#xd0 1)) (:rcl .    (#xd0 2)) (:rcr .   (#xd0 3)) (:shl/sal . (#xd0 4)) (:shr .    (#xd0 5)) (:shl/sal . (#xd0 6)) (:sar .  (#xd0 7)))
(define-attribute-set :grp2-d1
  (:rol .    (#xd1 0)) (:ror .    (#xd1 1)) (:rcl .    (#xd1 2)) (:rcr .   (#xd1 3)) (:shl/sal . (#xd1 4)) (:shr .    (#xd1 5)) (:shl/sal . (#xd1 6)) (:sar .  (#xd1 7)))
(define-attribute-set :grp2-d2
  (:rol .    (#xd2 0)) (:ror .    (#xd2 1)) (:rcl .    (#xd2 2)) (:rcr .   (#xd2 3)) (:shl/sal . (#xd2 4)) (:shr .    (#xd2 5)) (:shl/sal . (#xd2 6)) (:sar .  (#xd2 7)))
(define-attribute-set :grp2-d3                                                                                  
  (:rol .    (#xd3 0)) (:ror .    (#xd3 1)) (:rcl .    (#xd3 2)) (:rcr .   (#xd3 3)) (:shl/sal . (#xd3 4)) (:shr .    (#xd3 5)) (:shl/sal . (#xd3 6)) (:sar .  (#xd3 7)))
(define-attribute-set :grp3-f6
  (:test .   (#xf6 0)) (:test .   (#xf6 1)) (:not .    (#xf6 2)) (:neg .   (#xf6 3)) (:mul .     (#xf6 4)) (:imul .   (#xf6 5)) (:div .     (#xf6 6)) (:idiv . (#xf6 7)))
(define-attribute-set :grp3-f7
  (:test .   (#xf7 0)) (:test .   (#xf7 1)) (:not .    (#xf7 2)) (:neg .   (#xf7 3)) (:mul .     (#xf7 4)) (:imul .   (#xf7 5)) (:div .     (#xf7 6)) (:idiv . (#xf7 7)))
(define-attribute-set :grp4-fe
  (:inc .    (#xfe 0)) (:dec .    (#xfe 1))  #|    invalid   |#   #|   invalid   |#   #|    invalid    |#   #|   invalid    |#   #|   invalid     |#   #|   invalid   |#)
(define-attribute-set :grp5-ff
  (:inc .    (#xff 0)) (:dec .    (#xff 1)) (:call .   (#xff 2)) (:call .  (#xff 3)) (:jmp .     (#xff 4)) (:jmp .    (#xff 5)) (:push .    (#xff 6))  #|   invalid   |#)
(define-attribute-set :grp6-0f-00
  (:sldt . (#x0f00 0)) (:str .  (#x0f00 1)) (:lldt . (#x0f00 2)) (:ltr . (#x0f00 3)) (:verr .  (#x0f00 4)) (:verw . (#x0f00 5))  #|   invalid     |#   #|   invalid   |#)
(define-attribute-set :grp7-0f-01
  (:sgdt . (#x0f01 0))  #|     mod      |#  (:lgdt . (#x0f01 2))  #|     mod     |#  (:smsw .  (#x0f01 4))  #|  invalid     |#  (:lmsw .  (#x0f01 6))  #|     mod     |#)

;; extension by mod00 renders them, opcodes, unchanged
(define-attribute-set :grp7-0f-01-1-0
  (:sidt .   (#x0f01 1 0)))
(define-attribute-set :grp7-0f-01-3-0
  (:lidt .   (#x0f01 3 0)))
(define-attribute-set :grp7-0f-01-7-0
  (:invlpg . (#x0f01 7 0)))

;; reg, mod11, and three r/m bits -- ugh, three-byte opcodes!
(define-attribute-set :grp7-0f-01-1-3
  (:swapgs .  (#x0f01 1 3 0)) (:rdtscp .  (#x0f01 1 3 1)))
(define-attribute-set :grp7-0f-01-3-3
  (:vmrun .   (#x0f01 3 3 0)) (:vmmcall . (#x0f01 3 3 1)) (:vmload . (#x0f01 3 3 2)) (:vmsave .  (#x0f01 3 3 3))
  (:stgi .    (#x0f01 3 3 4)) (:clgi .    (#x0f01 3 3 5)) (:skinit . (#x0f01 3 3 6)) (:invlpga . (#x0f01 3 3 7)))
(define-attribute-set :grp7-0f-01-7-3
  (:monitor . (#x0f01 7 3 0)) (:mwait .   (#x0f01 7 3 1)))

(define-attribute-set :grp8-0f-ba
   #|    invalid     |#   #|     invalid     |#   #|    invalid      |#   #|     invalid     |#  (:bt .     (#x0fba 4)) (:bts . (#x0fba 5)) (:btr .    (#x0fba 6)) (:btc .    (#x0fba 7)))
(define-attribute-set :grp9-0f-c7 
   #|    invalid     |# (:cmpxchg8/16b . (#x0fc7 1)) #| invalid      |#   #|     invalid     |#   #|    invalid     |#   #|   invalid   |#   #|    invalid     |#   #|     invalid      |#)
(define-attribute-set :grp10-0f-b9
   #|     what       |#   #|        a        |#   #|    genius       |#   #|      plan       |#   #|    ???????     |#   #|   !!!!!!!   |#   #|     genius     |#   #|     !??!?!?      |#)
(define-attribute-set :grp11-c6
  (:mov .    (#x0fc6 0))  #|     invalid     |#   #|    invalid      |#   #|     invalid     |#   #|    invalid     |#   #|   invalid   |#   #|    invalid     |#   #|     invalid      |#)
(define-attribute-set :grp11-c7
  (:mov .    (#x0fc7 0))  #|     invalid     |#   #|    invalid      |#   #|     invalid     |#   #|    invalid     |#   #|   invalid   |#   #|    invalid     |#   #|     invalid      |#)
;; XXX: this is the only place we commit to the opcode bastardisation sin, really...
(define-attribute-set :grp12-0f-71
   #|    invalid     |#   #|     invalid     |#  (:psrlw .  (#x00f71 2))  #|     invalid     |#  (:psraw . (#x00f71 4))  #|   invalid   |#  (:psllw . (#x00f71 6))  #|     invalid      |#)
(define-attribute-set :grp12-0f-71-op
   #|    invalid     |#   #|     invalid     |#  (:psrlw .  (#x10f71 2))  #|     invalid     |#  (:psraw . (#x10f71 4))  #|   invalid   |#  (:psllw . (#x10f71 6))  #|     invalid      |#)
(define-attribute-set :grp13-0f-72
   #|    invalid     |#   #|     invalid     |#  (:psrld .  (#x00f72 2))  #|     invalid     |#  (:psrad . (#x00f72 4))  #|   invalid   |#  (:pslld . (#x00f72 6))  #|     invalid      |#)
(define-attribute-set :grp13-0f-72-op
   #|    invalid     |#   #|     invalid     |#  (:psrld .  (#x10f72 2))  #|     invalid     |#  (:psrad . (#x10f72 4))  #|   invalid   |#  (:pslld . (#x10f72 6))  #|     invalid      |#)
(define-attribute-set :grp14-0f-73
   #|    invalid     |#   #|     invalid     |#  (:psrlq .  (#x00f73 2))  #|     invalid     |#   #|    invalid     |#   #|   invalid   |#  (:psllq . (#x00f73 6))  #|     invalid      |#)
(define-attribute-set :grp14-0f-73-op
   #|    invalid     |#   #|     invalid     |#  (:psrlq .  (#x10f73 2)) (:psrldq . (#x10f73 3))  #|    invalid     |#   #|   invalid   |#  (:psllq . (#x10f73 6)) (:pslldq . (#x10f73 7)))
(define-attribute-set :grp15-0f-ae
  (:fxsave . (#x0fae 0)) (:fxrstor . (#x0fae 1)) (:ldmxcsr . (#x0fae 2)) (:stmxcsr . (#x0fae 3))  #|    invalid     |#   #|     mod     |#   #|      mod       |#   #|       mod        |#)

;; reg, mod
(define-attribute-set :grp15-0f-ae-5
                            (:mfence .  (#x0fae 5 3)))
(define-attribute-set :grp15-0f-ae-6
                            (:lfence .  (#x0fae 6 3)))
(define-attribute-set :grp15-0f-ae-7
  (:clflush . (#x0fae 7 0)) (:sfence .  (#x0fae 7 3)))

(define-attribute-set :grp16-0f-18
  (:prefetch . (#x0f18 0)) (:prefetch . (#x0f18 1)) (:prefetch . (#x0f18 2)) (:prefetch . (#x0f18 3)) (:nop . (#x0f18 4)) (:nop . (#x0f18 5)) (:nop . (#x0f18 6)) (:nop . (#x0f18 7)))
(define-attribute-set :grp17-0f-78-op
  (:extrq .    (#x0f78 0))  #|     invalid      |#   #|     invalid      |#   #|      invalid     |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grpp-0f-0d
  (:prefetch . (#x0f0d 0)) (:prefetch . (#x0f0d 1))  #|     reserved     |#  (:prefetch . (#x0f0d 3))  #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#)


;;; ModRM
;;;
;; C - reg:control
;; D - reg:debug
;; E - GPR/mem(segreg,sib,disp)
;; G - reg:GPR
;; M - mem
;; N - r/m:MMX64, mod:11
;; P - reg:MMX64
;; Q - 64bit MMX/mem(segreg,sib,disp)
;; R - r/m:GPR, mod:11
;; S - reg:segreg
;; U - r/m:XMM128, mod:11
;; V - reg:XMM128
;; W - 128bit XMM/mem(segreg,sib,disp)

;;; Misc
;;;
;; A - imm farptr
;; F - rflags
;; I - imm
;; J - rip-relative offset
;; O - imm offset, modrm-less, sib-less
;; X - ds.rsi
;; Y - es.rdi
;; a - two consecutive memory operands, used in BOUND
;; b - force byte
;; w - force word
;; d - force dword
;; q - force qword (64 bit)
;; dq - force double qword (128 bit)
;; p - 32/48 bit farptr
;; pi - MMX packed int (64 bit)
;; ps - SP packed FP (128 bit)
;; pd - DP packed FP (128 bit)
;; s - 6/10 byte pseudo-descriptor 
;; si - scalar dword
;; ss - scalar SP FP
;; sd - scalar DP FP
;; v - integer, depending on the EOpS
;; z - { 16 <= EOpS 32, 32 <= EOpS { 32, 64 }}
;; /... - modrm reg/sib base

(defstruct (instruction-argument (:conc-name instarg-) (:constructor make-instarg (type position sourcep destp)))
  (type     nil :type argument-type         :read-only t)
  (position nil :type (or null (integer 0)) :read-only t)
  (sourcep  nil :type boolean               :read-only t)
  (destp    nil :type boolean               :read-only t))

(defclass instruction-format ()
  ((id       :reader format-id       :initarg :id)
   (arglist  :reader format-arglist  :initarg :arglist)
   (funclist :reader format-funclist :initarg :funclist)))

(define-subcontainer insn-format                :type instruction-format :container-slot id->format :if-exists :continue)
(define-subcontainer mnemo/opcode-insn-format   :type instruction-format :container-slot mnemo/opcode->format :if-exists :continue)
(define-subcontainer mnemo/arglist-insn-formats :type list               :container-slot mnemo/arglist->formats :if-exists :continue :if-does-not-exist :continue)

(defun ensure-instruction-format (isa id attributes argspec insn/opcode-pairlist)
  (let* ((arglist (mapcar #'car (remove-if-not #'consp argspec)))
         (f (make-instance (isa-format-type isa) :id id :arglist arglist :funclist nil))
         (posn 0))
    (with-slots (funclist) f
      (iter (for (s/d-spec argtype) on argspec by #'cddr)
            (let ((arglistedp (consp argtype))
                  (argtype (ensure-car argtype))) ; get rid of the arglistness hint
              (push (make-instarg (argtype isa argtype) (when arglistedp posn)
                                  (or (eq s/d-spec 'r) (eq s/d-spec 'rw))
                                  (or (eq s/d-spec 'w) (eq s/d-spec 'rw)))
                    funclist)
              (when arglistedp
                (incf posn))))
      (nreversef funclist)
      (iter (for (op code) in insn/opcode-pairlist)
            (setf (mnemo/opcode-insn-format isa (cons op code)) f)
            (push f (mnemo/arglist-insn-formats isa (cons op arglist))))
      (setf (insn-format isa id) f))))

(defmacro defiformat (id attributes argspec &body insn/opcode-specs)
  `(ensure-instruction-format *isa* ,id ',attributes ',argspec '(,@insn/opcode-specs)))

;; Issues:
;;  the correspondence of sources and destinatios to instruction arguments is unclear, and in particular,
;;  whether we have the first argument as source is unclear from our representation
;;
;;  GDTR, IDTR, RPL, DPL, STAR, and, likely, some other system registers are either not accounted for properly, or ignored completely

;; Mnemonics:
;;  > - depends on RFLAGS
;;  < - modifies RFLAGS
;;  @ - modifies RIP and, maybe, CS and/or RSP, implies |
;;  @@ - like @, but modifies more
;;  @@@ - like @, but modifies still more
;;  # - port I/O
;;  $ - system-level crap is going-on
;;;; invert sourceness/destness of first/second/ argument
;;  | - does not modify its first argument
;;  2| - /does/ modify its second argument
;;  ! - does not source its first argument
;;  2! - does not source its second argument

(defun make-addressing-subtree-onethird (sixty-four-p)
  `(nil ((active-set (0 1 2 3))
         (seek 08) ; last seek was before parsing the modrm microformat, let's prepare for displacement/SIB
         (dispatch :mod))
        (#b00 ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
               (dispatch (:b :r/m)))
              (#x4 #xc ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
                        (microformat :uf-sib 08 00)
                        (seek 08)
                        (dispatch :base))
                   ((#x5 #x13) ((active-set (0 1 2))
                                (dispatch :base :mod))
                    ((#x5 0) () "")))
              (#x5 #xd ()
                   ,@(if sixty-four-p
                         `("[RIP+disp32]" :rip :imm32)
                         `("[disp32]"          :imm32))))
        (#b01 ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
               (dispatch (:b :r/m))))
        (#b10 ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
               (dispatch (:b :r/m))))
        (#b11 ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
               (dispatch (:b :r/m))))))

(defun make-sibhalf-subtree-lastthird ()
  `)

(defiformat "<>AL"               () (rw :rflags rw :al)                                        (:aaa #x37     :aas #x3f     :daa #x27     :das #x2f))
(defiformat "<AL, AH, imm8"      () ( w :rflags rw :al   r  :ah  r (:imm8))                    (:aad #xd5))
(defiformat "<2|2!AL, AH, imm8"  () ( w :rflags rw :al    w :ah  r (:imm8))                    (:aam #xd4))
                                                                                       
(defiformat "<AL,  imm8"         () ( w :rflags rw (:al)               r  (:imm8))             (:add #x04   :adc #x14   :sbb #x1c   :sub #x2c))
(defiformat "<XAX, immXX"        () ( w :rflags rw (:xax)              r  (:immx))             (:add #x05   :adc #x15   :sbb #x1d   :sub #x2d))
(defiformat "<~S,  imm8"         () ( w :rflags rw ((8 (tree :r/m)))   r  (:imm8))             (:add #x80 0 :adc #x80 2 :sbb #x80 3 :sub #x80 5))
(defiformat "<~S, immXX"         () ( w :rflags rw ((x (tree :r/m)))   r  (:immx))             (:add #x81 0 :adc #x81 2 :sbb #x81 3 :sub #x81 5))
(defiformat "<~S, imm8"          () ( w :rflags rw ((x (tree :r/m)))   r  (:imm8))             (:add #x83 0 :adc #x83 2 :sbb #x83 3 :sub #x83 5 :bts #xba 5 :btr #xba 6 :btc #xba 7))
(defiformat "<~S,  reg8"         () ( w :rflags rw ((8 (tree :r/m)))   r  (:reg8))             (:add #x00   :adc #x10   :sbb #x18   :sub #x28  ))
(defiformat "<~S, regXX"         () ( w :rflags rw ((x (tree :r/m)))   r  (:regx))             (:add #x01   :adc #x11   :sbb #x19   :sub #x29   :bts #xab   :btr #xb3   :btc #xbb  ))
(defiformat "<reg8,  ~S"         () ( w :rflags rw (:reg8)             r  (8 ((tree :r/m))))   (:add #x02   :adc #x12   :sbb #x1a   :sub #x2a  ))
(defiformat "<reg8,  ~S"         () ( w :rflags rw (:reg8)             r  (x ((tree :r/m))))   (:add #x03   :adc #x13   :sbb #x1b   :sub #x2b  ))
                                                                                                                  
(defiformat "AL, imm8"           () (           rw (:al)               r  (:imm8))             (:or #x0c     :and #x24    :xor #x34))
(defiformat "XAX, immXX"         () (           rw (:xax)              r  (:immx))             (:or #x0d     :and #x25    :xor #x35))
(defiformat "~S, imm8"           () (           rw ((8 (tree :r/m)))   r  (:imm8))             (:or #x80 1   :and #x80 4  :xor #x80 6))
(defiformat "~S, immXX"          () (           rw ((x (tree :r/m)))   r  (:immx))             (:or #x81 1   :and #x81 4  :xor #x81 6))
(defiformat "~S, imm8"           () (           rw ((x (tree :r/m)))   r  (:imm8))             (:or #x83 1   :and #x83 4  :xor #x83 6))
(defiformat "~S, reg8"           () (           rw ((8 (tree :r/m)))   r  (:reg8))             (:or #x08     :and #x20    :xor #x30))
(defiformat "~S, regXX"          () (           rw ((x (tree :r/m)))   r  (:regx))             (:or #x09     :and #x21    :xor #x31))
(defiformat "reg8, ~S"           () (           rw (:reg8)             r  ((8 (tree :r/m))))   (:or #x0a     :and #x22    :xor #x32))
(defiformat "regXX, ~S"          () (           rw (:regx)             r  ((x (tree :r/m))))   (:or #x0b     :and #x23    :xor #x33))
                                                                                                            
(defiformat ">!~S"               () (           rw ((x (tree :r/m)))   r  :rflags)             (:seto  #x90 0 :setno  #x91 0 :setc   #x92 0 :setnc  #x93 0)
                                                                                               (:setz  #x94 0 :setnz  #x95 0 :setna  #x96 0 :seta   #x97 0)
                                                                                               (:sets  #x98 0 :setns  #x99 0 :setp   #x9a 0 :setnp  #x9b 0)
                                                                                               (:setl  #x9c 0 :setnl  #x9d 0 :setng  #x9e 0 :setg   #x9f 0))

(defiformat ">regXX, ~S"         () (rw (:regx) r  ((x (tree :r/m)))   r  :rflags)             (:cmovo #x40 0 :cmovno #x41 0 :cmovc  #x42 0 :cmovnc #x43 0)
                                                                                               (:cmovz #x44 0 :cmovnz #x45 0 :cmovna #x46 0 :cmova  #x47 0)
                                                                                               (:cmovs #x48 0 :cmovns #x49 0 :cmovp  #x4a 0 :cmovnp #x4b 0)
                                                                                               (:cmovl #x4c 0 :cmovnl #x4d 0 :cmovng #x4e 0 :cmovg  #x4f 0))

;; (defiformat "<|AL, imm8"          (:rflags)                        (:al :imm8))                                   ;; CMP, TEST
;; (defiformat "<|AX, imm16"            (:rflags)                        (:ax :imm16))                                  ;; CMP, TEST
;; (defiformat "<|EAX, imm32"           (:rflags)                        (:eax :imm32))                                 ;; CMP, TEST
;; (defiformat "<|RAX, imm32"           (:rflags)                        (:rax :imm32))                                 ;; CMP, TEST
;; (defiformat "<|reg/mem8, imm8"       (:rflags)                        (:reg/mem8 :imm8))                             ;; CMP, TEST
;; (defiformat "<|reg/mem16, imm16"     (:rflags)                        (:reg/mem16 :imm16))                           ;; CMP, TEST
;; (defiformat "<|reg/mem32, imm32"     (:rflags)                        (:reg/mem32 :imm32))                           ;; CMP, TEST
;; (defiformat "<|reg/mem64, imm32"     (:rflags)                        (:reg/mem64 :imm32))                           ;; CMP, TEST
;; (defiformat "<|reg/mem16, imm8"      (:rflags)                        (:reg/mem16 :imm8))                            ;; CMP, BT
;; (defiformat "<|reg/mem32, imm8"      (:rflags)                        (:reg/mem32 :imm8))                            ;; CMP, BT
;; (defiformat "<|reg/mem64, imm8"      (:rflags)                        (:reg/mem64 :imm8))                            ;; CMP, BT
;; (defiformat "<|reg/mem8, reg8"       (:rflags)                        (:reg/mem8 :reg8))                             ;; CMP, TEST
;; (defiformat "<|reg/mem16, reg16"     (:rflags)                        (:reg/mem16 :reg16))                           ;; CMP, TEST, BT
;; (defiformat "<|reg/mem32, reg32"     (:rflags)                        (:reg/mem32 :reg32))                           ;; CMP, TEST, BT
;; (defiformat "<|reg/mem64, reg64"     (:rflags)                        (:reg/mem64 :reg64))                           ;; CMP, TEST, BT
;; (defiformat "<|reg8, reg/mem8"       (:rflags)                        (:reg8 :reg/mem8))                             ;; CMP
;; (defiformat "<|reg16, reg/mem16"     (:rflags)                        (:reg16 :reg/mem16))                           ;; CMP
;; (defiformat "<|reg32, reg/mem32"     (:rflags)                        (:reg32 :reg/mem32))                           ;; CMP
;; (defiformat "<|reg64, reg/mem64"     (:rflags)                        (:reg64 :reg/mem64))                           ;; CMP

;; (defiformat "reg/mem8"               (:reg/mem8)                      (:reg/mem8))                                   ;; NOT
;; (defiformat "reg/mem16"              (:reg/mem16)                     (:reg/mem16))                                  ;; NOT
;; (defiformat "reg/mem32"              (:reg/mem32)                     (:reg/mem32))                                  ;; NOT
;; (defiformat "reg/mem64"              (:reg/mem64)                     (:reg/mem64))                                  ;; NOT

;; (defiformat "<reg/mem8"              (:rflags :reg/mem8)              (:reg/mem8))                                   ;; NEG, DEC, INC
;; (defiformat "<reg/mem16"             (:rflags :reg/mem16)             (:reg/mem16))                                  ;; NEG, DEC, INC
;; (defiformat "<reg/mem32"             (:rflags :reg/mem32)             (:reg/mem32))                                  ;; NEG, DEC, INC
;; (defiformat "<reg/mem64"             (:rflags :reg/mem64)             (:reg/mem64))                                  ;; NEG, DEC, INC

;; (defiformat "|reg16, mem32"          ()                               (:reg16 :mem32))                               ;; BOUND
;; (defiformat "|reg32, mem64"          ()                               (:reg32 :mem64))                               ;; BOUND

;; (defiformat "<reg16"                 (:rflags :reg16)                 (:reg16))                                      ;; DEC, INC
;; (defiformat "<reg32"                 (:rflags :reg32)                 (:reg32))                                      ;; DEC, INC

;; (defiformat "reg32"                  (:reg32)                         (:reg32))                                      ;; BSWAP
;; (defiformat "reg64"                  (:reg64)                         (:reg64))                                      ;; BSWAP

;; ;;;;
;; ;;;; Interrupts
;; ;;;;
;; (defiformat "$@<>imm8"               (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:rflags :imm8 :rip :rsp :cs :ss :mem)) ;; INT, actually potentially it touches a lot more...
;; (defiformat "$@>"                    (:rip :cpl :cs :tss)                       (:rflags))                              ;; INTO, actually potentially it touches a lot more...
;; (defiformat "$@<"                    (:rip :rflags)                   ())                                               ;; INT3, actually potentially it touches a lot more...
;; (defiformat "$@@<"                   (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:cpl :cs :tss))                        ;; IRET, IRETD, IRETQ

;; ;;;;
;; ;;;; Jumps, calls, returns and branches
;; ;;;;
;; (defiformat "@immoff8"               (:rip)                           (:immoff8))                                    ;; JMP
;; (defiformat "@immoff16"              (:rip)                           (:immoff16))                                   ;; JMP
;; (defiformat "@immoff32"              (:rip)                           (:immoff32))                                   ;; JMP
;; (defiformat "@reg/mem16"             (:rip)                           (:reg/mem16))                                  ;; JMP
;; (defiformat "@reg/mem32"             (:rip)                           (:reg/mem32))                                  ;; JMP
;; (defiformat "@reg/mem64"             (:rip)                           (:reg/mem64))                                  ;; JMP

;; (defiformat "@ptr16:16"              (:rip :cs :tss)                  (:ptr16/16))                                   ;; JMP FAR
;; (defiformat "@ptr16:32"              (:rip :cs :tss)                  (:ptr16/32))                                   ;; JMP FAR
;; (defiformat "@mem32"                 (:rip :cs :tss)                  (:mem32))                                      ;; JMP FAR
;; (defiformat "@mem48"                 (:rip :cs :tss)                  (:mem48))                                      ;; JMP FAR

;; (defiformat "@@immoff16"             (:rip :rsp :mem16)               (:rip :rbp :rsp :immoff16))                    ;; CALL
;; (defiformat "@@immoff32"             (:rip :rsp :mem32)               (:rip :rsp :immoff32))                         ;; CALL
;; (defiformat "@@reg/mem16"            (:rip :rsp :mem16)               (:rip :rsp :reg/mem16))                        ;; CALL
;; (defiformat "@@reg/mem32"            (:rip :rsp :mem32)               (:rip :rsp :reg/mem32))                        ;; CALL
;; (defiformat "@@reg/mem64"            (:rip :rsp :mem64)               (:rip :rsp :reg/mem64))                        ;; CALL

;; (defiformat "@@"                     (:rip :rsp)                      (:rip :rsp :mem16))                            ;; RET
;; (defiformat "@@imm8"                 (:rip :rsp)                      (:rip :rsp :mem16 :imm8))                      ;; RET

;; (defiformat "@>immoff8"              (:rip)                           (:rflags :immoff8))                            ;; Jxx
;; (defiformat "@>immoff16"             (:rip)                           (:rflags :immoff16))                           ;; Jxx
;; (defiformat "@>immoff32"             (:rip)                           (:rflags :immoff32))                           ;; Jxx

;; (defiformat "@CX, immoff8"           (:rip)                           (:cx :immoff8))                                ;; JCXZ
;; (defiformat "@ECX, immoff8"          (:rip)                           (:ecx :immoff8))                               ;; JECXZ
;; (defiformat "@RCX, immoff8"          (:rip)                           (:rcx :immoff8))                               ;; JRCXZ

;; (defiformat "@@@ptr16:16"            (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :ptr16/16))       ;; CALL FAR
;; (defiformat "@@@ptr16:32"            (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :ptr16/32))       ;; CALL FAR
;; (defiformat "@@@mem32"               (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :mem32))          ;; CALL FAR
;; (defiformat "@@@mem48"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :mem48))          ;; CALL FAR
;; (defiformat "@@@"                    (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16))               ;; RETF
;; (defiformat "@@@imm16"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16 :imm16))        ;; RETF

;; (defiformat "!AX, AL"                (:ax)                            (:al))                                         ;; CBW
;; (defiformat "!EAX, AX"               (:eax)                           (:ax))                                         ;; CWDE
;; (defiformat "!RAX, EAX"              (:rax)                           (:eax))                                        ;; CDQE

;; (defiformat "2|AX, DX"               (:ax :dx)                        (:ax))                                         ;; CWD
;; (defiformat "2|EAX, EDX"             (:eax :edx)                      (:eax))                                        ;; CDQ
;; (defiformat "2|RAX, RDX"             (:rax :rdx)                      (:rax))                                        ;; CQO

;; (defiformat "<"                      (:rflags)                        ())                                            ;; CLC, CLD, STC, STD
;; (defiformat "$<IF"                   (:rflags)                        (:cpl :cs))                                    ;; CLI, STI
;; (defiformat "<>"                     (:rflags)                        (:rflags))                                     ;; CMC

;; (defiformat "|mem8"                  ()                               (:mem8))                                       ;; CLFLUSH, INVLPG
;; (defiformat "|RAX, ECX"              ()                               (:rax :ecx))                                   ;; INVLPGA

;; (defiformat ""                       ()                               ())                                            ;; LFENCE, SFENCE, MFENCE, NOP, PAUSE
;; (defiformat "|CPL"                   ()                               (:cpl :cs))                                    ;; INVD, WBINVD, HLT
;; (defiformat "|!mem16/32/64"          ()                               ())                                            ;; NOP
;; (defiformat "|!mem8"                 ()                               ())                                            ;; PREFETCH{,W,NTA,0,1,2}

;; ;;;;
;; ;;;; String formats
;; ;;;;                                                                    
;; (defiformat "<>|mem8, mem8"          (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem8 :mem8))   ;; CMPS, CMPSB
;; (defiformat "<>|mem16, mem16"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem16 :mem16)) ;; CMPS, CMPSW
;; (defiformat "<>|mem32, mem32"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem32 :mem32)) ;; CMPS, CMPSD
;; (defiformat "<>|mem64, mem64"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem64 :mem64)) ;; CMPS, CMPSQ

;; (defiformat "!AL, mem8"              (:al  :rsi)                      (:ds :rsi :mem8))                              ;; LODS, LODSB
;; (defiformat "!AX, mem16"             (:ax  :rsi)                      (:ds :rsi :mem16))                             ;; LODS, LODSW
;; (defiformat "!EAX, mem32"            (:eax :rsi)                      (:ds :rsi :mem32))                             ;; LODS, LODSD
;; (defiformat "!RAX, mem64"            (:rax :rsi)                      (:ds :rsi :mem64))                             ;; LODS, LODSQ

;; (defiformat "!mem8, mem8"            (:rsi :rdi :mem8)                (:segreg :rsi :es :rdi :mem8))                 ;; MOVS, MOVSB
;; (defiformat "!mem16, mem16"          (:rsi :rdi :mem16)               (:segreg :rsi :es :rdi :mem16))                ;; MOVS, MOVSW
;; (defiformat "!mem32, mem32"          (:rsi :rdi :mem32)               (:segreg :rsi :es :rdi :mem32))                ;; MOVS, MOVSD
;; (defiformat "!mem64, mem64"          (:rsi :rdi :mem64)               (:segreg :rsi :es :rdi :mem64))                ;; MOVS, MOVSQ

;; (defiformat "<>|AL, mem8"            (:rflags :rdi)                   (:rflags :es :rdi :al :mem8))                  ;; SCAS, SCASB
;; (defiformat "<>|AX, mem16"           (:rflags :rdi)                   (:rflags :es :rdi :ax :mem16))                 ;; SCAS, SCASW
;; (defiformat "<>|EAX, mem32"          (:rflags :rdi)                   (:rflags :es :rdi :eax :mem32))                ;; SCAS, SCASD
;; (defiformat "<>|RAX, mem64"          (:rflags :rdi)                   (:rflags :es :rdi :rax :mem64))                ;; SCAS, SCASQ

;; (defiformat "!mem8, AL"              (:mem8  :rdi)                    (:es :rdi :al))                                ;; STOS, STOSB
;; (defiformat "!mem16, AX"             (:mem16 :rdi)                    (:es :rdi :ax))                                ;; STOS, STOSW
;; (defiformat "!mem32, EAX"            (:mem32 :rdi)                    (:es :rdi :eax))                               ;; STOS, STOSD
;; (defiformat "!mem64, RAX"            (:mem64 :rdi)                    (:es :rdi :rax))                               ;; STOS, STOSQ
;; ;;;;

;; (defiformat "<AL, reg/mem8, reg8"    (:rflags :al :reg/mem8)          (:al :reg/mem8 :reg8))                         ;; CMPXCHG
;; (defiformat "<AX, reg/mem16, reg16"  (:rflags :al :reg/mem16)         (:al :reg/mem16 :reg16))                       ;; CMPXCHG
;; (defiformat "<EAX, reg/mem32, reg32" (:rflags :al :reg/mem32)         (:al :reg/mem32 :reg32))                       ;; CMPXCHG
;; (defiformat "<RAX, reg/mem64, reg64" (:rflags :al :reg/mem64)         (:al :reg/mem64 :reg64))                       ;; CMPXCHG

;; (defiformat "<EDX:EAX, reg/mem64, ECX:EBX"  (:rflags :edx :eax :reg/mem64)  (:edx :eax :reg/mem64 :ecx :edx))        ;; CMPXCHG8B
;; (defiformat "<RDX:RAX, reg/mem128, RCX:RBX" (:rflags :rdx :rax :reg/mem128) (:rdx :rax :reg/mem128 :rcx :rdx))       ;; CMPXCHG16B

;; (defiformat "EAX, EBX, ECX, EDX"            (:eax :ebx :ecx :edx)     (:eax))                                        ;; CPUID
                                                                                                                         
;; (defiformat "<AL, AH, reg/mem8"             (:rflags :ah :al)         (:ax :reg/mem8))                               ;; DIV, IDIV
;; (defiformat "<DX, AX, reg/mem16"            (:rflags :dx :ax)         (:dx :ax :reg/mem16))                          ;; DIV, IDIV
;; (defiformat "<EDX, EAX, reg/mem32"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
;; (defiformat "<RDX, RAX, reg/mem64"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
;; (defiformat "<!AX, AL, reg/mem8"            (:rflags :ax)             (:al :reg/mem8))                               ;; MUL, IMUL
;; (defiformat "<!DX, AX, AX, reg/mem16"       (:rflags :dx :ax)         (:ax :reg/mem16))                              ;; MUL, IMUL
;; (defiformat "<!EDX, EAX, EAX, reg/mem32"    (:rflags :edx :eax)       (:eax :reg/mem32))                             ;; MUL, IMUL
;; (defiformat "<!RDX, RAX, RAX, reg/mem64"    (:rflags :rdx :rax)       (:rax :reg/mem64))                             ;; MUL, IMUL
                                                                                                                         
;; (defiformat "imm16, 0"                      (:rsp :rbp)               (:imm16 0 :rsp :rbp :ss))                      ;; ENTER
;; (defiformat "imm16, 1"                      (:rsp :rbp)               (:imm16 1 :rsp :rbp :ss))                      ;; ENTER
;; (defiformat "imm16, imm8"                   (:rsp :rbp)               (:imm16 :imm8 :rsp :rbp :ss))                  ;; ENTER
                                                                                                                         
;; (defiformat "BP, SP"                        (:bp :sp)                 (:bp :mem16))                                  ;; LEAVE 
;; (defiformat "EBP, ESP"                      (:ebp :esp)               (:ebp :mem32))                                 ;; LEAVE 
;; (defiformat "RBP, RSP"                      (:rbp :rsp)               (:rbp :mem64))                                 ;; LEAVE 
                                                                                                                         
;; (defiformat "<!reg16, reg/mem16, imm8"      (:rflags :reg16)          (:reg/mem16 :imm8))                            ;; IMUL
;; (defiformat "<!reg32, reg/mem32, imm8"      (:rflags :reg32)          (:reg/mem32 :imm8))                            ;; IMUL
;; (defiformat "<!reg64, reg/mem64, imm8"      (:rflags :reg64)          (:reg/mem64 :imm8))                            ;; IMUL
;; (defiformat "<!reg16, reg/mem16, imm16"     (:rflags :reg16)          (:reg/mem16 :imm16))                           ;; IMUL
;; (defiformat "<!reg32, reg/mem32, imm32"     (:rflags :reg32)          (:reg/mem32 :imm32))                           ;; IMUL
;; (defiformat "<!reg64, reg/mem64, imm32"     (:rflags :reg64)          (:reg/mem64 :imm32))                           ;; IMUL
                                                                                                                         
;; (defiformat "#!AL, DX"                      (:al)                     (:dx :tss))                                    ;; IN
;; (defiformat "#!AX, DX"                      (:ax)                     (:dx :tss))                                    ;; IN
;; (defiformat "#!EAX, DX"                     (:eax)                    (:dx :tss))                                    ;; IN
;; (defiformat "#!AL, imm8"                    (:al)                     (:imm8 :tss))                                  ;; IN
;; (defiformat "#!AX, imm8"                    (:ax)                     (:imm8 :tss))                                  ;; IN
;; (defiformat "#!EAX, imm8"                   (:eax)                    (:imm8 :tss))                                  ;; IN
                                                                                                                               
;; (defiformat "#|DX, AL"                      ()                        (:dx :al  :tss))                               ;; OUT
;; (defiformat "#|DX, AX"                      ()                        (:dx :ax  :tss))                               ;; OUT
;; (defiformat "#|DX, EAX"                     ()                        (:dx :eax :tss))                               ;; OUT
;; (defiformat "#imm8, AL"                     ()                        (:imm8 :al  :tss))                             ;; OUT
;; (defiformat "#imm8, AX"                     ()                        (:imm8 :ax  :tss))                             ;; OUT
;; (defiformat "#imm8, EAX"                    ()                        (:imm8 :eax :tss))                             ;; OUT
                                                                                                                               
;; (defiformat "#!>mem8, DX"                   (:mem8 :rdi)              (:rflags :es :rdi :dx :tss))                   ;; INS, INSB
;; (defiformat "#!>mem16, DX"                  (:mem16 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSW
;; (defiformat "#!>mem32, DX"                  (:mem32 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSD
;; (defiformat "#|>DX, mem8"                   (:rsi)                    (:rflags :ds :rsi :dx :mem8  :tss))            ;; OUTS, OUTSB
;; (defiformat "#|>DX, mem16"                  (:rsi)                    (:rflags :ds :rsi :dx :mem16 :tss))            ;; OUTS, OUTSW
;; (defiformat "#|>DX, mem32"                  (:rsi)                    (:rflags :ds :rsi :dx :mem32 :tss))            ;; OUTS, OUTSD
                                                                                                                         
;; (defiformat ">!AH"                          (:ah)                     (:rflags))                                     ;; LAHF
;; (defiformat "<|!AH"                         (:rflags)                 (:ah))                                         ;; SAHF
                                                                                                                         
;; (defiformat "!DS, reg16, mem32"             (:ds :reg16)              (:mem32))                                      ;; LDS
;; (defiformat "!DS, reg32, mem48"             (:ds :reg32)              (:mem48))                                      ;; LDS
;; (defiformat "!ES, reg16, mem32"             (:es :reg16)              (:mem32))                                      ;; LES
;; (defiformat "!ES, reg32, mem48"             (:es :reg32)              (:mem48))                                      ;; LES
;; (defiformat "!FS, reg16, mem32"             (:fs :reg16)              (:mem32))                                      ;; LFS
;; (defiformat "!FS, reg32, mem48"             (:fs :reg32)              (:mem48))                                      ;; LFS
;; (defiformat "!GS, reg16, mem32"             (:gs :reg16)              (:mem32))                                      ;; LGS
;; (defiformat "!GS, reg32, mem48"             (:gs :reg32)              (:mem48))                                      ;; LGS
;; (defiformat "!SS, reg16, mem32"             (:ss :reg16)              (:mem32))                                      ;; LSS
;; (defiformat "!SS, reg32, mem48"             (:ss :reg32)              (:mem48))                                      ;; LSS
                                                                                                                         
;; (defiformat "!reg16, mem"                   (:reg16)                  (:mem))                                        ;; LEA
;; (defiformat "!reg32, mem"                   (:reg32)                  (:mem))                                        ;; LEA
;; (defiformat "!reg64, mem"                   (:reg64)                  (:mem))                                        ;; LEA
                                                                                                                         
;; (defiformat "@RCX, immoff8"                 (:rip :rcx)               (:rcx :immoff8))                               ;; LOOP
;; (defiformat "@>RCX, immoff8"                (:rip :rcx)               (:rflags :rcx :immoff8))                       ;; LOOPxx
                                                                                                                         
;; (defiformat "<!reg16, reg/mem16"            (:rflags :reg16)          (:reg/mem16))                                  ;; LZCNT, POPCNT
;; (defiformat "<!reg32, reg/mem32"            (:rflags :reg32)          (:reg/mem32))                                  ;; LZCNT, POPCNT
;; (defiformat "<!reg64, reg/mem64"            (:rflags :reg64)          (:reg/mem64))                                  ;; LZCNT, POPCNT
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; load/stores                                                                                                         
;; ;;;;                                                                                                                     
;; (defiformat "!reg/mem8, reg8"               (:reg/mem8)               (:reg8))                                       ;; MOV
;; (defiformat "!reg/mem16, reg16"             (:reg/mem16)              (:reg16))                                      ;; MOV
;; (defiformat "!reg/mem32, reg32"             (:reg/mem32)              (:reg32))                                      ;; MOV
;; (defiformat "!reg/mem64, reg64"             (:reg/mem64)              (:reg64))                                      ;; MOV
;; (defiformat "!reg8, reg/mem8"               (:reg8)                   (:reg/mem8))                                   ;; MOV
;; (defiformat "!reg16, reg/mem16"             (:reg16)                  (:reg/mem16))                                  ;; MOV
;; (defiformat "!reg32, reg/mem32"             (:reg32)                  (:reg/mem32))                                  ;; MOV
;; (defiformat "!reg64, reg/mem64"             (:reg64)                  (:reg/mem64))                                  ;; MOV

;; (defiformat "!reg16, reg/mem8"              (:reg16)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (defiformat "!reg32, reg/mem8"              (:reg32)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (defiformat "!reg64, reg/mem8"              (:reg64)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (defiformat "!reg32, reg/mem16"             (:reg32)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
;; (defiformat "!reg64, reg/mem16"             (:reg64)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
;; (defiformat "!reg64, reg/mem32"             (:reg64)                  (:reg/mem32))                                  ;; MOVSXD (weird for 16bit op; separate format?)                     
                                                                                                    
;; (defiformat "!mem32, reg32"                 (:mem32)                  (:reg32))                                      ;; MOVNTI
;; (defiformat "!mem64, reg64"                 (:mem64)                  (:reg64))                                      ;; MOVNTI
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; RIP-relative load/stores                                                                                            
;; ;;;;                                                                                                                     
;; (defiformat "!AL, immoff8"                  (:al)                     (:immoff8 :mem8))                              ;; MOV
;; (defiformat "!AX, immoff16"                 (:ax)                     (:immoff16 :mem16))                            ;; MOV
;; (defiformat "!EAX, immoff32"                (:eax)                    (:immoff32 :mem32))                            ;; MOV
;; (defiformat "!RAX, immoff64"                (:rax)                    (:immoff64 :mem64))                            ;; MOV
;; (defiformat "immoff8, AL"                   (:mem8)                   (:immoff8 :al))                                ;; MOV
;; (defiformat "immoff16, AX"                  (:mem16)                  (:immoff16 :ax))                               ;; MOV
;; (defiformat "immoff32, EAX"                 (:mem32)                  (:immoff32 :eax))                              ;; MOV
;; (defiformat "immoff64, RAX"                 (:mem64)                  (:immoff64 :rax))                              ;; MOV
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; constant                                                                                                            
;; ;;;;                                                                                                                     
;; (defiformat "!reg8, imm8"                   (:reg8)                   (:imm8))                                       ;; MOV
;; (defiformat "!reg16, imm16"                 (:reg16)                  (:imm16))                                      ;; MOV
;; (defiformat "!reg32, imm32"                 (:reg32)                  (:imm32))                                      ;; MOV
;; (defiformat "!reg64, imm64"                 (:reg64)                  (:imm64))                                      ;; MOV
;; (defiformat "!reg/mem8, imm8"               (:reg/mem8)               (:imm8))                                       ;; MOV
;; (defiformat "!reg/mem16, imm16"             (:reg/mem16)              (:imm16))                                      ;; MOV
;; (defiformat "!reg/mem32, imm32"             (:reg/mem32)              (:imm32))                                      ;; MOV
;; (defiformat "!reg/mem64, imm32"             (:reg/mem64)              (:imm32))                                      ;; MOV
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; segment register                                                                                                    
;; ;;;;                                                                                                                     
;; (defiformat "!reg16/32/64/mem16, segreg"    (:reg16/32/64/mem16)      (:segreg))                                     ;; MOV
;; (defiformat "!segreg, reg/mem16"            (:segreg)                 (:reg/mem16))                                  ;; MOV

;; ;;;;                                                                                                                     
;; ;;;; MMX/XMM                                                                                                             
;; ;;;;                                                                                                                     
;; (defiformat "!mmx, reg/mem32"               (:mmx)                    (:reg/mem32))                                  ;; MOVD
;; (defiformat "!mmx, reg/mem64"               (:mmx)                    (:reg/mem64))                                  ;; MOVD
;; (defiformat "!reg/mem32, mmx"               (:reg/mem32)              (:mmx))                                        ;; MOVD
;; (defiformat "!reg/mem64, mmx"               (:reg/mem64)              (:mmx))                                        ;; MOVD
;; (defiformat "!xmm, reg/mem32"               (:xmm)                    (:reg/mem32))                                  ;; MOVD
;; (defiformat "!xmm, reg/mem64"               (:xmm)                    (:reg/mem64))                                  ;; MOVD
;; (defiformat "!reg/mem32, xmm"               (:reg/mem32)              (:xmm))                                        ;; MOVD
;; (defiformat "!reg/mem64, xmm"               (:reg/mem64)              (:xmm))                                        ;; MOVD
                                                                                                                         
;; (defiformat "!reg32, xmm"                   (:reg32)                  (:xmm))                                        ;; MOVMSKPS, MOVMSKPD

;; ;;;;
;; ;;;; system
;; ;;;;                                                                                                                         
;; (defiformat "$!cr, reg32"                   (:cr)                     (:reg32 :cpl :cs))                             ;; MOV
;; (defiformat "$!cr, reg64"                   (:cr)                     (:reg64 :cpl :cs))                             ;; MOV
;; (defiformat "!reg32, cr"                    (:reg32)                  (:cr :cpl :cs))                                ;; MOV
;; (defiformat "!reg64, cr"                    (:reg64)                  (:cr :cpl :cs))                                ;; MOV

;; (defiformat "$!CR8, reg32"                  (:cr8)                    (:reg32 :cpl :cs))                             ;; MOV
;; (defiformat "$!CR8, reg64"                  (:cr8)                    (:reg64 :cpl :cs))                             ;; MOV
;; (defiformat "!reg32, CR8"                   (:reg32)                  (:cr8 :cpl :cs))                               ;; MOV
;; (defiformat "!reg64, CR8"                   (:reg64)                  (:cr8 :cpl :cs))                               ;; MOV

;; (defiformat "$!dr, reg32"                   (:dr)                     (:reg32 :cpl :cs))                             ;; MOV
;; (defiformat "$!dr, reg64"                   (:dr)                     (:reg64 :cpl :cs))                             ;; MOV
;; (defiformat "!reg32, dr"                    (:reg32)                  (:dr :cpl :cs))                                ;; MOV
;; (defiformat "!reg64, dr"                    (:reg64)                  (:dr :cpl :cs))                                ;; MOV

;; ;;;;
;; ;;;; Stack
;; ;;;;
;; (defiformat "!reg/mem16, [SS:RSP]"          (:reg/mem16 :rsp)         (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!reg/mem32, [SS:RSP]"          (:reg/mem32 :rsp)         (:ss :rsp :mem32))                             ;; POP
;; (defiformat "!reg/mem64, [SS:RSP]"          (:reg/mem64 :rsp)         (:ss :rsp :mem64))                             ;; POP
;; (defiformat "!reg16, [SS:RSP]"              (:reg16 :rsp)             (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!reg32, [SS:RSP]"              (:reg32 :rsp)             (:ss :rsp :mem32))                             ;; POP
;; (defiformat "!reg64, [SS:RSP]"              (:reg64 :rsp)             (:ss :rsp :mem64))                             ;; POP
;; (defiformat "!DS, [SS:RSP]"                 (:ds :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!ES, [SS:RSP]"                 (:es :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!SS, [SS:RSP]"                 (:ss :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!FS, [SS:RSP]"                 (:fs :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (defiformat "!GS, [SS:RSP]"                 (:gs :rsp)                (:ss :rsp :mem16))                             ;; POP

;; (defiformat "![SS:RSP], reg/mem16"          (:mem16 :rsp)             (:ss :rsp :reg/mem16))                         ;; PUSH
;; (defiformat "![SS:RSP], reg/mem32"          (:mem32 :rsp)             (:ss :rsp :reg/mem32))                         ;; PUSH
;; (defiformat "![SS:RSP], reg/mem64"          (:mem64 :rsp)             (:ss :rsp :reg/mem64))                         ;; PUSH
;; (defiformat "![SS:RSP], reg16"              (:mem16 :rsp)             (:ss :rsp :reg16))                             ;; PUSH
;; (defiformat "![SS:RSP], reg32"              (:mem32 :rsp)             (:ss :rsp :reg32))                             ;; PUSH
;; (defiformat "![SS:RSP], reg64"              (:mem64 :rsp)             (:ss :rsp :reg64))                             ;; PUSH
;; (defiformat "![SS:RSP], imm8"               (:mem8  :rsp)             (:ss :rsp :imm8))                              ;; PUSH
;; (defiformat "![SS:RSP], imm16"              (:mem16 :rsp)             (:ss :rsp :imm16))                             ;; PUSH
;; (defiformat "![SS:RSP], imm32"              (:mem32 :rsp)             (:ss :rsp :imm32))                             ;; PUSH
;; (defiformat "![SS:RSP], imm64"              (:mem64 :rsp)             (:ss :rsp :imm64))                             ;; PUSH
;; (defiformat "![SS:RSP], CS"                 (:mem16 :rsp)             (:ss :rsp :cs))                                ;; PUSH
;; (defiformat "![SS:RSP], DS"                 (:mem16 :rsp)             (:ss :rsp :ds))                                ;; PUSH
;; (defiformat "![SS:RSP], ES"                 (:mem16 :rsp)             (:ss :rsp :es))                                ;; PUSH
;; (defiformat "![SS:RSP], SS"                 (:mem16 :rsp)             (:ss :rsp :ss))                                ;; PUSH
;; (defiformat "![SS:RSP], FS"                 (:mem16 :rsp)             (:ss :rsp :fs))                                ;; PUSH
;; (defiformat "![SS:RSP], GS"                 (:mem16 :rsp)             (:ss :rsp :gs))                                ;; PUSH

;; (defiformat "!DI, SI, BP, SP, BX, DX, CX, AX, [SS:SP]"          (:di :si :bp :sp :bx :dx :cx :ax)         (:ss :rsp :mem128)) ;; POPA
;; (defiformat "!EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX, [SS:ESP]" (:edi :esi :ebp :esp :ebx :edx :ecx :eax) (:ss :rsp :mem256)) ;; POPAD

;; (defiformat "![SS:SP], AX, CX, DX, BX, SP, BP, SI, DI"          (:ss :rsp :mem128)         (:di :si :bp :sp :bx :dx :cx :ax)) ;; PUSHA
;; (defiformat "![SS:ESP], EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI" (:ss :rsp :mem256) (:edi :esi :ebp :esp :ebx :edx :ecx :eax)) ;; PUSHAD

;; (defiformat "<>![SS:SP]"                    (:flags  :rsp)            (:flags  :cpl :cs :ss :rsp :mem16))            ;; POPF
;; (defiformat "<>![SS:ESP]"                   (:eflags :rsp)            (:eflags :cpl :cs :ss :rsp :mem32))            ;; POPFD
;; (defiformat "<>![SS:RSP]"                   (:rflags :rsp)            (:rflags :cpl :cs :ss :rsp :mem64))            ;; POPFQ

;; (defiformat ">![SS:SP]"                     (:mem16 :rsp)             (:flags  :ss :rsp))                            ;; PUSHF
;; (defiformat ">![SS:ESP]"                    (:mem32 :rsp)             (:eflags :ss :rsp))                            ;; PUSHFD
;; (defiformat ">![SS:RSP]"                    (:mem64 :rsp)             (:rflags :ss :rsp))                            ;; PUSHFQ

;; (defiformat "<>reg/mem8, 1"                 (:rflags :reg/mem8)       (:rflags :reg/mem8  1))                        ;; RCL, RCR
;; (defiformat "<>reg/mem16, 1"                (:rflags :reg/mem16)      (:rflags :reg/mem16 1))                        ;; RCL, RCR
;; (defiformat "<>reg/mem32, 1"                (:rflags :reg/mem32)      (:rflags :reg/mem32 1))                        ;; RCL, RCR
;; (defiformat "<>reg/mem64, 1"                (:rflags :reg/mem64)      (:rflags :reg/mem64 1))                        ;; RCL, RCR
;; (defiformat "<>reg/mem8, CL"                (:rflags :reg/mem8)       (:rflags :reg/mem8  :cl))                      ;; RCL, RCR
;; (defiformat "<>reg/mem16, CL"               (:rflags :reg/mem16)      (:rflags :reg/mem16 :cl))                      ;; RCL, RCR
;; (defiformat "<>reg/mem32, CL"               (:rflags :reg/mem32)      (:rflags :reg/mem32 :cl))                      ;; RCL, RCR
;; (defiformat "<>reg/mem64, CL"               (:rflags :reg/mem64)      (:rflags :reg/mem64 :cl))                      ;; RCL, RCR
;; (defiformat "<>reg/mem8, imm8"              (:rflags :reg/mem8)       (:rflags :reg/mem8  :imm8))                    ;; RCL, RCR
;; (defiformat "<>reg/mem16, imm8"             (:rflags :reg/mem16)      (:rflags :reg/mem16 :imm8))                    ;; RCL, RCR
;; (defiformat "<>reg/mem32, imm8"             (:rflags :reg/mem32)      (:rflags :reg/mem32 :imm8))                    ;; RCL, RCR
;; (defiformat "<>reg/mem64, imm8"             (:rflags :reg/mem64)      (:rflags :reg/mem64 :imm8))                    ;; RCL, RCR

;; (defiformat "<reg/mem8, 1"                  (:rflags :reg/mem8)       (:reg/mem8 1))                                 ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem16, 1"                 (:rflags :reg/mem16)      (:reg/mem16 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem32, 1"                 (:rflags :reg/mem32)      (:reg/mem32 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem64, 1"                 (:rflags :reg/mem64)      (:reg/mem64 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem8, CL"                 (:rflags :reg/mem8)       (:reg/mem8 :cl))                               ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem16, CL"                (:rflags :reg/mem16)      (:reg/mem16 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem32, CL"                (:rflags :reg/mem32)      (:reg/mem32 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem64, CL"                (:rflags :reg/mem64)      (:reg/mem64 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem8, imm8"               (:rflags :reg/mem8)       (:reg/mem8 :imm8))                             ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem16, imm8"              (:rflags :reg/mem16)      (:reg/mem16 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem32, imm8"              (:rflags :reg/mem32)      (:reg/mem32 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (defiformat "<reg/mem64, imm8"              (:rflags :reg/mem64)      (:reg/mem64 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR

;; (defiformat "<reg/mem16, reg16, CL"         (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :cl))                     ;; SHLD, SHRD
;; (defiformat "<reg/mem32, reg32, CL"         (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :cl))                     ;; SHLD, SHRD
;; (defiformat "<reg/mem64, reg64, CL"         (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :cl))                     ;; SHLD, SHRD
;; (defiformat "<reg/mem16, reg16, imm8"       (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :imm8))                   ;; SHLD, SHRD
;; (defiformat "<reg/mem32, reg32, imm8"       (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :imm8))                   ;; SHLD, SHRD
;; (defiformat "<reg/mem64, reg64, imm8"       (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :imm8))                   ;; SHLD, SHRD

;; (defiformat "2|reg/mem8,  reg8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XADD, XCHG
;; (defiformat "2|reg/mem16, reg16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XADD, XCHG
;; (defiformat "2|reg/mem32, reg32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XADD, XCHG
;; (defiformat "2|reg/mem64, reg64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XADD, XCHG

;; (defiformat "2|AX,  reg16"                  (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
;; (defiformat "2|EAX, reg32"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
;; (defiformat "2|RAX, reg64"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;; ;;;;
;; ;;;; XCHG's identicalities
;; ;;;;
;; (defiformat "2|reg8,  reg/mem8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XCHG
;; (defiformat "2|reg16, reg/mem16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XCHG
;; (defiformat "2|reg32, reg/mem32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XCHG
;; (defiformat "2|reg64, reg/mem64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XCHG
;; (defiformat "2|reg16, AX"                   (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
;; (defiformat "2|reg32, EAX"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
;; (defiformat "2|reg64, RAX"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;; ;;;;
;; ;;;; assorted system stuff
;; ;;;;
;; (defiformat "AL, seg:[RBX + AL]"            (:al)                     (:segreg :rbx :al))                            ;; XLAT, XLATB

;; (defiformat "<$reg/mem16, reg16"            (:segreg)                 (:segreg :reg16))                              ;; ARPL
;; (defiformat "$!GIF"                         (:gif)                    ())                                            ;; CLGI, STGI

;; (defiformat "$CR0"                          (:cr0)                    ())                                            ;; CLTS

;; (defiformat "<!$reg16, reg/mem16"           (:rflags :reg16)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
;; (defiformat "<!$reg32, reg/mem16"           (:rflags :reg32)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
;; (defiformat "<!$reg64, reg/mem16"           (:rflags :reg64)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL

;; (defiformat "|$mem48"                       ()                        (:mem48 :cpl :cs))                             ;; LGDT, LIDT
;; (defiformat "|$mem80"                       ()                        (:mem80 :cpl :cs))                             ;; LGDT, LIDT

;; (defiformat "!mem48"                        (:mem48)                  ())                                            ;; SGDT, SIDT
;; (defiformat "!mem80"                        (:mem80)                  ())                                            ;; SGDT, SIDT

;; (defiformat "!$sysreg16, reg/mem16"         (:sysreg16)               (:reg/mem16 :cpl :cs))                         ;; LIDT, LMSW, LTR

;; (defiformat "$segreg:[EAX], ECX, EDX"       ()                        (:segreg :eax :ecx :edx :cpl :cs))             ;; MONITOR
;; (defiformat "$EAX, ECX"                     ()                        (:eax :ecx :cpl :cs))                          ;; MWAIT

;; (defiformat "2!2|EDX:EAX, ECX, sysreg64"    (:eax :edx)               (:ecx :sysreg64 :cpl :cs))                     ;; RDMSR, RDPMC
;; (defiformat "2!2|EDX:EAX, sysreg64"         (:eax :edx)               (:sysreg64 :cpl :cs :cr4))                     ;; RDTSC
;; (defiformat "2!2|3!3|EDX:EAX:ECX, sysreg64, sysreg32" (:eax :edx :ecx)(:sysreg64 :sysreg32 :cpl :cs :cr4))           ;; RDTSCP

;; (defiformat "$!sysreg64, EDX:EAX, ECX"      (:sysreg64)               (:eax :edx :ecx :cpl :cs))                     ;; RDMSR, RDPMC

;; (defiformat "!reg16, sysreg16"              (:reg16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (defiformat "!reg32, sysreg16"              (:reg32)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (defiformat "!reg64, sysreg16"              (:reg64)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (defiformat "!mem16, sysreg16"              (:mem16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (defiformat "2|sysreg16, GS"                (:gs :sysreg16)           (:gs :sysreg16 :cpl :cs))                      ;; SWAPGS

;; (defiformat "$@<!CX"                        (:eflags :eip :cpl :cs :ss :cx)       (:star))                           ;; SYSCALL (short mode)
;; (defiformat "$@<!2|RCX, R11"                (:rflags :rip :cpl :cs :ss :rcx :r11) (:cstar))                          ;; SYSCALL (long mode)
;; (defiformat "$@<|CX"                        (:eflags :eip :cpl :cs :ss)           (:efer :cpl :cs :star :ecx))       ;; SYSRET (short mode)
;; (defiformat "$@<|RCX, R11"                  (:rflags :rip :cpl :cs :ss)           (:efer :cpl :cs :cstar :rcx :r11)) ;; SYSRET (long mode)

;; (defiformat "$@<SS:ESP"                     (:eflags :eip :cpl :cs :ss :esp)      ())                                ;; SYSENTER
;; (defiformat "$@<SS:ESP, CX, DX"             (:eflags :eip :cpl :cs :ss :esp)      (:cx :dx))                         ;; SYSEXIT

;; (defiformat "$@"                            (:rip)                                ())                                ;; UD2, VMMCALL

;; (defiformat "<$reg/mem16"                   (:rflags)                             (:reg/mem16 :cpl :cs))             ;; VERR, VERW

;; (defiformat "$<"                            (:rflags :cr0 :cr3 :cr4 :cr6 :cr7 :efer) (:cr0 :cr3 :cr4 :cr6 :cr7 :efer))                          ;; RSM
;; (defiformat "<|$[EAX]"                      (:rflags :cr0 :cs :ss :eax :edx :esp :ebx :ecx :edx :esi :edi :rgpr :efer :gif) (:eax :efer :cppl)) ;; SKINIT

;; (defiformat "$!2|FS, GS, CS, [RAX]"         (:fs :gs :tr :star :lstar :cstar :sfmask) (:rax :mem :cpl :cs :efer))                               ;; VMLOAD
;; (defiformat "$![RAX], CS, FS, GS"           (:mem)                                    (:rax :cpl :cs :efer :fs :gs :tr :star :lstar :cstar))    ;; VMSAVE
;; (defiformat "$<>@![RAX]"                    (:rflags :es :cs :ss :ds :efer :cr0 :cr4 :cr3 :cr2 :rip :rsp :rax :dr6 :dr7 :cpl :mem :gif) 
;;                                                            (:rflags :rip :rsp :rax :mem :cpl :cs :efer :sysreg64 :es :cs :ss :ds :cr0 :cr4 :cr3))              ;; VMRUN

;;;;
;;;; Total of 483 instruction formats
;;;;

;;;;
;;;; Not an instruction
;;;;
;; (defiformat "$<>@"                       (:gif :efer :cr0 :cr4 :cr3 :rflags :rip :rsp :rax :dr7 :cpl :es :cs :ss :ds)
;;                                              (:es :cs :ss :ds :efer :cr4 :cr3 :cr2 :cr0 :rflags :rip :rsp :rax :dr7 :dr6 :cpl))                  ;; #VMEXIT
