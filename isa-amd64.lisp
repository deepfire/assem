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

(define-microformat :suf-prefixes
  (:opersz/p (1 0))
  (:rep/p    (1 1))
  (:repn/p   (1 2)))

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

(define-format-argument/attribute-correspondence :overseg ()
  (:es .                :es)
  (:cs .                :cs)
  (:ss .                :ss)
  (:ds .                :ds)
  (:fs .                :fs)
  (:gs .                :gs))

(define-format-argument/attribute-correspondence :regxs ()
  ((:opersz/p) .        :reg16)
  (() .                 :reg32))

(define-format-argument/attribute-correspondence :regxl ()
  ((:opersz/p) .        :reg32)
  (() .                 :reg64))

(define-format-argument/attribute-correspondence :regx ()
  ((:opersz/p) .        :reg16)
  (() .                 :reg32)
  ((:rex-w :opersz/p) . :reg64)
  ((:rex-w) .           :reg64))

(define-format-argument/attribute-correspondence :xaxs ()
  ((:opersz/p) .        :ax)
  (() .                 :eax))

(define-format-argument/attribute-correspondence :xax-1 ()
  ((:opersz/p) .        :al)
  (() .                 :ax)
  ((:rex-w :opersz/p) . :eax)
  ((:rex-w) .           :eax))

(define-format-argument/attribute-correspondence :xax ()
  ((:opersz/p) .        :ax)
  (() .                 :eax)
  ((:rex-w :opersz/p) . :rax)
  ((:rex-w) .           :rax))

(define-format-argument/attribute-correspondence :adxcx32 ()
  ((:opersz/p) .        :cx)
  (() .                 :ecx))

(define-format-argument/attribute-correspondence :adxcx64 ()
  ((:opersz/p) .        :ecx)
  (() .                 :rcx))

(define-format-argument/attribute-correspondence :xdx ()
  ((:opersz/p) .        :dx)
  (() .                 :ed)
  ((:rex-w :opersz/p) . :rdx)
  ((:rex-w) .           :rdx))

(define-format-argument/attribute-correspondence :xaxl ()
  ((:opersz/p) .        :eax)
  (() .                 :eax)
  ((:rex-w :opersz/p) . :rax)
  ((:rex-w) .           :rax))

(define-format-argument/attribute-correspondence :xbxl ()
  ((:opersz/p) .        :ebx)
  (() .                 :ebx)
  ((:rex-w :opersz/p) . :rbx)
  ((:rex-w) .           :rbx))

(define-format-argument/attribute-correspondence :xcxl ()
  ((:opersz/p) .        :ecx)
  (() .                 :ecx)
  ((:rex-w :opersz/p) . :rcx)
  ((:rex-w) .           :rcx))

(define-format-argument/attribute-correspondence :xdxl ()
  ((:opersz/p) .        :edx)
  (() .                 :edx)
  ((:rex-w :opersz/p) . :rdx)
  ((:rex-w) .           :rdx))

(define-format-argument/attribute-correspondence :basex ()
  ((:addrsz/p) .        :base32)
  (() .                 :base64))

(define-format-argument/attribute-correspondence :basex+ ()
  ((:addrsz/p) .        :base32+)
  (() .                 :base64+))

(define-format-argument/attribute-correspondence :basex+2 ()
  ((:addrsz/p) .        :base32+2)
  (() .                 :base64+2))

(define-format-argument/attribute-correspondence :segdds ()
  ((:cs) .              :cs)
  (() .                 :ds)
  ((:ds) .              :ds)
  ((:es) .              :es)
  ((:fs) .              :fs)
  ((:gs) .              :gs)
  ((:ss) .              :ss))

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
;;                   (post-seek 08))
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
;;                   (post-seek 08)
;;                   (recurse)))
;;     (:xop        ((active-set :xopcode
;;                                ,@(unless sixty-four-p
;;                                          `(:xopcode-compatmode))
;;                                :xopcode-unprefixed :xopcode-unprefixed-modrm
;;                                ;; ...and the modrm-extended points of bastardisation
;;                                (#x0f00 #x0f01 #x0fba #x0fc7 #x0fb9 #x0f71 #x0f72 #x0f73 #x0fae #x0f18 #x0f0d))
;;                   (insert :xop-tree)
;;                   (dispatch ((08 00) :window))
;;                   (post-seek 08)))
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
               (microformat :uf-rex (04 00))
               (post-seek 08)
               (insert-subtree :nrex)))
        (:nrex ((active-set :opersz/p :rep/p :repn/p :addrsz :overseg :lock
                             :opcode :opcode-modrmless-regspec
                             ,@(if sixty-four-p
                                   '(:opcode-longmode)
                                   '(:opcode-compatmode :opcode-modrmless-regspec-compatmode))
                             ;; modrm:reg-"enhanced" dispatch
                             (#x80 #x81 ,@(unless sixty-four-p '(#x82)) #x83 #x8f #xc0 #xc1 #xd0 #xd1 #xd2 #xd3 #xf6 #xf7 #xfe #xff #xc6 #xc7))
                (window 08 00)
                (dispatch :window)
                (post-seek 08))
               (:addrsz   ((ban-sets :addrsz)
                           (insert-subtree nil)))
               (:overseg  ((ban-sets :overseg)
                           (insert-subtree nil)))
               (:lock     ((ban-sets :lock)
                           (insert-subtree nil)))
               (:opersz/p ((ban-sets :xopcode-unprefixed :xopcode-rep :xopcode-repn :opersz/p)
                           (allow-sets-at-subtree :xop :xopcode-opersz)
                           (insert-subtree nil)))
               (:rep/p    ((ban-sets :xopcode-unprefixed :xopcode-opersz :rep/p :repn/p)
                           (allow-sets-at-subtree :xop :xopcode-rep)
                           (insert-subtree nil)))
               (:repn/p   ((ban-sets :xopcode-unprefixed :xopcode-opersz :rep/p :repn/p)
                           (allow-sets-at-subtree :xop :xopcode-repn)
                           (insert-subtree nil)))
               (:opcode                               ((mnemonic t)
                                                       (dispatch :mnemonic :window)))
               (:opcode-modrmless-regspec             ((active-set :opcode-modrmless-regspec-internal)
                                                       (mnemonic t)
                                                       (argument 0 (:b (03 00)))
                                                       (dispatch :mnemonic :window)))
               (:opcode-modrmless-regspec-compatmode  ((active-set :opcode-modrmless-regspec-compatmode-internal)
                                                       (mnemonic t)
                                                       (argument 0 (:b (03 00)))
                                                       (dispatch :mnemonic :window)))
               (:opcode-longmode                      ((mnemonic t)
                                                       (dispatch :mnemonic :window)))
               (:opcode-compatmode                    ((mnemonic t)
                                                       (dispatch :mnemonic :window)))
               (#x80 ((active-set :grp1-80)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp1-80 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#x81 ((active-set :grp1-81)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp1-81 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               ,@(unless sixty-four-p
                         `((#x82 ((active-set :grp1-82-compatmode)
                                  (microformat :uf-modrm (08 00))
                                  (dispatch :window :reg))
                                 (:grp1-82-compatmode ((mnemonic t)
                                                       (dispatch :mnemonic :window :reg))))))
               (#x83 ((active-set :grp1-83)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp1-83 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#x8f ((active-set :grp1-8f)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp1-8f ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xc0 ((active-set :grp2-c0)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-c0 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xc1 ((active-set :grp2-c1)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-c1 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xd0 ((active-set :grp2-d0)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-d0 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xd1 ((active-set :grp2-d1)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-d1 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xd2 ((active-set :grp2-d2)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-d2 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xd3 ((active-set :grp2-d3)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp2-d3 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xf6 ((active-set :grp3-f6)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp3-f6 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xf7 ((active-set :grp3-f7)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp3-f7 ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xfe ((active-set :grp4-fe)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp4-fe ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xff ((active-set :grp5-ff)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp5-ff ((mnemonic t)
                                (dispatch :mnemonic :window :reg))))
               (#xc6 ((active-set :grp11-c6)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp11-c6 ((mnemonic t)
                                 (dispatch :mnemonic :window :reg))))
               (#xc7 ((active-set :grp11-c7)
                      (microformat :uf-modrm (08 00))
                      (dispatch :window :reg))
                     (:grp11-c7 ((mnemonic t)
                                 (dispatch :mnemonic :window :reg))))
               (:xop ((active-set :xopcode
                                   ,@(unless sixty-four-p
                                             `(:xopcode-compatmode))
                                   :xopcode-modrmless-regspec :xopcode-unprefixed
                                   ;; modrm:reg-"enhanced" dispatch
                                   (#x0f00 #x0f01 #x0fba #x0fc7 #x0fb9 #x0f71 #x0f72 #x0f73 #x0fae #x0f18 #x0f78 #x0f0d))
                      (dispatch (:window (08 08)))
                      (post-seek 08))
                     (:xopcode                    ((mnemonic t)
                                                   (dispatch :mnemonic ((08 -08) :window))))
                     (:xopcode-modrmless-regspec  ((active-set :xopcode-modrmless-regspec-internal)
                                                   (mnemonic t)
                                                   (argument 0 (:b (03 00)))
                                                   (dispatch :mnemonic :window)))
                     (:xopcode-unprefixed         ((mnemonic t)
                                                   (dispatch :mnemonic (:suf-prefixes :window))))
                     (:xopcode-opersz             ((mnemonic t)
                                                   (dispatch :mnemonic (:suf-prefixes :window))))
                     (:xopcode-rep                ((mnemonic t)
                                                   (dispatch :mnemonic (:suf-prefixes :window))))
                     (:xopcode-repn               ((mnemonic t)
                                                   (dispatch :mnemonic (:suf-prefixes :window))))
                     (#x0f00 ((active-set :grp6-0f-00)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp6-0f-00 ((mnemonic t)
                                           (dispatch :mnemonic :window :reg))))
                     (#x0f01 ((active-set :grp7-0f-01 ((#x0f01 1) (#x0f01 3) (#x0f01 7)))
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp7-0f-01 ((mnemonic t) ; modulo 1 4 7
                                           (dispatch :mnemonic :window :reg)))
                             ((#x0f01 1) ((active-set :grp7-0f-01-1-0 (#x0f01 1 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-1-0   ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod)))
                              ((#x0f01 1 3)      ((active-set :grp7-0f-01-1-3)
                                                  (dispatch :window :reg :mod :r/m))
                               (:grp7-0f-01-1-3  ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod :r/m)))))
                             ((#x0f01 3) ((active-set :grp7-0f-01-3-0 (#x0f01 3 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-3-0   ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod)))
                              ((#x0f01 3 3)      ((active-set :grp7-0f-01-3-3)
                                                  (dispatch :window :reg :mod :r/m))
                               (:grp7-0f-01-3-3  ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod :r/m)))))
                             ((#x0f01 7) ((active-set :grp7-0f-01-7-0 (#x0f01 7 3))
                                          (dispatch :window :reg :mod))
                              (:grp7-0f-01-7-0   ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod)))
                              ((#x0f01 7 3)      ((active-set :grp7-0f-01-7-3)
                                                  (dispatch :window :reg :mod :r/m))
                               (:grp7-0f-01-7-3  ((mnemonic t)
                                                  (dispatch :mnemonic :window :reg :mod :r/m))))))
                     (#x0fba ((active-set :grp8-0f-ba)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp8-0f-ba ((mnemonic t)
                                           (dispatch :mnemonic :window :reg))))
                     (#x0fc7 ((active-set :grp9-0f-c7)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp9-0f-c7 ((mnemonic t)
                                           (dispatch :mnemonic :window :reg))))
                     (#x0fb9 ((active-set :grp10-0f-b9)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp10-0f-b9 ((mnemonic t)
                                            (dispatch :mnemonic :window :reg))))
                     (#x0f71 ((active-set (#x00f71 #x10f71))
                              (microformat :uf-modrm (08 00))
                              (dispatch (:suf-prefixes :window)))
                             (#x00f71 ((active-set :grp12-0f-71)
                                       (dispatch :window :reg))
                                      (:grp12-0f-71 ((mnemonic t)
                                                     (dispatch :mnemonic (:suf-prefixes :window) :reg))))
                             (#x10f71 ((active-set :grp12-0f-71-op)
                                       (dispatch :window :reg))
                                      (:grp12-0f-71-op ((mnemonic t)
                                                        (dispatch :mnemonic (:suf-prefixes :window) :reg)))))
                     (#x0f72 ((active-set (#x00f72 #x10f72))
                              (microformat :uf-modrm (08 00))
                              (dispatch (:suf-prefixes :window)))
                             (#x00f72 ((active-set :grp13-0f-72)
                                       (dispatch :window :reg))
                                      (:grp13-0f-72 ((mnemonic t)
                                                     (dispatch :mnemonic (:suf-prefixes :window) :reg))))
                             (#x10f72 ((active-set :grp13-0f-72-op)
                                       (dispatch :window :reg))
                                      (:grp13-0f-72-op ((mnemonic t)
                                                        (dispatch :mnemonic (:suf-prefixes :window) :reg)))))
                     (#x0f73 ((active-set (#x00f73 #x10f73))
                              (microformat :uf-modrm (08 00))
                              (dispatch (:suf-prefixes :window)))
                             (#x00f73 ((active-set :grp14-0f-73)
                                       (dispatch :window :reg))
                                      (:grp14-0f-73 ((mnemonic t)
                                                     (dispatch :mnemonic (:suf-prefixes :window) :reg))))
                             (#x10f73 ((active-set :grp14-0f-73-op)
                                       (dispatch :window :reg))
                                      (:grp14-0f-73-op ((mnemonic t)
                                                        (dispatch :mnemonic (:suf-prefixes :window) :reg)))))
                     (#x0fae ((active-set :grp15-0f-ae ((#x0fae 5) (#x0fae 6) (#x0fae 7)))
                              (microformat :uf-modrm (08 00))
                              (dispatch (:suf-prefixes :window) :reg))
                             (:grp15-0f-ae ((mnemonic t)
                                            (dispatch (:suf-prefixes :mnemonic) :window :reg)))
                             ((#x0fae 5) ((active-set :grp15-0f-ae-5)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-5 ((mnemonic t) ; lfence
                                               (dispatch (:suf-prefixes :mnemonic) :window :reg))))
                             ((#x0fae 6) ((active-set :grp15-0f-ae-6)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-6 ((mnemonic t) ; mfence
                                               (dispatch (:suf-prefixes  :mnemonic) :window :reg))))
                             ((#x0fae 7) ((active-set :grp15-0f-ae-7)
                                          (dispatch :window :reg :mod))
                              (:grp15-0f-ae-7 ((mnemonic t) ; sfence, clflush
                                               (dispatch (:suf-prefixes :mnemonic) :window :reg)))))
                     (#x0f18 ((active-set :grp16-0f-18)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grp16-0f-18 ((mnemonic t)
                                            (dispatch :mnemonic :window :reg))))
                     (#x0f78 ((active-set (#x10f78))
                              (microformat :uf-modrm (08 00))
                              (dispatch (:suf-prefixes :window)))
                             ((#x10f78) ((active-set :grp17-0f-78-op)
                                         (dispatch :window :reg))
                              (:grp17-0f-78-op ((mnemonic t)
                                                (dispatch :mnemonic (:suf-prefixes :window) :reg)))))
                     (#x0f0d ((active-set :grpp-0f-0d)
                              (microformat :uf-modrm (08 00))
                              (dispatch :window :reg))
                             (:grpp-0f-0d ((mnemonic t)
                                           (dispatch :mnemonic :window :reg))))))))

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
  (:loopne/nz . #xe0) (:loope/z . #xe1) (:loop .     #xe2) (:je/rcxz .   #xe3) (:in .        #xe4) (:in .        #xe5) (:out .     #xe6) (:out .       #xe7)
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
  (:wrmsr .     #x0f30) (:rdtsc .     #x0f31) (:rdmsr .     #x0f32) (:rdpmc .    #x0f33)  #|  32bit mode  |#   #|  32bit mode  |#   #|   invalid    |#   #|   invalid    |#
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

;; vvol. 5,6 material, except: xadd, movmskps, movd, movnti, btc, bsf, bsr and movsx
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

;; vvol. 5,6 material, except: xadd, movmskpd, movd
(define-attribute-set :xopcode-opersz
  (:movupd .    #x0f10) (:movupd .    #x0f11) (:movlpd .    #x0f12) (:movlpd .    #x0f13) (:unpcklpd .   #x0f14) (:unpckhpd .   #x0f15) (:movhpd .   #x0f16) (:movhpd .   #x0f17)
  (:movmskpd .  #x0f50) (:sqrtpd .    #x0f51)  #|   invalid     |#   #|   invalid     |#  (:andpd .      #x0f54) (:andnpd .     #x0f55) (:orpd .     #x0f56) (:xorpd .    #x0f57)
  (:punpcklbw . #x0f60) (:punpcklwd . #x0f61) (:punpckldq . #x0f62) (:packsswb .  #x0f63) (:pcmpgtb .    #x0f64) (:pcmpgtw .    #x0f65) (:pcmpgtd .  #x0f66) (:packuswb . #x0f67)
  (:pshufd .    #x0f70)  #|   grp12       |#   #|   grp13       |#   #|   grp14       |#  (:pcmpeqb .    #x0f74) (:pcmpeqw .    #x0f75) (:pcmpeqd .  #x0f76)  #|   invalid    |#
  (:xadd .      #x0fc0) (:xadd .      #x0fc1) (:cmppd .     #x0fc2)  #|   invalid     |#  (:pinsrw .     #x0fc4) (:pextsrw .    #x0fc5) (:shufpd .   #x0fc6)  #|    grp9      |#
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

;; vvol. 5,6 material, except: xadd, popcnt and lzcnt
(define-attribute-set :xopcode-rep
  (:movss .   #x0f10) (:movss .   #x0f11) (:movsldup . #x0f12)  #|   invalid     |#   #|   invalid     |#   #|  invalid     |#  (:movshdup . #x0f16)  #|   invalid  |#
   #|   invalid   |#  (:sqrtss .  #x0f51) (:rsqrtss .  #x0f52) (:rcpss .     #x0f53)  #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
  (:pshufhw . #x0f70) #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#
  (:xadd .    #x0fc0) (:xadd .    #x0fc1) (:cmpss .    #x0fc2)  #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|    grp9    |#
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
   #|   invalid   |#  #|    invalid   |#   #|   invalid    |#   #|   invalid     |#   #|   invalid     |#   #|  invalid     |#   #|   invalid    |#   #|   invalid  |#)

;; vvol. 5,6 material, except: xadd
(define-attribute-set :xopcode-repn
  (:movsd .     #x0f10) (:movsd .     #x0f11) (:movddup .   #x0f12)  #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#  (:sqrtsd .    #x0f51)  #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:pshuflw .   #x0f70)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:xadd .      #x0fc0) (:xadd .      #x0fc1) (:cmpsd .     #x0fc2)  #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|    grp9      |#
  (:addsubps .  #x0fd0)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#  (:movdq2q .  #x0fd6)  #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#  (:cvtpd2dq . #x0fe6)  #|   invalid    |#
  (:lddqu .     #x0ff0)  #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
   #|    invalid    |#   #|    invalid    |#  (:cvtsi2sd .  #x0f2a) (:movntsd .   #x0f2b) (:cvttsd2si .  #x0f2c) (:cvtsd2si .   #x0f2d)  #|   invalid    |#   #|   invalid    |#
  (:addsd .     #x0f58) (:mulsd .     #x0f59) (:cvtsd2ss .  #x0f5a)  #|    invalid    |#  (:subsd .      #x0f5c) (:minsd .      #x0f5d) (:divsd .    #x0f5e) (:maxsd .    #x0f5f)
   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid    |#   #|    invalid     |#   #|    invalid     |#   #|   invalid    |#   #|   invalid    |#
  (:insertq .   #x0f78) (:insertq .   #x0f79)  #|    invalid    |#   #|    invalid    |#  (:haddps .     #x0f7c) (:hsubps .     #x0f7d)  #|   invalid    |#   #|   invalid    |#
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
  (:prefetchnta . (#x0f18 0)) (:prefetch0 .  (#x0f18 1)) (:prefetch1 . (#x0f18 2)) (:prefetch2 . (#x0f18 3))
  (:nop .         (#x0f18 4)) (:nop .        (#x0f18 5)) (:nop .       (#x0f18 6)) (:nop .       (#x0f18 7)))
(define-attribute-set :grp17-0f-78-op
  (:extrq .       (#x0f78 0))  #|     invalid        |#   #|     invalid       |#   #|      invalid      |#
   #|   invalid           |#   #|     invalid        |#   #|     invalid       |#   #|      invalid      |#)
(define-attribute-set :grpp-0f-0d
  (:prefetch .    (#x0f0d 0)) (:prefetchw .  (#x0f0d 1)) (:prefetch .  (#x0f0d 2)) (:prefetchw . (#x0f0d 3))
  (:prefetch .    (#x0f0d 4)) (:prefetch .   (#x0f0d 5)) (:prefetch .  (#x0f0d 6)) (:prefetch .  (#x0f0d 7)))


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
         (pre-seek 08) ; last seek was before parsing the modrm microformat, let's prepare for displacement/SIB
         (dispatch :mod))
        (#b00 ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
               (dispatch (:b :r/m)))
              (#x4 #xc ((active-set (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
                        (microformat :uf-sib 08 00)
                        (pre-seek 08)
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
  `())

;;;;
;;;; Odd-ball
;;;;
(defiformat "|regXX, memXX"          (r  (:regx) r  ((x (tree :r/monly))))                     (:bound #x62))
(defiformat "AL, seg:[RBX + AL]"     (rw :al     r  (:segdds) r  :rbx)                         (:xlat  #xd7)) ;; how do we designate optionals?
;;; end-of-odd-ball

;;;;
;;;; Arithmetics
;;;;
(defiformat "<>AL"                   (rw :rflags rw :al)                                       (:aaa #x37   :aas #x3f   :daa #x27   :das #x2f))
(defiformat "<AL, AH, imm8"          ( w :rflags rw :al   r  :ah  r (:imm8))                   (:aad #xd5))
(defiformat "<2|2!AL, AH, imm8"      ( w :rflags rw :al    w :ah  r (:imm8))                   (:aam #xd4))
                                                                                    
(defiformat "<AL,  imm8"             ( w :rflags rw (:al)               r  (:imm8))            (:add #x04   :adc #x14   :sbb #x1c   :sub #x2c))
(defiformat "<XAX, immXX"            ( w :rflags rw (:xax)              r  (:immx))            (:add #x05   :adc #x15   :sbb #x1d   :sub #x2d))
(defiformat "<~S,  imm8"             ( w :rflags rw (8 (tree :r/m))     r  (:imm8))            (:add #x80 0 :adc #x80 2 :sbb #x80 3 :sub #x80 5))
(defiformat "<~S, immXX"             ( w :rflags rw (x (tree :r/m))     r  (:immx))            (:add #x81 0 :adc #x81 2 :sbb #x81 3 :sub #x81 5))
(defiformat "<~S, imm8"              ( w :rflags rw (x (tree :r/m))     r  (:imm8))            (:add #x83 0 :adc #x83 2 :sbb #x83 3 :sub #x83 5 :bts #xba 5 :btr #xba 6 :btc #x0ba 7))
(defiformat "<~S, reg8"              ( w :rflags rw (8 (tree :r/m))     r  (:reg8))            (:add #x00   :adc #x10   :sbb #x18   :sub #x28  ))
(defiformat "<~S, regXX"             ( w :rflags rw (x (tree :r/m))     r  (:regx))            (:add #x01   :adc #x11   :sbb #x19   :sub #x29   :bts #xab   :btr #xb3   :btc #x0bb  ))
(defiformat "<reg8,  ~S"             ( w :rflags rw (:reg8)             r  (8 (tree :r/m)))    (:add #x02   :adc #x12   :sbb #x1a   :sub #x2a  ))
(defiformat "<reg8,  ~S"             ( w :rflags rw (:reg8)             r  (x (tree :r/m)))    (:add #x03   :adc #x13   :sbb #x1b   :sub #x2b  ))
                                                                                                              
(defiformat "AL,  imm8"              (           rw (:al)               r  (:imm8))            (:or #x0c    :and #x24   :xor #x34))
(defiformat "XAX, immXX"             (           rw (:xax)              r  (:immx))            (:or #x0d    :and #x25   :xor #x35))
(defiformat "~S,  imm8"              (           rw (8 (tree :r/m))     r  (:imm8))            (:or #x80 1  :and #x80 4 :xor #x80 6))
(defiformat "~S, immXX"              (           rw (x (tree :r/m))     r  (:immx))            (:or #x81 1  :and #x81 4 :xor #x81 6))
(defiformat "~S, imm8"               (           rw (x (tree :r/m))     r  (:imm8))            (:or #x83 1  :and #x83 4 :xor #x83 6))
(defiformat "~S, reg8"               (           rw (8 (tree :r/m))     r  (:reg8))            (:or #x08    :and #x20   :xor #x30))
(defiformat "~S, regXX"              (           rw (x (tree :r/m))     r  (:regx))            (:or #x09    :and #x21   :xor #x31))
(defiformat "reg8, ~S"               (           rw (:reg8)             r  (8 (tree :r/m)))    (:or #x0a    :and #x22   :xor #x32))
(defiformat "regXX, ~S"              (           rw (:regx)             r  (x (tree :r/m)))    (:or #x0b    :and #x23   :xor #x33))

(defiformat "regXXl"                 (rw (:regxl))                                             (:bswap #x0fc8 :bswap #x0fc9 :bswap #x0fca :bswap #x0fcb
                                                                                                :bswap #x0fcc :bswap #x0fcd :bswap #x0fce :bswap #x0fcf))

(defiformat "<>~S, 1"                (rw :rflags rw (8 (tree :r/m)) r  (1))                    (:rcl #xd0 2 :rcr #xd0 3))
(defiformat "<>~S, 1"                (rw :rflags rw (x (tree :r/m)) r  (1))                    (:rcl #xd1 2 :rcr #xd1 3))
(defiformat "<>~S, CL"               (rw :rflags rw (8 (tree :r/m)) r  (:cl))                  (:rcl #xd2 2 :rcr #xd2 3))
(defiformat "<>~S, CL"               (rw :rflags rw (x (tree :r/m)) r  (:cl))                  (:rcl #xd3 2 :rcr #xd3 3))
(defiformat "<>~S, imm8"             (rw :rflags rw (8 (tree :r/m)) r  (:imm8))                (:rcl #xc0 2 :rcr #xc0 3))
(defiformat "<>~S, imm8"             (rw :rflags rw (x (tree :r/m)) r  (:imm8))                (:rcl #xc1 2 :rcr #xc1 3))

(defiformat "<~S, 1"                 (r  :rflags rw (8 (tree :r/m)) r  (1))                    (:rol #xd0 0 :ror #xd0 1 :shl #xd0 4 :sal #xd0 4 :shr #xd0 5 :sar #xd0 7))
(defiformat "<~S, 1"                 (r  :rflags rw (x (tree :r/m)) r  (1))                    (:rol #xd1 0 :ror #xd1 1 :shl #xd1 4 :sal #xd1 4 :shr #xd1 5 :sar #xd1 7))
(defiformat "<~S, CL"                (r  :rflags rw (8 (tree :r/m)) r  (:cl))                  (:rol #xd2 0 :ror #xd2 1 :shl #xd2 4 :sal #xd2 4 :shr #xd2 5 :sar #xd2 7))
(defiformat "<~S, CL"                (r  :rflags rw (x (tree :r/m)) r  (:cl))                  (:rol #xd3 0 :ror #xd3 1 :shl #xd3 4 :sal #xd3 4 :shr #xd3 5 :sar #xd3 7))
(defiformat "<~S, imm8"              (r  :rflags rw (8 (tree :r/m)) r  (:imm8))                (:rol #xc0 0 :ror #xc0 1 :shl #xc0 4 :sal #xc0 4 :shr #xc0 5 :sar #xc0 7))
(defiformat "<~S, imm8"              (r  :rflags rw (x (tree :r/m)) r  (:imm8))                (:rol #xc1 0 :ror #xc1 1 :shl #xc1 4 :sal #xc1 4 :shr #xc1 5 :sar #xc1 7))

(defiformat "<~S, regXX, imm8"       (r  :rflags rw (x (tree :r/m)) rw (:regx) r  (:imm8))     (:shld #x0fa4 :shrd #x0fac))
(defiformat "<~S, regXX, CL"         (r  :rflags rw (x (tree :r/m)) rw (:regx) r  (:cl))       (:shld #x0fa5 :shrd #x0fad))

(defiformat "~S"                     (rw (8 (tree :r/m)))                                      (:not #xf6 2))
(defiformat "~S"                     (rw (x (tree :r/m)))                                      (:not #xf7 2))

(defiformat "<~S"                    ( w :rflags rw (8 (tree :r/m)))                           (:neg #xf6 3 :dec #xfe 1 :inc #xfe 0))
(defiformat "<~S"                    ( w :rflags rw (x (tree :r/m)))                           (:neg #xf7 3 :dec #xff 1 :inc #xff 0))

(defiformat "<!AX, AL, ~S"           ( w :rflags  w :ax     r  :al  r  (8 (tree :r/m)))        (:mul #xf6 4 :imul #xf6 5))
(defiformat "<!xDX, xAX, xAX, ~S"    ( w :rflags  w :xdx    rw :xax r  (x (tree :r/m)))        (:mul #xf7 4 :imul #xf7 5))
(defiformat "<AL, AH, ~S"            ( w :rflags rw :ax             r  (8 (tree :r/m)))        (:div #xf6 6 :idiv #xf6 7))
(defiformat "<xDX, xAX, ~S"          ( w :rflags rw :xdx    rw :xax r  (x (tree :r/m)))        (:div #xf7 6 :idiv #xf7 7))

(defiformat "<!regXX, ~S, imm8"      ( w :rflags  w (:regx) r  (x (tree :r/m)) r  (:imm8))     (:imul #x6b))
(defiformat "<!regXX, ~S, immx"      ( w :rflags  w (:regx) r  (x (tree :r/m)) r  (:immx))     (:imul #x69))

                                        ; XXX: LZ/POPCNT/others: the prefix flagging scheme allows decoding, but what about encoding?
(defiformat "<!regXX, ~S"            ( w :rflags  w (:regx) r  (x (tree :r/m)))                (:imul #x0faf :lzcnt #x20fbd :popcnt #x20fb8 :bsf #x00fbc :bsr #x00fbd))

(defiformat "<regXXs"                ( w :rflags rw (:regxs))                                  (:inc #x40 :inc #x41 :inc #x42 :inc #x43 :inc #x44 :inc #x45 :inc #x46 :inc #x47
                                                                                                :dec #x48 :dec #x49 :dec #x4a :dec #x4b :dec #x4c :dec #x4d :dec #x4e :dec #x4f))

(defiformat "2|~S,  reg8"            (rw (8 (tree :r/m))    rw (:reg8))                        (:xchg #x86 :xadd #x00fc0 :xadd #x10fc0 :xadd #x20fc0 :xadd #x40fc0))
(defiformat "2|~S, regXX"            (rw (x (tree :r/m))    rw (:regx))                        (:xchg #x87 :xadd #x00fc1 :xadd #x10fc1 :xadd #x20fc1 :xadd #x40fc1))
(defiformat "2|xAX,  regXX"          (rw (:xax)             rw (:regx))                        (:xchg #x90 :xchg #x91 :xchg #x92 :xchg #x93 :xchg #x94 :xchg #x95 :xchg #x96 :xchg #x97))
(defiformat "2|reg8,  ~S"            (rw (:reg8)            rw (8 (tree :r/m)))                (:xchg #x86))
(defiformat "2|regXX, ~S"            (rw (:regx)            rw (x (tree :r/m)))                (:xchg #x87))
(defiformat "2|regXX, xAX"           (rw (:xax)             rw (:regx))                        (:xchg #x90 :xchg #x91 :xchg #x92 :xchg #x93 :xchg #x94 :xchg #x95 :xchg #x96 :xchg #x97))

(defiformat "<AL, ~S, reg8"          ( w :rflags rw (:al)   rw (8 (tree :r/m)) r  (:reg8))     (:cmpxchg #x0fb0))
(defiformat "<xAX, ~S, regXX"        ( w :rflags rw (:xax)  rw (x (tree :r/m)) r  (:regx))     (:cmpxchg #x0fb1))

(defiformat "<xD:xA, r/m64/128, xC:xB" ( w :rflags rw :xdxl rw :xaxl rw :reg/mem64  r :xcxl r :xbxl) (:cmpxchg8/16b #x0fc7 1))

(defiformat "!xAX, xAX-1"            ( w :xax    r  :xax-1)                                    (:cbw/d/qe #x98))
(defiformat "2|xAX, xDX"             ( w :xdx    rw :xax)                                      (:cwd/q/o  #x99))
;;; end-of-arith

;;;;
;;;; Flag manipulations
;;;;
(defiformat ">regXX, ~S"             (rw (:regx) r  (x (tree :r/m))   r  :rflags)              (:cmovo #x40 0 :cmovno #x41 0 :cmovc  #x42 0 :cmovnc #x43 0
                                                                                                :cmovz #x44 0 :cmovnz #x45 0 :cmovna #x46 0 :cmova  #x47 0
                                                                                                :cmovs #x48 0 :cmovns #x49 0 :cmovp  #x4a 0 :cmovnp #x4b 0
                                                                                                :cmovl #x4c 0 :cmovnl #x4d 0 :cmovng #x4e 0 :cmovg  #x4f 0))

(defiformat ">!~S"                              (rw (x (tree :r/m))   r  :rflags)              (:seto  #x90 0 :setno  #x91 0 :setc   #x92 0 :setnc  #x93 0
                                                                                                :setz  #x94 0 :setnz  #x95 0 :setna  #x96 0 :seta   #x97 0
                                                                                                :sets  #x98 0 :setns  #x99 0 :setp   #x9a 0 :setnp  #x9b 0
                                                                                                :setl  #x9c 0 :setnl  #x9d 0 :setng  #x9e 0 :setg   #x9f 0))

(defiformat "<|AL, imm8"             ( w :rflags r  (:al)           r  (:imm8))                (:cmp #x3c   :test #xa8))
(defiformat "<|RAX, imm32"           ( w :rflags r  (:xax)          r  (:immx))                (:cmp #x3d   :test #xa9))
(defiformat "<|reg/mem8, imm8"       ( w :rflags r  (8 (tree :r/m)) r  (:imm8))                (:cmp #x80 7 :test #xf6 0   :test #xf6 1)) ;; duplicate?
(defiformat "<|reg/memXX, immXX"     ( w :rflags r  (x (tree :r/m)) r  (:immx))                (:cmp #x81 7 :test #xf7 0   :test #xf6 1)) ;; ...manual is unclear...
(defiformat "<|reg/memXX, imm8"      ( w :rflags r  (x (tree :r/m)) r  (:imm8))                (:cmp #x83 7 :bt   #x0fba 4))
(defiformat "<|reg/mem8, reg8"       ( w :rflags r  (8 (tree :r/m)) r  (:reg8))                (:cmp #x38   :test #x84))
(defiformat "<|reg/memXX, regXX"     ( w :rflags r  (x (tree :r/m)) r  (:regx))                (:cmp #x39   :test #x85     :bt #x0fa3))
(defiformat "<|reg8, reg/mem8"       ( w :rflags r  (:reg8)         r  (8 (tree :r/m)))        (:cmp #x3a))
(defiformat "<|regXX, reg/memXX"     ( w :rflags r  (:regx)         r  (x (tree :r/m)))        (:cmp #x3b))

(defiformat "<>"                     (rw :rflags)                                              (:cmc #xf5))
(defiformat "<"                      ( w :rflags)                                              (:clc #xf8 :cld #xfc :stc #xf9 :std #xfd))
(defiformat "$<IF"                   ( w :rflags r  :cpl  r  :cs)                              (:cli #xfa :sti #xfb))
                                                                                               
(defiformat "<|!AH"                  ( w :rflags r  :ah)                                       (:sahf #x9e))
(defiformat ">!AH"                   ( w :ah     r  :rflags)                                   (:lahf #x9f))
;;; end-of-flag-manip

;;;;
;;;; Jumps, calls, returns, branches and loops
;;;;
(defiformat "@immoff8"               ( w :rip   r  (:imm8))                                    (:jmp #xeb))
(defiformat "@immoff16"              ( w :rip   r  (:immxs))                                   (:jmp #xe9))
(defiformat "@reg/memXX"             ( w :rip   r  (x (tree :r/m)))                            (:jmp #xff 4)) ;; no prefix for 32bit in long mode

#|
 (defiformat "@ptr16:16"             ( w :rip    w :cs   w :tss   r  :imm32/48)                (:jmpf #xea)) ;; compat mode |#

(defiformat "@mem32/48"              ( w :rip    w :cs   w :tss   r  (fpx (tree :/m)))         (:jmpf #xff 5))

(defiformat "@@immoff32"             (rw :rip   rw :rsp r  :mem32 r  (:immxs))                 (:call #xe8))
(defiformat "@@reg/memXX"            (rw :rip   rw :rsp r  :memx  r  (x (tree :r/m)))          (:call #xff 2))

(defiformat "@@imm8"                 (rw :rip   rw :rsp r  :mem16 r  (:imm8))                  (:ret #xc2))
(defiformat "@@"                     (rw :rip   rw :rsp r  :mem16)                             (:ret #xc3))

(defiformat "@>immoff8"              ( w :rip   r  :rflags  r  (:imm8))                        (:jo #x70   :jno #x71   :jc #x72   :jnc #x73   :jz #x74   :jnz #x75   :jbe #x76   :jnbe #x77
                                                                                                :js #x78   :jns #x79   :jp #x7a   :jnp #x7b   :jl #x7c   :jnl #x7d   :jle #x7e   :jnle #x7f))
(defiformat "@>immoffXX"             ( w :rip   r  :rflags  r  (:immx))                        (:jo #x0f80 :jno #x0f81 :jc #x0f82 :jnc #x0f83 :jz #x0f84 :jnz #x0f85 :jbe #x0f86 :jnbe #x0f87
                                                                                                :js #x0f88 :jns #x0f89 :jp #x0f8a :jnp #x0f8b :jl #x0f8c :jnl #x0f8d :jle #x0f8e :jnle #x0f8f))

#|
 (defiformat "@adXCX, immoff8"       ( w :rip   r  :adxcx32 r  (:imm8))                        (:jxcxz #xe3)) ;; compat mode |#
(defiformat "@adXCX, immoff8"        ( w :rip   r  :adxcx64 r  (:imm8))                        (:je/rcxz #xe3)) ;; XXX: how do we dispatch on assembly?

(defiformat "@>RCX, immoff8"         ( w :rip   rw :xcx     r  (:imm8) r  :rflags)             (:loopnz #xe0 :loopz #xe1))
(defiformat "@RCX, immoff8"          ( w :rip   rw :xcx     r  (:imm8))                        (:loop   #xe2))

#|
 (defiformat "@@@ptr16:16/32"        (rw :rip   rw :rsp rw :cpl rw :cs rw :ss  w :mfpx
                                      r  :tss   r  :ptr16/16)                                  (:callf #x9a)) ;; compat mode |#
(defiformat "@@@mem32/48"            (rw :rip   rw :xsp rw :cpl rw :cs rw :ss  w :mfpx
                                      r  (fpx (tree :/m))   r  :tss)                           (:callf #xff 3))
(defiformat "@@@imm16"               (rw :rip   rw :xsp rw :cpl rw :cs rw :ss r  :mfpx
                                      r  (:imm16))                                             (:retf  #xca))
(defiformat "@@@"                    (rw :rip   rw :xsp rw :cpl rw :cs rw :ss r  :mfpx)        (:retf  #xcb))             
                                      
;;; end-of-jump-branch-call-rets

;;;;
;;;; String memory: XXX
;;;;                                                                    
(defiformat "<>|mem8, mem8"          (rw :rflags rw :si  rw :di  r (8 (:segdds  :si)) r (8 (:es  :di)))   (:cmps #xa6))
(defiformat "<>|memXX, memXX"        (rw :rflags rw :xsi rw :xdi r (x (:segdds :xsi)) r (x (:es :xdi)))   (:cmps #xa7))

(defiformat "!AL, mem8"              ( w (:al)   rw :si  r  (8 (:segdds  :si)))                (:lods #xac))
(defiformat "!xAX, memXX"            ( w (:xax)  rw :xsi r  (x (:segdds  :xsi)))               (:lods #xad))

(defiformat "!mem8, mem8"            (rw :si  rw :di   w (8 (:segdds  :si)) r  (8 (:es :di)))  (:movs #xa4))
(defiformat "!memXX, memXX"          (rw :xsi rw :xdi  w (x (:segdds :xsi)) r  (x (:es :xdi))) (:movs #xa5))

(defiformat "<>|AL, mem8"            (rw :rflags rw :di  r  (:al)   r  (8 (:es :di)))          (:scas #xae))
(defiformat "<>|xAX, memXX"          (rw :rflags rw :xdi r  (:xax)  r  (x (:es :xdi)))         (:scas #xaf))

(defiformat "!mem8, AL"              (rw :di      w  (8 (:es  :di)) r  (:al))                  (:stos #xaa))
(defiformat "!memXX, xAX"            (rw :xdi     w  (x (:es :xdi)) r  (:xax))                 (:stos #xab))
;;;; end-of-string-memorys

;;;;
;;;; Addressing
;;;;
(defiformat "!DS, regXX, mem32/48"   ( w :ds  w (:regxs)    r  (32 (tree :/m)))                (:lds #xc5))
(defiformat "!ES, regXX, mem32/48"   ( w :es  w (:regxs)    r  (32 (tree :/m)))                (:les #xc4))
(defiformat "!FS, regXX, mem32/48"   ( w :fs  w (:regxs)    r  (32 (tree :/m)))                (:lfs #x0fb4))
(defiformat "!GS, regXX, mem32/48"   ( w :gs  w (:regxs)    r  (32 (tree :/m)))                (:lgs #x0fb5))
(defiformat "!SS, regXX, mem32/48"   ( w :ss  w (:regxs)    r  (32 (tree :/m)))                (:lss #x0fb2))
                                                                             
(defiformat "!regXX, mem"            ( w (:regx)            r  (32 (tree :/m)))                (:lea #x8d))
;;; end-of-addressings
                                                                                                                         
;;;;                                                                                                                     
;;;; Moves
;;;;                                                                                                                     
(defiformat "!reg/mem8, reg8"        ( w (8 (tree :r/m))    r  (:reg8))                        (:mov #x88))
(defiformat "!reg/memXX, regXX"      ( w (x (tree :r/m))    r  (:regx))                        (:mov #x89))
(defiformat "!reg8, reg/mem8"        ( w (:reg8)            r  (8 (tree :r/m)))                (:mov #x8a))
(defiformat "!regXX, reg/memXX"      ( w (:regx)            r  (x (tree :r/m)))                (:mov #x8b))
                                                           
(defiformat "!regXX, reg/mem8"       ( w (:regx)            r  (8 (tree :r/m)))                (:movsx #x00fbe :movzx #x0fb6))
(defiformat "!regXXl, reg/mem16"     ( w (:regxl)           r  (16 (tree :r/m)))               (:movsx #x00fbf :movzx #x0fb7))
                                                           
(defiformat "!reg64, reg/mem32"      ( w (:reg64)           r  (32 (tree :r/m)))               (:movsxd #x63)) ;; (weird for 16bit op; separate format?)                     
                                                                             
(defiformat "!memXXl, regXXl"        ( w (xl (tree :/m))    r  (:regxl))                       (:movnti #x00fc3))
                                                                                                
(defiformat "!AL, immoff8"           ( w (:al)              r  (8 (:imm8)))                    (:mov #xa0))
(defiformat "!xAX, immoffXX"         ( w (:xax)             r  (x (:immxf)))                   (:mov #xa1))
(defiformat "immoff8, AL"            ( w (8 (:imm8))        r  (:al))                          (:mov #xa2))
(defiformat "immoffXX, xAX"          ( w (x (:immxf))       r  (:xax))                         (:mov #xa3))
                                                                                               
(defiformat "!reg8, imm8"            ( w (:reg8)            r  (:imm8))                        (:mov #xb0 :mov #xb1 :mov #xb2 :mov #xb3 :mov #xb4 :mov #xb5 :mov #xb6 :mov #xb7))
(defiformat "!regXX, immXXf"         ( w (:regx)            r  (:immxf))                       (:mov #xb8 :mov #xb9 :mov #xba :mov #xbb :mov #xbc :mov #xbd :mov #xbe :mov #xbf))
(defiformat "!reg/mem8, imm8"        ( w (:reg/mem8)        r  (:imm8))                        (:mov #xc6 0))
(defiformat "!reg/memXX, immXX"      ( w (x (tree :r/m))    r  (:immx))                        (:mov #xc7 0))
                                                                                                                     
(defiformat "!regXX/mem16, segreg"   ( w (x/16 (tree :r/m)) r  (:segreg))                      (:mov #x8c))
(defiformat "!segreg, reg/mem16"     ( w (:segreg)          r  (16 (tree :r/m)))               (:mov #x8e))

(defiformat "!mmx, reg/memXXl"       ( w (:mmx)             r  (xl (tree :r/m)))               (:movd #x00f6e))
(defiformat "!reg/memXXl, mmx"       ( w (xl (tree :r/m))   r  (:mmx))                         (:movd #x00f7e))
(defiformat "!xmm, reg/memXXl"       ( w (:xmm)             r  (xl (tree :r/m)))               (:movd #x10f6e))
(defiformat "!reg/memXXl, xmm"       ( w (xl (tree :r/m))   r  (:xmm))                         (:movd #x10f7e))

(defiformat "!reg32, xmm"            ( w (32 (tree :r/))    r  (:xmm))                         (:movmskps #x00f50 :movmskpd #x10f50))

;; NOTE: mod is ignored in this group
(defiformat "$!cr, regXXl"           ( w (:cr)     r :cpl   r  :cs     r  (xl (tree :r/)))     (:mov #x0f22 0))
(defiformat "!regXXl, cr"            ( w (xl (tree :r/))    r  (:cr)   r  :cpl r  :cs)         (:mov #x0f20 0))
(defiformat "$!cr8, regXXl"          ( w (:cr8)    r :cpl   r  :cs     r  (xl (tree :r/)))     (:mov #x0f22 1))
(defiformat "!regXXl, cr8"           ( w (xl (tree :r/))    r  (:cr8)  r  :cpl r  :cs)         (:mov #x0f20 1))
(defiformat "$!dr, regXXl"           ( w (:dr)     r :cpl   r  :cs     r  (xl (tree :r/)))     (:mov #x0f21))
(defiformat "!regXXl, dr"            ( w (xl (tree :r/))    r  (:dr)   r  :cpl r  :cs)         (:mov #x0f23))
;;; end-of-moves

;;;;
;;;; Stack
;;;;
(defiformat "![SS:RSP], reg/memXX"   ( w :memx     rw :rsp r  :ss r  (x (tree :r/m)))          (:push #xff 6))
(defiformat "![SS:RSP], regXX"       ( w :memx     rw :rsp r  :ss r  (:regx))                  (:push #x50)) ;; modrmless regspec
(defiformat "![SS:RSP], imm8"        ( w :mem8     rw :rsp r  :ss r  (:imm8))                  (:push #x6a))
(defiformat "![SS:RSP], immXX"       ( w :memx     rw :rsp r  :ss r  (:immxf))                 (:push #x68))
(defiformat "![SS:RSP], CS"          ( w :mem16    rw :rsp r  :ss r  (:cs))                    (:push #x0e))
(defiformat "![SS:RSP], DS"          ( w :mem16    rw :rsp r  :ss r  (:ds))                    (:push #x1e))
(defiformat "![SS:RSP], ES"          ( w :mem16    rw :rsp r  :ss r  (:es))                    (:push #x06))
(defiformat "![SS:RSP], SS"          ( w :mem16    rw :rsp r  :ss r  (:ss))                    (:push #x16))
(defiformat "![SS:RSP], FS"          ( w :mem16    rw :rsp r  :ss r  (:fs))                    (:push #x0fa0))
(defiformat "![SS:RSP], GS"          ( w :mem16    rw :rsp r  :ss r  (:gs))                    (:push #x0fa8))

(defiformat "!reg/memXX, [SS:RSP]"   ( w (x (tree :r/m)) rw :rsp r  :ss r  :memx)              (:pop #x8f 0))
(defiformat "!regXX, [SS:RSP]"       ( w (:regx)         rw :rsp r  :ss r  :memx)              (:pop #x58)) ;; modrmless regspec
(defiformat "!DS, [SS:RSP]"          ( w (:ds)           rw :rsp r  :ss r  :mem16)             (:pop #x1f))
(defiformat "!ES, [SS:RSP]"          ( w (:es)           rw :rsp r  :ss r  :mem16)             (:pop #x07))
(defiformat "!SS, [SS:RSP]"          ( w (:ss)           rw :rsp r  :ss r  :mem16)             (:pop #x17))
(defiformat "!FS, [SS:RSP]"          ( w (:fs)           rw :rsp r  :ss r  :mem16)             (:pop #x0fa1))
(defiformat "!GS, [SS:RSP]"          ( w (:gs)           rw :rsp r  :ss r  :mem16)             (:pop #x0fa9))

#|
 (defiformat "![SS:ESP], EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI"
                                     (rw :rsp  w :mem128/256  r  :ss  r  :rdi r  :rsi r  :rbp r  :rbx r  :rdx r  :rcx r  :rax) (:pusha/d #x60)) ;; compat
 (defiformat "!EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX, [SS:ESP]"
                                     (rw :rsp  w :rdi  w :rsi  w :rbp  w :rbx  w :rdx  w :rcx  w :rax r  :ss  r  :mem128/256)  (:popa/d  #x61)) ;; compat |#

(defiformat ">![SS:xSP]"             ( w :memx   rw :rsp r  :flags r  :ss)                     (:pushf/d/q #x9c))
(defiformat "<>![SS:RSP]"            (rw :rflags rw :rsp r  :ss    r  :memx    r  :cpl r  :cs) (:popf/d/q  #x9d))

(defiformat "imm16, imm8"            (rw :rsp    rw :rbp r  :ss    r  (:imm16) r  (:imm8))     (:enter #xc8))

(defiformat "xBP, xSP"               (rw  :xbp   rw :xsp r  :memx)                             (:leave #xc9))
;;; end-of-stacks

;;;;
;;;; Port I/O
;;;;
(defiformat "#!AL, imm8"             ( w (:al)    r  (:imm8)   r  :tss)                        (:inb  #xe4))
(defiformat "#!xAXs, imm8"           ( w (:xaxs)  r  (:imm8)   r  :tss)                        (:inb  #xe5))
(defiformat "#!AL, DX"               ( w (:al)    r  (:dx)     r  :tss)                        (:inb  #xec))
(defiformat "#!xAXs, DX"             ( w (:xaxs)  r  (:dx)     r  :tss)                        (:inb  #xed))
                                                                                                                        
(defiformat "#imm8, AL"              (r  (:imm8)  r  (:al)     r  :tss)                        (:outb #xe6))
(defiformat "#imm8, xAXs"            (r  (:imm8)  r  (:xaxs)   r  :tss)                        (:outb #xe7))
(defiformat "#|DX, AL"               (r  (:dx)    r  (:al)     r  :tss)                        (:outb #xee))
(defiformat "#|DX, xAXs"             (r  (:dx)    r  (:xaxs)   r  :tss)                        (:outb #xef))
                                                                                                                        
(defiformat "#!>mem8, DX"            ( w (8  (tree :/m)) rw :rdi  r  :es   r  (:dx)   r  :rflags r  :tss)   (:insb    #x6c))
(defiformat "#!>memXXl, DX"          ( w (xs (tree :/m)) rw :rdi  r  :es   r  (:dx)   r  :rflags r  :tss)   (:insw/d  #x6d))
(defiformat "#|>DX, mem8"            (rw :rsi     r  :ds r  (:dx) r  (8   (tree :/m)) r  :rflags r  :tss)   (:outsb   #x6e))
(defiformat "#|>DX, memXXs"          (rw :rsi     r  :ds r  (:dx) r  (xs  (tree :/m)) r  :rflags r  :tss)   (:outsw/d #x6f))
;;;; end-of-ios

;;;;
;;;; Interrupts
;;;;
(defiformat "$@<"                    ( w :rip     w :rflags    r  (3))                         (:int3     #xcc)) ;; how do we deal on the encode side wrt. INT?
(defiformat "$@<>imm8"               (rw :rflags rw :rip rw :rsp rw :cs     rw :ss  rw :mem 
                                       w :cpl w :tss           r  (:imm8))                     (:int      #xcd)) ;; how do we deal on the encode side wrt. INT 3?
(defiformat "$@>"                    ( w :rip     w :cpl  w :cs   w :tss    r  :rflags)        (:into     #xce))
(defiformat "$@@<"                   (rw :cpl    rw :cs  rw :tss  w :rflags
                                       w :rip  w :rsp  w :ss  w :mem)                          (:iret/d/q #xcf))
;;; end-of-interrupts

;;;;
;;;; System stuff
;;;;
(defiformat "EAX, EBX, ECX, EDX"     (rw :eax    w :ebx  w :ecx  w :edx)                       (:cpuid       #x0fa2))
(defiformat "|mem8"                  (r  (8 (tree :/m)))                                       (:clflush     #x0fae))
(defiformat "|!mem8"                 (r  (8 (tree :/m)))                                       (:prefetch    #x0f0d 0 :prefetchw #x0f0d 1 :prefetch  #x0f0d 2 :prefetchw #x0f0d 3
                                                                                                :prefetch    #x0f0d 4 :prefetch  #x0f0d 5 :prefetch  #x0f0d 6 :prefetch  #x0f0d 7
                                                                                                :prefetchnta #x0f18 0 :prefetch0 #x0f18 1 :prefetch1 #x0f18 2 :prefetch2 #x0f18 3
                                                                                                :nop         #x0f18 4 :nop       #x0f18 5 :nop       #x0f18 6 :nop       #x0f18 7
                                                                                                :invlpg      #x0f01 7 0))
(defiformat "|RAX, ECX"              (r  (:rax) r  (:ecx))                                     (:invlpga     #x0f01 3 3 7))
(defiformat ""                       ()                                                        (:mfence      #x0fae 5 3 :lfence #x0fae 6 3 :sfence #x0fae 7 3
                                                                                                :nop         #x90     ;; ..and watch the world going down in flames.. XXX!
                                                                                                :pause       #xf390)) ;; ..and wtf is that? rep nop? XXX!
(defiformat "|!mem16/32/64"          ((8 (tree :r/m)))                                         (:nop  #x0f19 :nop    #x0f1a :nop #x0f1b :nop #x0f1c :nop #x0f1d :nop #x0f1e :nop #x0f1f))
(defiformat "|CPL"                   (r  :cpl   r  :cs)                                        (:invd #x0f08 :wbinvd #x0f09 :hlt #xf4))

#|
 (defiformat "<$reg/mem16, reg16"    ( w :rflags rw (16 (tree :r/m))          r  (:reg16))     (:arpl #x63)) ;; compat |#
(defiformat "$!GIF"                  ( w :gif)                                                 (:stgi #x0f01 3 3 4 :clgi #x0f01 3 3 5))

(defiformat "$CR0"                   ( w :cr0)                                                 (:clts #x0f06))

(defiformat "<!$regXX, reg/mem16"    ( w :rflags  w (:regx) r  (16 (tree :r/m))
                                      r  :cpl    r  :cs     r  :dpl)                           (:lar #x0f02 :lsl #x0f03))

#|
 (defiformat "|$mem48"               (r  :mem48 r  :cpl r  :cs)                                (:lgdt    #x0f01 2 :lidt #x0f01 3 0)) ;; compat
 (defiformat "!mem48"                ( w :mem48)                                               (:sgdt    #x0f01 0 :sidt #x0f01 1 0)) ;; compat |#
(defiformat "|$mem80"                (r  (80 (tree :/m)) r  :cpl   r  :cs)                     (:lgdt    #x0f01 2 :lidt #x0f01 3 0)) ;; long
(defiformat "!mem80"                 ( w (80 (tree :/m)))                                      (:sgdt    #x0f01 0 :sidt #x0f01 1 0)) ;; long

(defiformat "!$sys16, ~S"            ( w :sys16  r  (16 (tree :r/m))         r  :cpl  r  :cs)  (:lldt    #x0f00 2 :lmsw #x0f01 6 :ltr #x0f00 3))

(defiformat "$seg:[EAX], ECX, EDX"   (r  :segdds r  :eax r  :ecx   r  :edx   r  :cpl  r  :cs)  (:monitor #x0f01 7 3 0))
(defiformat "$EAX, ECX"              (r  :eax    r  :ecx r  :cpl   r  :cs)                     (:mwait   #x0f01 7 3 1))

(defiformat "2!2|EDX:EAX, sys64"     ( w :eax     w :edx r  :sys64 r  :cpl   r  :cs   r  :cr4) (:rdtsc   #x0f31))
(defiformat "2!2|EDX:EAX, ECX,sys64" ( w :eax     w :edx r  :ecx   r  :sys64 r  :cpl  r  :cs)  (:rdmsr   #x0f32 :rdpmc #x0f33))
(defiformat "2!2|3!3|EDX:EAX:ECX, sys64, sys32" 
                                     ( w :eax     w :edx    w :ecx
                                      r  :sys64  r  :sys32 r  :cpl   r  :cs r  :cr4)           (:rdtscp  #x0f01 1 3 1))

(defiformat "$!sys64, EDX:EAX, ECX"  ( w :sys64  r  :eax r  :edx   r  :ecx   r  :cpl  r  :cs)  (:wrmsr   #x0f30))

(defiformat "!regXX/mem16, sys16"    ( w (x (tree :r/m))           r  :sys16)                  (:sldt    #x0f00 0 :smsw #x0f01 4 :str #x0f00 1)) ;; lying about affected memory size here
(defiformat "2|sys16, GS"            (rw :gs     rw :sys16         r  :cpl   r  :cs)           (:swapgs  #x0f01 1 3 0))

#|
 (defiformat "$@<!CX"                ( w :eflags  w :eip  w :cpl    w :cs     w :ss    w :cx
                                      r  :star)                                                (:syscall #x0f05)) ;; compat
 (defiformat "$@<|CX"                ( w :eflags  w :eip rw :cpl   rw :cs     w :ss
                                      r  :star   r  :efer r :ecx)                              (:sysret  #x0f07))  ;; compat |#
(defiformat "$@<!2|RCX, R11"         ( w :rflags  w :rip    w :cpl  w :cs     w :ss    w :rcx   
                                       w :r11    r  :cstar)                                    (:syscall #x0f05)) ;; long
(defiformat "$@<|RCX, R11"           ( w :rflags  w :rip   rw :cpl rw :cs     w :ss
                                      r  :efer   r  :cstar r  :rcx r  :r11)                    (:sysret  #x0f07)) ;; long

#|
 (defiformat "$@<SS:ESP"             ( w :eflags  w :eip  w :cpl    w :cs     w :ss    w :esp) (:sysenter #x0f34)) ;; compat
 (defiformat "$@<SS:ESP, CX, DX"     ( w :eflags  w :eip  w :cpl    w :cs     w :ss    w :esp
                                      r  :cx    r  :dx)                                        (:sysexit  #x0f35)) ;; compat |#

(defiformat "$@"                     ( w :rip)                                                 (:ud2 #x0f0b :vmmcall #x0f01 3 3 1))

(defiformat "<$reg/mem16"            ( w :rflags r  (16 (tree :r/m)) r  :cpl r  :cs)           (:verr #x0f00 4 :verw #x0f00 5))

(defiformat "$<"                     ( w :rflags rw :cr0 rw :cr3 rw :cr4 rw :cr6 rw :cr7
                                      rw :efer)                                                (:rsm    #x0faa))
(defiformat "<|$[EAX]"               ( w :rflags  w :cr0  w :cs   w :ss  w :edx w :esp rw :eax
                                       w :ebx  w :ecx  w :edx  w :esi  w :edi  w :rgpr  w :gif
                                      rw :efer r  :cppl)                                       (:skinit #x0f01 3 3 6))

(defiformat "$!2|FS, GS, CS, [RAX]"  ( w :fs      w :gs   w :tr   w :star  w :lstar  w :cstar
                                       w :sfmask r  :rax r  :mem r  :cpl  r  :cs    r  :efer)  (:vmload #x0f01 3 3 2))
(defiformat "$![RAX], CS, FS, GS"    ( w :mem    r  :rax r  :cpl r  :cs   r  :efer
                                      r  :fs     r  :gs  r  :tr  r  :star r  :lstar r :cstar)  (:vmsave #x0f01 3 3 3))
(defiformat "$<>@![RAX]"             (rw :rflags rw :es  rw :cs  rw :ss   rw :ds    rw :efer
                                      rw :cr0 rw :cr4 rw :cr3 rw :rip rw :rsp rw :rax rw :cpl
                                      rw :mem     w  :cr2    w  :dr6  w  :dr7  w  :gif
                                      r  :cs     r  :sys64)                                    (:vmrun  #x0f01 3 3 0))
;;;;
;;;; Total of some instruction formats
;;;;

;;;;
;;;; Not an instruction
;;;;
;; (defiformat "$<>@"                       (:gif :efer :cr0 :cr4 :cr3 :rflags :rip :rsp :rax :dr7 :cpl :es :cs :ss :ds)
;;                                              (:es :cs :ss :ds :efer :cr4 :cr3 :cr2 :cr0 :rflags :rip :rsp :rax :dr7 :dr6 :cpl))                  ;; #VMEXIT
