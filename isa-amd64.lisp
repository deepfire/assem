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
   (op/code->format                        :initarg :op/code->format)
   (op/arglist->formats                    :initarg :op/arglist->formats)
   (id->correspondence                     :initarg :id->correspondence))
  (:default-initargs
   :id->attrset         (make-hash-table :test 'eq)
   :id->argtype         (make-hash-table :test 'eq)
   :id->uformat         (make-hash-table :test 'eq)
   :id->format          (make-hash-table :test 'equal)
   :op/code->format     (make-hash-table :test 'equal)
   :op/arglist->formats (make-hash-table :test 'equal)
   :id->correspondence  (make-hash-table :test 'eq)))

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

(defstruct (microformat (:conc-name uformat-))
  (id    nil :type symbol :read-only t)
  (names nil :type list   :read-only t)
  (bytes nil :type list   :read-only t))

(define-subcontainer uformat :type microformat :container-slot id->uformat :if-exists :continue)

(defun ensure-microformat (isa name name/byte-pairs)
  (let ((u (make-microformat :id name :names (mapcar #'car name/byte-pairs) :names (mapcar #'cdr name/byte-pairs))))
    (setf (uformat isa name) u)))

(defmacro define-microformat (name &body name/byte-pairs)
  `(ensure-microformat *isa* ,name ',name/byte-pairs))

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
(define-attribute-set :segment
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
   :discmap (make-hash-table)))

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
    :ax  :bx  :cx  :dx  :sp  :bp  :si  :di              :r8w  :r9w :r10w :r11w :r12w :r13w :r14w :r15w)

(define-argument-type-set :reg32 32 ()
    :eax :ebx :ecx :edx :esp :ebp :esi :edi             :r8d  :r9d :r10d :r11d :r12d :r13d :r14d :r15d)

(define-argument-type-set :reg64 64 ()
    :rax :rbx :rcx :rdx :rsp :rbp :rsi :rdi             :r8   :r9  :r10  :r11  :r12  :r13  :r14  :r15)

(define-argument-type-set :base32 32 ()
   :eax  :ecx :edx :ebx :ebp :esi :edi                  :r8d  :r9d :r10d :r11d       :rip  :r14d :r15d)

(define-argument-type-set :base64 64 ()
    :rax :rcx :rdx :rbx :rbp :rsi :rdi                  :r8   :r9  :r10  :r11        :rip  :r14  :r15)

(define-argument-type-set :cr 32 (:register-members t)
    :cr0 :cr1 :cr2 :cr3 :cr4 :cr5 :cr6 :cr7 :cr8 :cr9 :cr0 :cr1 :cr2 :cr3 :cr4 :cr5)

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
   :argvalue->set (make-hash-table :test 'eq)))

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

;;;;               
;;;;   +------------+                                                        +----------------------------+ 
;;;;   |    legacy  |       REX           op                ModRM            |            SIB             |     displacement         immediate
;;;;   v  +-------+ |    +-------+    +-------+    +-------+-------+-------+ |  +-------+-------+-------+ v   +-------------+     +-------------+   
;;;; ---->|   8   |-+-+->|   8   |--->|  8/16 |-+->| 2 mod | 3 reg | 3 r/m |-+->| 2 sca | 3 idx | 3 bas |---+-|  8/16/32/64 |---+-|  8/16/32/64 |---->
;;;;   |  +-------+ ^ |  +-------+ ^  +-------+ |  +-------+-------+-------+    +-------+-------+-------+ ^ | +-------------+ ^ | +-------------+ ^ 
;;;;   +------------+ +------------+            +---------------------------------------------------------+ +-----------------+ +-----------------+ 
;;;;
;;;; The assumptions:
;;;;    1. the "default operand size" for compat/legacy modes is assumed to designate a 32-bit operand size.
;;;;    2. 16-bit addressing does not exist, period.
;;;;
(defun make-x86/64-isa (sixty-four-p)
  `(nil (00 04 (:rex :nrex))
        (:rex (:uf-rex)
              (ban :rex :addrsz :segment :lock :opersz/p :rep/p :repn/p)
              (shift -8)
              (include :nrex))
        (:nrex (-04 08 (:opersz/p :rep/p :repn/p :addrsz :segment :lock
                        :opcode
                        ,(if sixty-four-p
                             :opcode-longmode
                             :opcode-shortmode)
                        (#x80 #x81 ,@(unless sixty-four-p '(#x82)) #x83 #x8f #xc0 #xc1 #xd0 #xd1 #xd2 #xd3 #xf6 #xf7 #xfe #xff #xc6 #xc7)))
               ;; when there's no window declared, include uses the target's one
               (:addrsz   () (ban :addrsz)  (include nil))
               (:segment  () (ban :segment) (include nil))
               (:lock     () (ban :lock)    (include nil))
               (:opersz/p ()
                          (ban :opcode-ext-unprefixed :opersz/p)
                          (add-at :xop :opcode-ext-opersz (#x78))
                          (include nil))
               (:rep/p    ()
                          (ban :opcode-ext-unprefixed :rep/p :repn/p)
                          (add-at :xop :opcode-ext-rep)
                          (include nil))
               (:repn/p   ()
                          (ban :opcode-ext-unprefixed :rep/p :repn/p)
                          (add-at :xop :opcode-ext-repn)
                          (include nil))
               (:opcode ()
                        )
               (:opcode-longmode ()
                                 )
               (:opcode-shortmode ()
                                  )
               (#x80 (:uf-modrm (:grp1-80))
                     (dispatch :acc :reg)
                     (:grp1-80 ()
                               (dispatch :acc :reg :mod)))
               (#x81 (:uf-modrm (:grp1-81))
                     (dispatch :acc :reg)
                     (:grp1-81 ()
                               (dispatch :opcode :reg :mod)))
               ,@(unless sixty-four-p
                  `((#x82 (+ 03 03 (:grp1-82-shortmode))
                          (:grp1-82-shortmode ()
                                              ))))
               (#x83 (:uf-modrm (:grp1-83))
                     (dispatch :acc :reg)
                     (:grp1-83 ()
                               (dispatch :opcode :reg :mod)))
               (#x8f (+ 03 03 (:grp1-8f))
                     (:grp1-8f ()
                               ))
               (#xc0 (+ 03 03 (:grp2-c0))
                     (:grp2-c0 ()
                               ))
               (#xc1 (+ 03 03 (:grp2-c1))
                     (:grp2-c1 ()
                               ))
               (#xd0 (+ 03 03 (:grp2-d0))
                     (:grp2-d0 ()
                               ))
               (#xd1 (+ 03 03 (:grp2-d1))
                     (:grp2-d1 ()
                               ))
               (#xd2 (+ 03 03 (:grp2-d2))
                     (:grp2-d2 ()
                               ))
               (#xd3 (+ 03 03 (:grp2-d3))
                     (:grp2-d3 ()
                               ))
               (#xf6 (+ 03 03 (:grp3-f6))
                     (:grp3-f6 ()
                               ))
               (#xf7 (+ 03 03 (:grp3-f7))
                     (:grp3-f7 ()
                               ))
               (#xfe (+ 03 03 (:grp4-fe))
                     (:grp4-fe ()
                               ))
               (#xff (+ 03 03 (:grp5-ff))
                     (:grp5-ff ()
                               ))
               (#xc6 (+ 03 03 (:grp11-c6))
                     (:grp11-c6 ()
                                ))
               (#xc7 (+ 03 03 (:grp11-c7))
                     (:grp11-c7 ()
                                ))
               (:xop (08 08 (:opcode-ext
                             ,@(unless sixty-four-p
                                       `(:opcode-ext-shortmode))
                             :opcode-ext-unprefixed :opcode-ext-unprefixed-modrm
                             (#x00 #x01 #xba #xc7 #xb9 #x71 #x72 #x73 #xae #x18 #x0d)))
                     (:opcode-ext ()
                                  )
                     (:opcode-ext-unprefixed ()
                                             )
                     (:opcode-ext-opersz ()
                                         )
                     (:opcode-ext-rep ()
                                      )
                     (:opcode-ext-repn ()
                                       )
                     (#x00 (+ 03 03 (:grp6-0f-00))
                           (:grp6-0f-00 ()
                                        ))
                     (#x01 (+ 03 03 (:grp7-0f-01 (#x101 #x301 #x701)))
                           (:grp7-0f-01 ()
                                        )
                           (#x101 (+ 02 02 (:grp7-0f-01-1-0))
                                  (:grp7-0f-01-1-0 ()
                                                   )
                                  (#x1901 (+ -5 3 (:grp7-0f-01-1-3))
                                          (:grp7-0f-01-1-3 ()
                                                           )))
                           (#x301 (+ 02 02 (:grp7-0f-01-3-0))
                                  (:grp7-0f-01-3-0 ()
                                                   )
                                  (#x1b01 (+ -5 3 (:grp7-0f-01-3-3))
                                          (:grp7-0f-01-3-3 ()
                                                           )))
                           (#x701 (+ 02 02 (:grp7-0f-01-7-0))
                                  (:grp7-0f-01-7-0 ()
                                                   )
                                  (#x1f01 (+ -5 3 (:grp7-0f-01-7-3))
                                          (:grp7-0f-01-7-3 ()
                                                           ))))
                     (#xba (:uf-modrm (:grp8-0f-ba))
                           (dispatch :acc :reg)
                           (:grp8-0f-ba ()
                                        (dispatch :opcode :reg :mod)))
                     (#xc7 (+ 03 03 (:grp9-0f-c7))
                           (:grp9-0f-c7 ()
                                        ))
                     (#xb9 (+ 03 03 (:grp10-0f-b9))
                           (:grp10-0f-b9 ()
                                         ))
                     (#x71 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp12-0f-71))
                           (:grp12-0f-71 ()
                                         ))
                      (#b1 (+ 03 03 (:grp12-0f-71-op))
                           (:grp12-0f-71-op ()
                                         )))
                     (#x72 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp13-0f-72))
                           (:grp13-0f-72 ()
                                         ))
                      (#b1 (+ 03 03 (:grp13-0f-72-op))
                           (:grp13-0f-72-op ()
                                         )))
                     (#x73 (+ 01 :opersz/p (#b0 #b1))
                      (#b0 (+ 03 03 (:grp14-0f-73))
                           (:grp14-0f-73 ()
                                         ))
                      (#b1 (+ 03 03 (:grp14-0f-73-op))
                           (:grp14-0f-73-op ()
                                         )))
                     (#xae (+ 03 03 (:grp15-0f-ae (#x5ae #x6ae #x7ae)))
                           (:grp15-0f-ae ()
                                         )
                           (#x5ae (+ 02 02 (:grp15-0f-ae-5))
                                  (:grp15-0f-ae-5 ()
                                                  ))
                           (#x6ae (+ 02 02 (:grp15-0f-ae-6))
                                  (:grp15-0f-ae-6 ()
                                                  ))
                           (#x7ae (+ 02 02 (:grp15-0f-ae-7))
                                  (:grp15-0f-ae-7 ()
                                                  )))
                     (#x18 (+ 03 03 (:grp16-0f-18))
                           (:grp16-0f-18 ()
                                         ))
                     (#x78 (+ 03 03 (:grp17-0f-78-op))
                           (:grp17-0f-78 ()
                                         ))
                     (#x0d (+ 03 03 (:grpp-0f-0d))
                           (:grpp-0f-0d ()
                                        ))))))

(define-attribute-set :opcode
  (:add .       #x00) (:add .     #x01) (:add .      #x02) (:add .       #x03) (:add .       #x04) (:add .       #x05)  #| 32bit mode|#  #| 32bit mode   |#
  (:adc .       #x10) (:adc .     #x11) (:adc .      #x12) (:adc .       #x13) (:adc .       #x14) (:adc .       #x15)  #| 32bit mode|#  #| 32bit mode   |#
  (:and .       #x20) (:and .     #x21) (:and .      #x22) (:and .       #x23) (:and .       #x24) (:and .       #x25)  #| ES seg    |#  #| 32bit mode   |#
  (:xor .       #x30) (:xor .     #x31) (:xor .      #x32) (:xor .       #x33) (:xor .       #x34) (:xor .       #x35)  #| SS seg    |#  #| 32bit mode   |#
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#  #|    rex       |#
  (:push .      #x50) (:push .    #x51) (:push .     #x52) (:push .      #x53) (:push .      #x54) (:push .      #x55) (:push .    #x56) (:push .      #x57)
   #| 32bit mode  |#   #| 32bit mode|#   #| 32bit mode |#   #| 64bit mode  |#   #|   FS seg     |#   #|   GS seg    |#   #| oper size |#   #| addr size   |#
  (:jo .        #x70) (:jno .     #x71) (:jb .       #x72) (:jnb .       #x73) (:jz .        #x74) (:jnz .       #x75) (:jbe .     #x76) (:jnbe .      #x77)
   #|   grp1      |#   #|   grp1    |#   #| 32bit grp  |#   #|   grp1      |#  (:test .      #x84) (:test .      #x85) (:xchg .    #x86) (:xchg .      #x87)
  (:xchg .      #x90) (:xchg .    #x91) (:xchg .     #x92) (:xchg .      #x93) (:xchg .      #x94) (:xchg .      #x95) (:xchg .    #x96) (:xchg .      #x97)
  (:mov .       #xa0) (:mov .     #xa1) (:mov .      #xa2) (:mov .       #xa3) (:movsb .     #xa4) (:movsw/d/q . #xa5) (:cmpsb .   #xa6) (:cmpsw/d/q . #xa7)
  (:mov .       #xb0) (:mov .     #xb1) (:mov .      #xb2) (:mov .       #xb3) (:mov .       #xb4) (:mov .       #xb5) (:mov .     #xb6) (:mov .       #xb7)
   #|   grp2      |#   #|   grp2    |#  (:ret-near . #xc2) (:ret-near .  #xc3)  #| 32bit mode  |#   #| 32bit mode  |#   #|   grp11   |#   #|   grp11     |#
   #|   grp2      |#   #|   grp2    |#   #|   grp2     |#   #|   grp2      |#   #| 32bit mode  |#   #| 32bit mode  |#   #| 32bit mode|#  (:xlat .      #xd7)
  (:loopne/nz . #xe0) (:loope/z . #xe1) (:loop .     #xe2) (:jxcxz .     #xe3) (:in .        #xe4) (:in .        #xe5) (:out .     #xe6) (:out .       #xe7)
   #|  lock       |#  (:int1 .    #xf1)  #|   repn     |#   #|   rep       |#  (:hlt .       #xf4) (:cmc .       #xf5)  #|   grp3    |#   #|   grp3      |#
  (:or .        #x08) (:or .      #x09) (:or .       #x0a) (:or .        #x0b) (:or .        #x0c) (:or .        #x0d)  #| 32bit mode|#   #| xop         |#
  (:sbb .       #x18) (:sbb .     #x19) (:sbb .      #x1a) (:sbb .       #x1b) (:sbb .       #x1c) (:sbb .       #x1d)  #| 32bit mode|#   #| 32bit mode  |# 
  (:sub .       #x28) (:sub .     #x29) (:sub .      #x2a) (:sub .       #x2b) (:sub .       #x2c) (:sub .       #x2d)  #| CS seg    |#   #| 32bit mode  |# 
  (:cmp .       #x38) (:cmp .     #x39) (:cmp .      #x3a) (:cmp .       #x3b) (:cmp .       #x3c) (:cmp .       #x3d)  #| DS seg    |#   #| 32bit mode  |# 
   #|   rex       |#   #|   rex     |#   #|   rex      |#   #|   rex       |#   #|   rex       |#   #|   rex       |#   #|   rex     |#  #|    rex       |#
  (:pop .       #x58) (:pop .     #x59) (:pop .      #x5a) (:pop .       #x5b) (:pop .       #x5c) (:pop .       #x5d) (:pop .     #x5e) (:pop .       #x5f)
  (:push .      #x68) (:imul .    #x69) (:push .     #x6a) (:imul .      #x6b) (:insb .      #x6c) (:insw/d .    #x6d) (:outsb .   #x6e) (:outsw/d .   #x6f)
  (:js .        #x78) (:jns .     #x79) (:jp .       #x7a) (:jnp .       #x7b) (:jl .        #x7c) (:jnl .       #x7d) (:jle .     #x7e) (:jnle .      #x7f)
  (:mov .       #x88) (:mov .     #x89) (:mov .      #x8a) (:mov .       #x8b) (:mov .       #x8c) (:lea .       #x8d) (:mov .     #x8e)  #|   grp1      |#
  (:cbwde/qe .  #x98) (:cwdqo .   #x99)  #| 32bit mode |#  (:f/wait .    #x9b) (:pushf/d/q . #x9c) (:popf/d/q .  #x9d) (:sahf .    #x9e) (:lahf .      #x9f)
  (:test .      #xa8) (:test .    #xa9) (:stosb .    #xaa) (:stosw/d/q . #xab) (:lodsb .     #xac) (:lodsw/d/q . #xad) (:scasb .   #xae) (:scasw/d/q . #xaf)
  (:mov .       #xb8) (:mov .     #xb9) (:mov .      #xba) (:mov .       #xbb) (:mov .       #xbc) (:mov .       #xbd) (:mov .     #xbe) (:mov .       #xbf)
  (:enter .     #xc8) (:leave .   #xc9) (:ret .      #xca) (:ret .       #xcb) (:int3 .      #xcc) (:int .       #xcd)  #| 32bit mode|#  (:iret/d/q .  #xcf)
   #|   x87       |#   #|   x87     |#   #|   x87      |#   #|   x87       |#   #|   x87       |#   #|   x87       |#   #|   x87     |#  #|    x87       |#
  (:call .      #xe8) (:jmp .     #xe9)  #| 32bit mode |#  (:jmp .       #xeb) (:in .        #xec) (:in .        #xed) (:out .     #xee) (:out .       #xef)
  (:clc .       #xf8) (:stc .     #xf9) (:cli .      #xfa) (:sti .       #xfb) (:cld .       #xfc) (:std .       #xfd)  #| 64bit mode|#   #|   grp5      |#)
  
(define-attribute-set :opcode-longmode
   #|  .........           .......           ........  |#  (:movsxd .    #x63)) #|  .........           .........           .......           .........  |#

(define-attribute-set :opcode-shortmode
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-es . #x06) (:pop-es .    #x07)
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ss . #x16) (:pop-ss .    #x17)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:daa .       #x27)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aaa .       #x37)
  (:inc .       #x40) (:inc .     #x41) (:inc .      #x42) (:inc .       #x43) (:inc .       #x44) (:inc .       #x45) (:inc .     #x46) (:inc .       #x47)
  (:pusha/d .   #x60) (:popa/d .  #x61) (:bound .    #x62) (:arpl .      #x63)  #|  .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:les .       #xc4) (:lds .       #xc5)  #|  .......           .........  |#
   #|  .........           .......           ........           .........  |#  (:aam .       #xd4) (:aad .       #xd5) (:salc .    #xd6)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-cs . #x0e)  #|  .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:push-ds . #x1e) (:pop-ds .    #x1f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:das .       #x2f)
   #|  .........           .......           ........           .........           .........           .........           .......  |#  (:aas .       #x3f)
  (:dec .       #x48) (:dec .     #x49) (:dec .      #x4a) (:dec .       #x4b) (:dec .       #x4c) (:dec .       #x4d) (:dec .     #x4e) (:dec .       #x4f)
   #|  .........           .......  |#  (:call .     #x9a)  #|  .........           .........           .........           .......           .........  |#
   #|  .........           .......           ........           .........           .........           .........  |#  (:into .    #xce)  #|  .........  |#
   #|  .........           .......  |#  (:jmp .      #xea)  #|  .........           .........           .........           .......           .........  |#)

(define-attribute-set :opcode-ext
   #|    grp6               grp7      |#  (:lar .       #x02) (:lsl .      #x03)  #|   invalid  |#  (:syscall .  #x05) (:clts .    #x06) (:sysret .   #x07)
  ;; 1[0-7]: prefixed
  (:mov .       #x20) (:mov .       #x21) (:mov .       #x22) (:mov .      #x23)  #|   invalid  |#   #|   invalid  |#   #|   invalid |#   #|   invalid  |#
  (:wrmsr .     #x30) (:rstsc .     #x31) (:rdmsr .     #x32) (:rdpmc .    #x33)  #| 32bit mode |#   #| 32bit mode |#   #|   invalid |#   #|   invalid  |#
  (:cmovo .     #x40) (:cmovno .    #x41) (:cmovb .     #x42) (:cmovnb .   #x43) (:cmovz .    #x44) (:cmovnz .   #x45) (:cmovbe .  #x46) (:cmovnbe .  #x47)
  ;; 5[0-7]: prefixed
  ;; 6[0-7]: prefixed
  ;; 7[0-7]: prefixed
  (:jo .        #x80) (:jno .       #x81) (:jb .        #x82) (:jnb .      #x83) (:jz .       #x84) (:jnz .      #x85) (:jbe .     #x86) (:jnbe .     #x87)
  (:seto .      #x90) (:setno .     #x91) (:setb .      #x92) (:setnb .    #x93) (:setz .     #x94) (:setnz .    #x95) (:setbe .   #x96) (:setnbe .   #x97)
  (:push .      #xa0) (:pop .       #xa1) (:cpuid .     #xa2) (:bt .       #xa3) (:shld .     #xa4) (:shld .     #xa5)  #|   invalid |#   #|   invalid  |#
  (:cmpxchg .   #xb0) (:cmpxchg .   #xb1) (:lss .       #xb2) (:btr .      #xb3) (:lfs .      #xb4) (:lgs .      #xb5) (:movzx .   #xb6) (:movzx .    #xb7)
  ;; c[0-7]: prefixed
  ;; d[0-7]: prefixed
  ;; e[0-7]: prefixed
  ;; f[0-7]: prefixed
  (:invd .      #x08) (:wbinvd .    #x09)  #|   invalid   |#  (:ud2 .      #x0b)  #|   invalid  |#   #|   grp p    |#  (:femms .   #x0e)  #|   3dnow    |#
   #| modrm group |#  (:nop .       #x19) (:nop .       #x1a) (:nop .      #x1b) (:nop .      #x1c) (:nop .      #x1d) (:nop .     #x1e) (:nop .      #x1f)
  ;; 2[8-f]: prefixed
  ;; 3[8-f]: invalid
  (:cmovs .     #x48) (:cmovns .    #x49) (:cmovp .     #x4a) (:cmovnp .   #x4b) (:cmovl .    #x4c) (:cmovnl .   #x4d) (:cmovle .  #x4e) (:cmovnle .  #x4f)
  ;; 5[8-f]: prefixed
  ;; 6[8-f]: prefixed
  ;; 7[8-f]: prefixed
  (:js .        #x88) (:jns .       #x89) (:jp .        #x8a) (:jnp .      #x8b) (:jl .       #x8c) (:jnl .      #x8d) (:jle .     #x8e) (:jnle .     #x8f)
  (:sets .      #x98) (:setns .     #x99) (:setp .      #x9a) (:setnp .    #x9b) (:setl .     #x9c) (:setnl .    #x9d) (:setle   . #x9e) (:setnle .   #x9f)
  (:push .      #xa8) (:pop .       #xa9) (:rsm .       #xaa) (:bts .      #xab) (:shrd .     #xac) (:shrd .     #xad) (:grp15-ae . #xae) (:imul .     #xaf)
  ;; b[8-f]: prefixed
  (:bswap .     #xc8) (:bswap .     #xc9) (:bswap .     #xca) (:bswap .    #xcb) (:bswap .    #xcc) (:bswap .    #xcd) (:bswap .   #xce) (:bswap .    #xcf)
  ;; d[8-f]: prefixed
  ;; e[8-f]: prefixed
  ;; f[8-f]: prefixed
  )

(define-attribute-set :opcode-ext-shortmode
  #|    .........           .........           .........            ........ |#  (:sysenter .  #x34) (:sysexit .  #x35)  #|   .......            ........ |#)

(define-attribute-set :opcode-ext-unprefixed
  (:movups .    #x10) (:movups .    #x11) (:movl/hlps . #x12) (:movlps .    #x13) (:unpcklps .  #x14) (:unpckhps . #x15) (:movh/lhps . #x16) (:movhps .  #x17)
  (:movmskps .  #x50) (:sqrtps .    #x51) (:rsqrtps .   #x52) (:rcpps .     #x53) (:andps .     #x54) (:andnps .   #x55) (:orps .     #x56) (:xorps .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .   #x64) (:pcmpgtw .  #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufw .    #x70)  #|   grp12     |#   #|   grp13     |#   #|   grp14     |#  (:pcmpeqb .   #x74) (:pcmpeqw .  #x75) (:pcmpeqd .  #x76) (:emss .     #x77)
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpps .     #xc2) (:movnti .    #xc3) (:pinsrw .    #xc4) (:pextsrw .  #xc5) (:shufps .   #xc6) (:grp9 .     #xc7)
   #|   invalid   |#  (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .     #xd4) (:pmullw .   #xd5)  #|   invalid  |#  (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .   #xe4) (:pmulhw .   #xe5)  #|   invalid  |#  (:movntq .   #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .   #xf4) (:pmaddwd .  #xf5) (:psadbw .   #xf6) (:maskmovq . #xf7)
  (:movaps .    #x28) (:movaps .    #x29) (:cvtpi2ps .  #x2a) (:movntps .   #x2b) (:cvttps2pi . #x2c) (:cvtps2pi . #x2d) (:ucomiss .  #x2e) (:comiss .   #x2f)
  (:addps .     #x58) (:mulps .     #x59) (:cvtps2pd .  #x5a) (:cvtdq2ps .  #x5b) (:subps .     #x5c) (:minps .    #x5d) (:divps .    #x5e) (:maxps .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b)  #|   invalid   |#   #|   invalid  |#  (:movd .     #x6e) (:movq .     #x6f)
   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movd .     #x7e) (:movq .     #x7f)
   #|   reserved  |#   #|   grp10     |#   #|   grp8      |#  (:btc .       #xbb) (:bsf .       #xbc) (:bsr .      #xbd) (:movsx .    #xbe) (:movsx .    #xbf)
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .   #xdc) (:paddusw .  #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .    #xec) (:paddsw .   #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .      #xfc) (:padw .     #xfd) (:padd .     #xfe)  #|   invalid  |#)

(define-attribute-set :opcode-ext-rep
  (:movss .     #x10) (:movss .     #x11) (:movsldup .  #x12)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movshdup . #x16)  #|   invalid  |#
   #|   invalid   |#  (:sqrtss .    #x51) (:rsqrtss .   #x52) (:rcpss .     #x53)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  (:pshufhw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpss .     #xc2)  #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:movq2dq .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#  (:cvtdq2pd . #xe6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#  (:cvtsi2ss .  #x2a) (:movntss .   #x2b) (:cvttss2si . #x2c) (:cvtss2si . #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addss .     #x58) (:mulss .     #x59) (:cvtss2sd .  #x5a) (:cvttps2dq . #x5b) (:subss .     #x5c) (:minss .    #x5d) (:divss .    #x5e) (:maxss .    #x5f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#   #|   invalid  |#  (:movdqu .   #x6f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid  |#  (:movq .     #x7e) (:movdqu .   #x7f)
  (:popcnt .    #xb8) #|    reserved  |#   #|   reserved  |#   #|   reserved  |#   #|   reserved  |#  (:lzcnt .    #xbd)  #|   reserved |#   #|   reserved |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|   invalid  |#
  )

(define-attribute-set :opcode-ext-opersz
  (:movupd .    #x10) (:movupd .    #x11) (:movlpd .    #x12) (:movlpd .    #x13) (:unpcklpd .   #x14) (:unpckhpd .   #x15) (:movhpd .   #x16) (:movhpd .   #x17)
  (:movmskpd .  #x50) (:sqrtpd .    #x51)  #|   invalid   |#   #|   invalid   |#  (:andpd .      #x54) (:andnpd .     #x55) (:orpd .     #x56) (:xorpd .    #x57)
  (:punpcklbw . #x60) (:punpcklwd . #x61) (:punpckldq . #x62) (:packsswb .  #x63) (:pcmpgtb .    #x64) (:pcmpgtw .    #x65) (:pcmpgtd .  #x66) (:packuswb . #x67)
  (:pshufd .    #x70)  #|   grp12     |#   #|   grp13     |#   #|   grp14     |#  (:pcmpeqb .    #x74) (:pcmpeqw .    #x75) (:pcmpeqd .  #x76)  #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmppd .     #xc2)  #|   invalid   |#  (:pinsrw .     #xc4) (:pextsrw .    #xc5) (:shufpd .   #xc6)  #|   invalid  |#
  (:addsubpd .  #xd0) (:psrlw .     #xd1) (:psrld .     #xd2) (:psrlq .     #xd3) (:paddq .      #xd4) (:pmullw .     #xd5) (:movq .     #xd6) (:pmovmskb . #xd7)
  (:pavgb .     #xe0) (:psraw .     #xe1) (:psrad .     #xe2) (:pavgw .     #xe3) (:pmulhuw .    #xe4) (:pmulhw .     #xe5) (:cvttpd2d . #xe6) (:movntdq .  #xe7)
   #|   invalid   |#  (:psllw .     #xf1) (:pslld .     #xf2) (:psllq .     #xf3) (:pmuludq .    #xf4) (:pmaddwd .    #xf5) (:psadbw .   #xf6) (:maskmovdqu . #xf7)
  (:movapd .    #x28) (:movapd .    #x29) (:cvtpi2pd .  #x2a) (:movntpd .   #x2b) (:cvttpd2pi .  #x2c) (:cvtpd2pi .   #x2d) (:ucomisd .  #x2e) (:comisd .   #x2f)
  (:addpd .     #x58) (:mulpd .     #x59) (:cvtpd2ps .  #x5a) (:cvtps2dq .  #x5b) (:subpd .      #x5c) (:minpd .      #x5d) (:divpd .    #x5e) (:maxpd .    #x5f)
  (:punpckhwb . #x68) (:punpckhwd . #x69) (:punpckhdq . #x6a) (:packssdw .  #x6b) (:punpcklqdq . #x6c) (:punpckhqdq . #x6d) (:movd .     #x6e) (:movdqa .   #x6f)
   #|   grp17     |#  (:extrq .     #x79)  #|   invalid   |#   #|   invalid   |#  (:haddpd .     #x7c) (:hsubpd .     #x7d)  (:movd .    #x7e) (:movdqa .   #x7f)
  ;; b[8-f]: strange irregularity (heh) -- absence..
  (:psubusb .   #xd8) (:psubusw .   #xd9) (:pminub .    #xda) (:pand .      #xdb) (:paddusb .    #xdc) (:paddusw .    #xdd) (:pmaxub .   #xde) (:pandn .    #xdf)
  (:psubsb .    #xe8) (:psubsw .    #xe9) (:pminsw .    #xea) (:por .       #xeb) (:paddsb .     #xec) (:paddsw .     #xed) (:pmaxsw .   #xee) (:pxor .     #xef)
  (:psubb .     #xf8) (:psubw .     #xf9) (:psubd .     #xfa) (:psubq .     #xfb) (:padb .       #xfc) (:padw .       #xfd) (:padd .     #xfe)  #|   invalid  |#)

(define-attribute-set :opcode-ext-repn
  (:movsd .     #x10) (:movsd .     #x11) (:movddup .   #x12)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  (:sqrtsd .    #x51)  #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:pshuflw .   #x70) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:xadd .      #xc0) (:xadd .      #xc1) (:cmpsd .     #xc2)  #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
  (:addsubps .  #xd0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:movdq2q .  #xd6)  #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#  (:cvtpd2dq . #xe6)  #|   invalid  |#
  (:lddqu .     #xf0) #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid    |#   #|   invalid    |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#   #|   invalid   |#  (:cvtsi2sd .  #x2a) (:movntsd .   #x2b) (:cvttsd2si .  #x2c) (:cvtsd2si .   #x2d)  #|   invalid  |#   #|   invalid  |#
  (:addsd .     #x58) (:mulsd .     #x59) (:cvtsd2ss .  #x5a)  #|   invalid   |#  (:subsd .      #x5c) (:minsd .      #x5d) (:divsd .    #x5e) (:maxsd .    #x5f)
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
  (:insertq .   #x78) (:insertq .   #x79)  #|   invalid   |#   #|   invalid   |#  (:haddps .     #x5c) (:hsubps .     #x5d)  #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#
   #|   invalid   |#  #|    invalid   |#   #|   invalid   |#   #|   invalid   |#   #|   invalid   |#   #|  invalid      |#   #|   invalid  |#   #|   invalid  |#)

(define-attribute-set :grp1-80
  (:add .  (#x80 0)) (:or .     (#x80 1)) (:adc .  (#x80 2)) (:sbb .  (#x80 3)) (:and .  (#x80 4)) (:sub . (#x80 5)) (:xor .   (#x80 6)) (:cmp .    (#x80 7)))
(define-attribute-set :grp1-81
  (:add .  (#x81 0)) (:or .     (#x81 1)) (:adc .  (#x81 2)) (:sbb .  (#x81 3)) (:and .  (#x81 4)) (:sub . (#x81 5)) (:xor .   (#x81 6)) (:cmp .    (#x81 7)))
(define-attribute-set :grp1-82-shortmode
  (:add .  (#x82 0)) (:or .     (#x82 1)) (:adc .  (#x82 2)) (:sbb .  (#x82 3)) (:and .  (#x82 4)) (:sub . (#x82 5)) (:xor .   (#x82 6)) (:cmp .    (#x82 7)))
(define-attribute-set :grp1-83
  (:add .  (#x83 0)) (:or .     (#x83 1)) (:adc .  (#x83 2)) (:sbb .  (#x83 3)) (:and .  (#x83 4)) (:sub . (#x83 5)) (:xor .   (#x83 6)) (:cmp .    (#x83 7)))
(define-attribute-set :grp1-8f
  (:pop .     #x08f)  #|   invalid    |#   #|   invalid  |#   #|   invalid  |#   #|   invalid  |#   #| invalid   |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp2-c0
  (:rol .     #x0c0) (:ror .       #x1c0) (:rcl .     #x2c0) (:rcr .     #x3c0) (:shl/sal . #x4c0) (:shr .    #x5c0) (:shl/sal .  #x6c0) (:sar .       #x7c0))
(define-attribute-set :grp2-c1
  (:rol .     #x0c1) (:ror .       #x1c1) (:rcl .     #x2c1) (:rcr .     #x3c1) (:shl/sal . #x4c1) (:shr .    #x5c1) (:shl/sal .  #x6c1) (:sar .       #x7c1))
(define-attribute-set :grp2-d0
  (:rol .     #x0d0) (:ror .       #x1d0) (:rcl .     #x2d0) (:rcr .     #x3d0) (:shl/sal . #x4d0) (:shr .    #x5d0) (:shl/sal .  #x6d0) (:sar .       #x7d0))
(define-attribute-set :grp2-d1                                                                                              
  (:rol .     #x0d1) (:ror .       #x1d1) (:rcl .     #x2d1) (:rcr .     #x3d1) (:shl/sal . #x4d1) (:shr .    #x5d1) (:shl/sal .  #x6d1) (:sar .       #x7d1))
(define-attribute-set :grp2-d2                                                                                              
  (:rol .     #x0d2) (:ror .       #x1d2) (:rcl .     #x2d2) (:rcr .     #x3d2) (:shl/sal . #x4d2) (:shr .    #x5d2) (:shl/sal .  #x6d2) (:sar .       #x7d2))
(define-attribute-set :grp2-d3                                                                                              
  (:rol .     #x0d3) (:ror .       #x1d3) (:rcl .     #x2d3) (:rcr .     #x3d3) (:shl/sal . #x4d3) (:shr .    #x5d3) (:shl/sal .  #x6d3) (:sar .       #x7d3))
(define-attribute-set :grp3-f6
  (:test .    #x0f6) (:test .      #x1f6) (:not .     #x2f6) (:neg .     #x3f6) (:mul .     #x4f6) (:imul .   #x5f6) (:div .      #x6f6) (:idiv .      #x7f6))
(define-attribute-set :grp3-f7
  (:test .    #x0f7) (:test .      #x1f7) (:not .     #x2f7) (:neg .     #x3f7) (:mul .     #x4f7) (:imul .   #x5f7) (:div .      #x6f7) (:idiv .      #x7f7))
(define-attribute-set :grp4-fe
  (:inc .     #x0fe) (:dec .       #x1fe)  #|   invalid  |#   #|   invalid  |#   #|   invalid  |#   #| invalid   |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp5-ff
  (:inc .     #x0ff) (:dec .       #x1ff) (:call .    #x2ff) (:call .    #x3ff) (:jmp .     #x4ff) (:jmp .    #x5ff) (:push .     #x6ff)  #|   invalid    |#)
(define-attribute-set :grp6-0f-00
  (:sldt .    #x000) (:str .       #x100) (:lldt .    #x200) (:ltr .     #x300) (:verr .    #x400) (:verw .   #x500)  #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp7-0f-01
  (:sgdt .    #x001)  #|     mod      |#  (:lgdt .    #x201)  #|    mod     |#  (:smsw .    #x401)  #| invalid   |#  (:lmsw .     #x601)  #|     mod      |#)

;; extension by mod00 renders them, opcodes, unchanged
(define-attribute-set :grp7-0f-01-1-0
  (:sidt .    #x101))
(define-attribute-set :grp7-0f-01-3-0
  (:lidt .    #x301))
(define-attribute-set :grp7-0f-01-7-0
  (:invlpg .  #x701))

;; mod11, and three r/m bits
(define-attribute-set :grp7-0f-01-1-3
  (:swapgs .  #x1901) (:rdtscp .  #x5901))
(define-attribute-set :grp7-0f-01-3-3
  (:vmrun .   #x1b01) (:vmmcall . #x5b01) (:vmload . #x9b01) (:vmsave . #xdb01) (:stgi .  #x11b01) (:clgi . #x15b01) (:skinit . #x19b01) (:invlpga . #x1db01))
(define-attribute-set :grp7-0f-01-7-3
  (:monitor . #x1f01) (:mwait .   #x5f01))

(define-attribute-set :grp8-0f-ba
   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#  (:bt .   (#xba 4)) (:bts . (#xba 5)) (:btr .   (#xba 6)) (:btc .    (#xba 7)))
(define-attribute-set :grp9-0f-c7 
   #|   invalid  |# (:cmpxchg8/16b . #x1c7) #|  invalid  |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp10-0f-b9
   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#) ;; what a genius plan...
(define-attribute-set :grp11-c6
  (:mov .      #x0c6)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp11-c7
  (:mov .      #x0c7)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grp12-0f-71
   #|   invalid   |#   #|   invalid   |#  (:psrlw .   #x271)  #|   invalid  |#  (:psraw .   #x471)  #|  invalid  |#  (:psllw .    #x671)  #|   invalid    |#)
(define-attribute-set :grp12-0f-71-op
   #|   invalid   |#   #|   invalid   |#  (:psrlw .   #x271)  #|   invalid  |#  (:psraw .   #x471)  #|  invalid  |#  (:psllw .    #x671)  #|   invalid    |#)
(define-attribute-set :grp13-0f-72
   #|   invalid   |#   #|   invalid   |#  (:psrld .   #x272)  #|   invalid  |#  (:psrad .   #x472)  #|  invalid  |#  (:pslld .    #x672)  #|   invalid    |#)
(define-attribute-set :grp13-0f-72-op
   #|   invalid   |#   #|   invalid   |#  (:psrld .   #x272)  #|   invalid  |#  (:psrad .   #x472)  #|  invalid  |#  (:pslld .    #x672)  #|   invalid    |#)
(define-attribute-set :grp14-0f-73
   #|   invalid   |#   #|   invalid   |#  (:psrlq .   #x273)  #|   invalid  |#   #|  invalid   |#   #|  invalid  |#  (:psllq .    #x673)  #|   invalid    |#)
(define-attribute-set :grp14-0f-73-op
   #|   invalid   |#   #|   invalid   |#  (:psrlq .   #x273) (:psrldq .  #x373)  #|  invalid   |#   #|  invalid  |#  (:psllq .    #x673) (:pslldq .    #x773))
(define-attribute-set :grp15-0f-ae
  (:fxsave .   #x0ae) (:fxrstor .  #x1ae) (:ldmxcsr . #x2ae) (:stmxcsr . #x3ae)  #|  invalid   |#   #|    mod    |#   #|     mod     |#   #|     mod      |#)

;; extend opcode by two mod bits
;;        mod00              mod11
(define-attribute-set :grp15-0f-ae-5
                      (:mfence .  #x1dae))
(define-attribute-set :grp15-0f-ae-6
                      (:lfence .  #x1eae))
(define-attribute-set :grp15-0f-ae-7
  (:clflush .  #x7ae) (:sfence .  #x1fae))

(define-attribute-set :grp16-0f-18
  (:prefetch .   #x0) (:prefetch .   #x1) (:prefetch .  #x2) (:prefetch .  #x3) (:nop .       #x4) (:nop .      #x5) (:nop .        #x6) (:nop .         #x7))
(define-attribute-set :grp17-0f-78-op
  (:extrq .      #x0)  #|   invalid   |#   #|  invalid   |#   #|   invalid  |#   #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)
(define-attribute-set :grpp-0f-0d
  (:prefetch .   #x0) (:prefetch .   #x1)  #|  reserved  |#  (:prefetch .  #x3)  #|  invalid   |#   #|  invalid  |#   #|   invalid   |#   #|   invalid    |#)


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

(define-subcontainer insn-format             :type instruction-format :container-slot id->format :if-exists :continue)
(define-subcontainer op/code-insn-format     :type instruction-format :container-slot op/code->format :if-exists :continue)
(define-subcontainer op/arglist-insn-formats :type list               :container-slot op/arglist->formats :if-exists :continue :if-does-not-exist :continue)

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
            (setf (op/code-insn-format isa (cons op code)) f)
            (push f (op/arglist-insn-formats isa (cons op arglist))))
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

(defiformat "<>AL"              () (rw :rflags rw :al)                                  (:aaa #x37     :aas #x3f     :daa #x27     :das #x2f))
(defiformat "<AL, AH, imm8"     () ( w :rflags rw :al   r  :ah  r (:imm8))              (:aad #xd5))
(defiformat "<2|2!AL, AH, imm8" () ( w :rflags rw :al    w :ah  r (:imm8))              (:aam #xd4))
                                                                                           
(defiformat "<AL, imm8"         () ( w :rflags rw (:al)  r  (:imm8))                    (:add #x04     :adc #x14     :sbb #x1c     :sub #x2c))
(defiformat "<XAX, immXX"       () ( w :rflags rw (:xax) r  (:immx))                    (:add #x05     :adc #x15     :sbb #x1d     :sub #x2d))
(defiformat "<reg/mem8, imm8"   () ( w :rflags rw ((8 :basereg))        r  (:imm8))     (:add #x80 0 0 :adc #x80 2 0 :sbb #x80 3 0 :sub #x80 5 0))
(defiformat "<reg/mem8, imm8"   () ( w :rflags rw ((8 :basereg :imm8))  r  (:imm8))     (:add #x80 0 1 :adc #x80 2 1 :sbb #x80 3 1 :sub #x80 5 1))
(defiformat "<reg/mem8, imm8"   () ( w :rflags rw ((8 :basereg :imm32)) r  (:imm8))     (:add #x80 0 2 :adc #x80 2 2 :sbb #x80 3 2 :sub #x80 5 2))
(defiformat "<reg/mem8, imm8"   () ( w :rflags rw (:reg8)               r  (:imm8))     (:add #x80 0 3 :adc #x80 2 3 :sbb #x80 3 3 :sub #x80 5 3))
(defiformat "<reg/memXX, immXX" () ( w :rflags rw ((x :basereg))        r  (:immx))     (:add #x81 0 0 :adc #x81 2 0 :sbb #x81 3 0 :sub #x81 5 0))
(defiformat "<reg/memXX, immXX" () ( w :rflags rw ((x :basereg :imm8))  r  (:immx))     (:add #x81 0 1 :adc #x81 2 1 :sbb #x81 3 1 :sub #x81 5 1))
(defiformat "<reg/memXX, immXX" () ( w :rflags rw ((x :basereg :imm32)) r  (:immx))     (:add #x81 0 2 :adc #x81 2 2 :sbb #x81 3 2 :sub #x81 5 2))
(defiformat "<reg/memXX, immXX" () ( w :rflags rw (:regx)               r  (:immx))     (:add #x81 0 3 :adc #x81 2 3 :sbb #x81 3 3 :sub #x81 5 3))
(defiformat "<reg/memXX, imm8"  () ( w :rflags rw ((x :basereg))        r  (:imm8))     (:add #x83 0 0 :adc #x83 2 0 :sbb #x83 3 0 :sub #x83 5 0 :bts #xba 5 0 :btr #xba 6 0 :btc #xba 7 0))
(defiformat "<reg/memXX, imm8"  () ( w :rflags rw ((x :basereg :imm8))  r  (:imm8))     (:add #x83 0 1 :adc #x83 2 1 :sbb #x83 3 1 :sub #x83 5 1 :bts #xba 5 1 :btr #xba 6 1 :btc #xba 7 1))
(defiformat "<reg/memXX, imm8"  () ( w :rflags rw ((x :basereg :imm32)) r  (:imm8))     (:add #x83 0 2 :adc #x83 2 2 :sbb #x83 3 2 :sub #x83 5 2 :bts #xba 5 2 :btr #xba 6 2 :btc #xba 7 2))
(defiformat "<reg/memXX, imm8"  () ( w :rflags rw (:regx)               r  (:imm8))     (:add #x83 0 3 :adc #x83 2 3 :sbb #x83 3 3 :sub #x83 5 3 :bts #xba 5 3 :btr #xba 6 3 :btc #xba 7 3))
(defiformat "<reg/mem8, reg8"   () ( w :rflags rw ((8 :basereg))        r  (:reg8))     (:add #x00 0 :adc #x10 0 :sbb #x18 0 :sub #x28 0))
(defiformat "<reg/mem8, reg8"   () ( w :rflags rw ((8 :basereg :imm8))  r  (:reg8))     (:add #x00 1 :adc #x10 1 :sbb #x18 1 :sub #x28 1))
(defiformat "<reg/mem8, reg8"   () ( w :rflags rw ((8 :basereg :imm32)) r  (:reg8))     (:add #x00 2 :adc #x10 2 :sbb #x18 2 :sub #x28 2))
(defiformat "<reg/mem8, reg8"   () ( w :rflags rw (:reg8)               r  (:reg8))     (:add #x00 3 :adc #x10 3 :sbb #x18 3 :sub #x28 3))
(defiformat "<reg/memXX, regXX" () ( w :rflags rw ((x :basereg))        r  (:regx))     (:add #x01 0 :adc #x11 0 :sbb #x19 0 :sub #x29 0 :bts #xab 0 :btr #xb3 0 :btc #xbb 0))
(defiformat "<reg/memXX, regXX" () ( w :rflags rw ((x :basereg :imm8))  r  (:regx))     (:add #x01 1 :adc #x11 1 :sbb #x19 1 :sub #x29 1 :bts #xab 1 :btr #xb3 1 :btc #xbb 1))
(defiformat "<reg/memXX, regXX" () ( w :rflags rw ((x :basereg :imm32)) r  (:regx))     (:add #x01 2 :adc #x11 2 :sbb #x19 2 :sub #x29 2 :bts #xab 2 :btr #xb3 2 :btc #xbb 2))
(defiformat "<reg/memXX, regXX" () ( w :rflags rw (:regx) r  (:regx))                   (:add #x01 3 :adc #x11 3 :sbb #x19 3 :sub #x29 3 :bts #xab 3 :btr #xb3 3 :btc #xbb 3))
(defiformat "<reg8, reg/mem8"   () ( w :rflags rw (:reg8) r  ((8 :basereg)))            (:add #x02 0 :adc #x12 0 :sbb #x1a 0 :sub #x2a 0))
(defiformat "<reg8, reg/mem8"   () ( w :rflags rw (:reg8) r  ((8 :basereg :imm8)))      (:add #x02 1 :adc #x12 1 :sbb #x1a 1 :sub #x2a 1))
(defiformat "<reg8, reg/mem8"   () ( w :rflags rw (:reg8) r  ((8 :basereg :imm32)))     (:add #x02 2 :adc #x12 2 :sbb #x1a 2 :sub #x2a 2))
(defiformat "<reg8, reg/mem8"   () ( w :rflags rw (:reg8) r  (:reg8))                   (:add #x02 3 :adc #x12 3 :sbb #x1a 3 :sub #x2a 3))
(defiformat "<reg8, reg/memXX"  () ( w :rflags rw (:reg8) r  ((x :basereg)))            (:add #x03 0 :adc #x13 0 :sbb #x1b 0 :sub #x2b 0))
(defiformat "<reg8, reg/memXX"  () ( w :rflags rw (:reg8) r  ((x :basereg :imm8)))      (:add #x03 1 :adc #x13 1 :sbb #x1b 1 :sub #x2b 1))
(defiformat "<reg8, reg/memXX"  () ( w :rflags rw (:reg8) r  ((x :basereg :imm32)))     (:add #x03 2 :adc #x13 2 :sbb #x1b 2 :sub #x2b 2))
(defiformat "<reg8, reg/memXX"  () ( w :rflags rw (:reg8) r  (:regx))                   (:add #x03 3 :adc #x13 3 :sbb #x1b 3 :sub #x2b 3))
                                                                                                                  
(defiformat "AL, imm8"          () (rw (:al)                 r  (:imm8))                (:or #x0c)   (:and #x24)  (:xor #x34))
(defiformat "XAX, immXX"        () (rw (:xax)                r  (:immx))                (:or #x0d)   (:and #x25)  (:xor #x35))
(defiformat "reg/mem8, imm8"    () (rw ((8 :basereg))        r  (:imm8))                (:or #x80 1)  (:and #x80 4) (:xor #x80 6))
(defiformat "reg/mem8, imm8"    () (rw ((8 :basereg :imm8))  r  (:imm8))                (:or #x80 1)  (:and #x80 4) (:xor #x80 6))
(defiformat "reg/mem8, imm8"    () (rw ((8 :basereg :imm32)) r  (:imm8))                (:or #x80 1)  (:and #x80 4) (:xor #x80 6))
(defiformat "reg/mem8, imm8"    () (rw (:reg8)               r  (:imm8))                (:or #x80 1)  (:and #x80 4) (:xor #x80 6))
(defiformat "reg/memXX, immXX"  () (rw ((x :basereg))        r  (:immx))                (:or #x81 1)  (:and #x81 4) (:xor #x81 6))
(defiformat "reg/memXX, immXX"  () (rw ((x :basereg :imm8))  r  (:immx))                (:or #x81 1)  (:and #x81 4) (:xor #x81 6))
(defiformat "reg/memXX, immXX"  () (rw ((x :basereg :imm32)) r  (:immx))                (:or #x81 1)  (:and #x81 4) (:xor #x81 6))
(defiformat "reg/memXX, immXX"  () (rw (:regx)               r  (:immx))                (:or #x81 1)  (:and #x81 4) (:xor #x81 6))
(defiformat "reg/memXX, imm8"   () (rw ((x :basereg))        r  (:imm8))                (:or #x83 1)  (:and #x83 4) (:xor #x83 6))
(defiformat "reg/memXX, imm8"   () (rw ((x :basereg :imm8))  r  (:imm8))                (:or #x83 1)  (:and #x83 4) (:xor #x83 6))
(defiformat "reg/memXX, imm8"   () (rw ((x :basereg :imm32)) r  (:imm8))                (:or #x83 1)  (:and #x83 4) (:xor #x83 6))
(defiformat "reg/memXX, imm8"   () (rw (:regx)               r  (:imm8))                (:or #x83 1)  (:and #x83 4) (:xor #x83 6))
(defiformat "reg/mem8, reg8"    () (rw ((8 :basereg))        r  (:reg8))                (:or #x08)   (:and #x20)  (:xor #x30))
(defiformat "reg/mem8, reg8"    () (rw ((8 :basereg :imm8))  r  (:reg8))                (:or #x08)   (:and #x20)  (:xor #x30))
(defiformat "reg/mem8, reg8"    () (rw ((8 :basereg :imm32)) r  (:reg8))                (:or #x08)   (:and #x20)  (:xor #x30))
(defiformat "reg/mem8, reg8"    () (rw (:reg8)               r  (:reg8))                (:or #x08)   (:and #x20)  (:xor #x30))
(defiformat "reg/memXX, regXX"  () (rw ((x :basereg))        r  (:regx))                (:or #x09)   (:and #x21)  (:xor #x31))
(defiformat "reg/memXX, regXX"  () (rw ((x :basereg :imm8))  r  (:regx))                (:or #x09)   (:and #x21)  (:xor #x31))
(defiformat "reg/memXX, regXX"  () (rw ((x :basereg :imm32)) r  (:regx))                (:or #x09)   (:and #x21)  (:xor #x31))
(defiformat "reg/memXX, regXX"  () (rw (:reg)                r  (:regx))                (:or #x09)   (:and #x21)  (:xor #x31))
(defiformat "reg8, reg/mem8"    () (rw (:reg8)     r  ((8 :basereg)))                   (:or #x0a)   (:and #x22)  (:xor #x32))
(defiformat "reg8, reg/mem8"    () (rw (:reg8)     r  ((8 :basereg :imm8)))             (:or #x0a)   (:and #x22)  (:xor #x32))
(defiformat "reg8, reg/mem8"    () (rw (:reg8)     r  ((8 :basereg :imm32)))            (:or #x0a)   (:and #x22)  (:xor #x32))
(defiformat "reg8, reg/mem8"    () (rw (:reg8)     r  (:reg8))                          (:or #x0a)   (:and #x22)  (:xor #x32))
(defiformat "regXX, reg/memXX"  () (rw (:regx)     r  ((x :basereg)))                   (:or #x0b)   (:and #x23)  (:xor #x33))
(defiformat "regXX, reg/memXX"  () (rw (:regx)     r  ((x :basereg :imm8)))             (:or #x0b)   (:and #x23)  (:xor #x33))
(defiformat "regXX, reg/memXX"  () (rw (:regx)     r  ((x :basereg :imm32)))            (:or #x0b)   (:and #x23)  (:xor #x33))
(defiformat "regXX, reg/memXX"  () (rw (:regx)     r  (:regx))                          (:or #x0b)   (:and #x23)  (:xor #x33))
                                                                                                            
(defiformat ">!reg/mem8"        () (rw ((8 :basereg))        r  :rflags)               (:seto  #x90 0) (:setno  #x91 0) (:setc   #x92 0) (:setnc  #x93 0)
                                                                                               (:setz  #x94 0) (:setnz  #x95 0) (:setna  #x96 0) (:seta   #x97 0)
                                                                                               (:sets  #x98 0) (:setns  #x99 0) (:setp   #x9a 0) (:setnp  #x9b 0)
                                                                                               (:setl  #x9c 0) (:setnl  #x9d 0) (:setng  #x9e 0) (:setg   #x9f 0))
(defiformat ">!reg/mem8"        () (rw ((8 :basereg :imm8))  r  :rflags)               (:seto  #x90 1) (:setno  #x91 1) (:setc   #x92 1) (:setnc  #x93 1)
                                                                                               (:setz  #x94 1) (:setnz  #x95 1) (:setna  #x96 1) (:seta   #x97 1)
                                                                                               (:sets  #x98 1) (:setns  #x99 1) (:setp   #x9a 1) (:setnp  #x9b 1)
                                                                                               (:setl  #x9c 1) (:setnl  #x9d 1) (:setng  #x9e 1) (:setg   #x9f 1))
(defiformat ">!reg/mem8"        () (rw ((8 :basereg :imm32)) r  :rflags)               (:seto  #x90 2) (:setno  #x91 2) (:setc   #x92 2) (:setnc  #x93 2)
                                                                                               (:setz  #x94 2) (:setnz  #x95 2) (:setna  #x96 2) (:seta   #x97 2)
                                                                                               (:sets  #x98 2) (:setns  #x99 2) (:setp   #x9a 2) (:setnp  #x9b 2)
                                                                                               (:setl  #x9c 2) (:setnl  #x9d 2) (:setng  #x9e 2) (:setg   #x9f 2))
(defiformat ">!reg/mem8"        () (rw (:reg8)                       r  :rflags)               (:seto  #x90 3) (:setno  #x91 3) (:setc   #x92 3) (:setnc  #x93 3)
                                                                                               (:setz  #x94 3) (:setnz  #x95 3) (:setna  #x96 3) (:seta   #x97 3)
                                                                                               (:sets  #x98 3) (:setns  #x99 3) (:setp   #x9a 3) (:setnp  #x9b 3)
                                                                                               (:setl  #x9c 3) (:setnl  #x9d 3) (:setng  #x9e 3) (:setg   #x9f 3))

(defiformat ">regXX, reg/memXX" () (rw (:regx)     r  ((x :basereg)) r :rflags)        (:cmovo #x40 0) (:cmovno #x41 0) (:cmovc  #x42 0) (:cmovnc #x43 0)
                                                                                               (:cmovz #x44 0) (:cmovnz #x45 0) (:cmovna #x46 0) (:cmova  #x47 0)
                                                                                               (:cmovs #x48 0) (:cmovns #x49 0) (:cmovp  #x4a 0) (:cmovnp #x4b 0)
                                                                                               (:cmovl #x4c 0) (:cmovnl #x4d 0) (:cmovng #x4e 0) (:cmovg  #x4f 0))
(defiformat ">regXX, reg/memXX" () (rw (:regx)     r  ((x :basereg :imm8)) r :rflags)  (:cmovo #x40 1) (:cmovno #x41 1) (:cmovc  #x42 1) (:cmovnc #x43 1)
                                                                                               (:cmovz #x44 1) (:cmovnz #x45 1) (:cmovna #x46 1) (:cmova  #x47 1)
                                                                                               (:cmovs #x48 1) (:cmovns #x49 1) (:cmovp  #x4a 1) (:cmovnp #x4b 1)
                                                                                               (:cmovl #x4c 1) (:cmovnl #x4d 1) (:cmovng #x4e 1) (:cmovg  #x4f 1))
(defiformat ">regXX, reg/memXX" () (rw (:regx)     r  ((x :basereg :imm32)) r :rflags) (:cmovo #x40 2) (:cmovno #x41 2) (:cmovc  #x42 2) (:cmovnc #x43 2)
                                                                                               (:cmovz #x44 2) (:cmovnz #x45 2) (:cmovna #x46 2) (:cmova  #x47 2)
                                                                                               (:cmovs #x48 2) (:cmovns #x49 2) (:cmovp  #x4a 2) (:cmovnp #x4b 2)
                                                                                               (:cmovl #x4c 2) (:cmovnl #x4d 2) (:cmovng #x4e 2) (:cmovg  #x4f 2))
(defiformat ">regXX, reg/memXX" () (rw (:regx)     r  (:regx) r :rflags)                       (:cmovo #x40 3) (:cmovno #x41 3) (:cmovc  #x42 3) (:cmovnc #x43 3)
                                                                                               (:cmovz #x44 3) (:cmovnz #x45 3) (:cmovna #x46 3) (:cmova  #x47 3)
                                                                                               (:cmovs #x48 3) (:cmovns #x49 3) (:cmovp  #x4a 3) (:cmovnp #x4b 3)
                                                                                               (:cmovl #x4c 3) (:cmovnl #x4d 3) (:cmovng #x4e 3) (:cmovg  #x4f 3))

;; (defiformat "<|AL, imm8"             (:rflags)                        (:al :imm8))                                   ;; CMP, TEST
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
