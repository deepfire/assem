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
   (id->format                             :initarg :id->format)
   (op/code->format                        :initarg :op/code->format)
   (op/arglist->formats                    :initarg :op/arglist->formats)
   (id->correspondence                     :initarg :id->correspondence))
  (:default-initargs
   :id->attrset         (make-hash-table :test 'eq)
   :id->argtype         (make-hash-table :test 'eq)
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

(defstruct (attribute-set (:conc-name attrset-))
  (name nil :type symbol :read-only t)
  (key->value (make-hash-table :test 'eq) :type hash-table)
  (value->key (make-hash-table :test 'eq) :type hash-table))

(define-subcontainer attrset :type attribute-set :container-slot id->attrset :if-exists :continue)

(define-subcontainer value :type unsigned-byte :container-slot key->value :if-exists :continue)
(define-subcontainer key   :type symbol        :container-slot value->key :if-exists :continue)

(defun ensure-attribute-set (isa name key/value-pairs)
  (let ((a (make-attribute-set :name name)))
    (iter (for (key . value) in key/value-pairs)
          (setf (value a key) value
                (key a value) key))
    (setf (attrset isa name) a)))

(defmacro define-attribute-set (name &body attrset-spec)
  `(ensure-attribute-set *isa* ,name '(,@attrset-spec)))

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
(define-attribute-set :rex-w
  (nil . #b0) (:w . #b1))
(define-attribute-set :rex-r
  (nil . #b0) (:r . #b1))
(define-attribute-set :rex-x
  (nil . #b0) (:x . #b1))
(define-attribute-set :rex-b
  (nil . #b0) (:b . #b1))
(define-attribute-set :xop
  (:xop .           #x0f))
(define-attribute-set :3dnow
  (:3dnow .         #x0f))

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
    (unless (every #'argtype-elementp elements)
      (error "~@<in ENSURE-ARGUMENT-TYPE-SET: set elements must be actually elements.~:@>"))
    (when (some #'argtype-immediatep elements)
      (error "~@<in ENSURE-ARGUMENT-TYPE-SET: set elements cannot be immediate.~:@>"))
    (unless (or (not width)
                (every (compose (curry #'= width) #'argtype-width) elements))
      (error "~@<in ENSURE-ARGUMENT-TYPE-SET: all set elements must have the same width: ~D bits.~:@>" width))
    (setf (argtype-set-childs a) elements
          (argtype isa name) a)))

(defmacro define-argument-types (() &body argtype-specs)
  `(iter (for (type width) in '(,@argtype-specs))
         (ensure-argument-type *isa* type nil t width)))

(defmacro define-immediate-argument-types (() &body argtype-specs)
  `(progn
     ,@(iter (for (name width) in argtype-specs)
             (collect `(ensure-argument-type *isa* ',name t t ,width)))))

(defmacro define-argument-type-physical-hierarchy (() argtype-spec-tree)
  `(ensure-argument-type-physical-tree *isa* ',argtype-spec-tree))

(defmacro define-argument-type-set (name width (&key register-members) &body element-names)
  `(ensure-argument-type-set *isa* ',name ,width '(,@element-names) ,register-members))

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
    :al :ah :bl :bh :cl :spl :bpl :sil :dil :ch :dl :dh :r9b :r10b :r11b :r12b :r13b :r14b :r15b)

(define-argument-type-set :reg16 16 ()
    :ax  :bx  :cx  :dx  :sp  :bp  :si  :di  :r9w :r10w :r11w :r12w :r13w :r14w :r15w)

(define-argument-type-set :reg32 32 ()
    :eax :ebx :ecx :edx :esp :ebp :esi :edi :r9d :r10d :r11d :r12d :r13d :r14d :r15d)

(define-argument-type-set :reg64 64 ()
    :rax :rbx :rcx :rdx :rsp :rbp :rsi :rdi :r9 :r10 :r11 :r12 :r13 :r14 :r15)

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
  `(ensure-argument/attribute-correspondence *isa* ,name '(,@corr-spec)))

(define-format-argument/attribute-correspondence :segreg-over ()
  (:es . :es) (:cs . :cs) (:ss . :ss) (:ds . :ds) (:fs . :fs) (:gs . :gs))

(define-format-argument/attribute-correspondence :reg/memx ()
  ((:opersz/p) .        :reg/mem16)
  (() .                 :reg/mem32)
  ((:rex-w :opersz/p) . :reg/mem64)
  ((:rex-w) .           :reg/mem64))

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
        (:rex (04 01 (:rex-w))
              (ban :rex :addrsz :segment :lock :opersz/p :rep/p :repn/p)
              (:rex-w (01 01) (:rex-r)
                      (:rex-r (01 01) (:rex-x)
                              (:rex-x (01 01) (:rex-b)
                                      (:rex-b (01 08) (:rex-b)
                                              ;; include keeps the declared window (01 08)
                                              (include :nrex))))))
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
               (#x80 (+ 03 03 (:grp1-80))
                     (:grp1-80 ()
                               (fetch 02 02)
                               (shift -6)))
               (#x81 (+ 03 03 (:grp1-81))
                     (:grp1-81 ()
                               (fetch 02 02)
                               (shift -6)))
               ,@(unless sixty-four-p
                  `((#x82 (+ 03 03 (:grp1-82-shortmode))
                          (:grp1-82-shortmode ()
                                              ))))
               (#x83 (+ 03 03 (:grp1-83))
                     (:grp1-83 ()
                               (fetch 02 02)
                               (shift -6)))
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
                     (#xba (+ 03 03 (:grp8-0f-ba))
                           (:grp8-0f-ba ()
                                        (fetch 02 02)
                                        (shift -6)))
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
  (:add    .  #x080) (:or .        #x180) (:adc .     #x280) (:sbb .     #x380) (:and .     #x480) (:sub .    #x580) (:xor .      #x680) (:cmp .       #x780))
(define-attribute-set :grp1-81
  (:add .     #x081) (:or .        #x181) (:adc .     #x281) (:sbb .     #x381) (:and .     #x481) (:sub .    #x581) (:xor .      #x681) (:cmp .       #x781))
(define-attribute-set :grp1-82-shortmode
  (:add .     #x082) (:or .        #x182) (:adc .     #x282) (:sbb .     #x382) (:and .     #x482) (:sub .    #x582) (:xor .      #x682) (:cmp .       #x782))
(define-attribute-set :grp1-83
  (:add .     #x083) (:or .        #x183) (:adc .     #x283) (:sbb .     #x383) (:and .     #x483) (:sub .    #x583) (:xor .      #x683) (:cmp .       #x783))
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
   #|   invalid   |#   #|   invalid   |#   #|  invalid   |#   #|   invalid  |#  (:bt .      #x4ba) (:bts .    #x5ba) (:btr .      #x6ba) (:btc .       #x7ba))
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

(defmacro define-instruction-format (id attributes argspec &body insn/opcode-specs)
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

(define-instruction-format "<>AL"              ()       (rw :rflags     rw :al)                                     (:aaa #x37)  (:aas #x3f)  (:daa #x27)  (:das #x2f))
(define-instruction-format "<AL, AH, imm8"     ()       ( w :rflags     rw :al         r  :ah         r (:imm8))    (:aad #xd5))
(define-instruction-format "<2|2!AL, AH, imm8" ()       ( w :rflags     rw :al          w :ah         r (:imm8))    (:aam #xd4))
                                                                                                                  
(define-instruction-format "<AL, imm8"         ()       ( w :rflags     rw (:al)       r  (:imm8))                  (:add #x04)  (:adc #x14)  (:sbb #x1c)  (:sub #x2c))
(define-instruction-format "<XAX, immXX"       ()       ( w :rflags     rw (:xax)      r  (:immx))                  (:add #x05)  (:adc #x15)  (:sbb #x1d)  (:sub #x2d))
(define-instruction-format "<reg/mem8, imm8"   (:modrm) ( w :rflags     rw (:reg/mem8) r  (:imm8))                  (:add #x080) (:adc #x280) (:sbb #x380) (:sub #x580))
(define-instruction-format "<reg/memXX, immXX" (:modrm) ( w :rflags     rw (:reg/memx) r  (:immx))                  (:add #x081) (:adc #x281) (:sbb #x381) (:sub #x581))
(define-instruction-format "<reg/memXX, imm8"  (:modrm) ( w :rflags     rw (:reg/memx) r  (:imm8))                  (:add #x083) (:adc #x283) (:sbb #x383) (:sub #x583) (:bts #x5ba) (:btr #x6ba) (:btc #x7ba))
(define-instruction-format "<reg/mem8, reg8"   (:modrm) ( w :rflags     rw (:reg/mem8) r  (:reg8))                  (:add #x00)  (:adc #x10)  (:sbb #x18)  (:sub #x28))
(define-instruction-format "<reg/memXX, regXX" (:modrm) ( w :rflags     rw (:reg/memx) r  (:regx))                  (:add #x01)  (:adc #x11)  (:sbb #x19)  (:sub #x29)  (:bts #xab)  (:btr #xb3)  (:btc #xbb))
(define-instruction-format "<reg8, reg/mem8"   (:modrm) ( w :rflags     rw (:reg8)     r  (:reg/mem8))              (:add #x02)  (:adc #x12)  (:sbb #x1a)  (:sub #x2a))
(define-instruction-format "<reg8, reg/memXX"  (:modrm) ( w :rflags     rw (:reg8)     r  (:reg/memx))              (:add #x03)  (:adc #x13)  (:sbb #x1b)  (:sub #x2b))
                                                                                                                  
(define-instruction-format "AL, imm8"          ()       (rw (:al)       r  (:imm8))                                 (:or #x0c)   (:and #x24)  (:xor #x34))
(define-instruction-format "XAX, immXX"        ()       (rw (:xax)      r  (:immx))                                 (:or #x0d)   (:and #x25)  (:xor #x35))
(define-instruction-format "reg/mem8, imm8"    (:modrm) (rw (:reg/mem8) r  (:imm8))                                 (:or #x180)  (:and #x480) (:xor #x680))
(define-instruction-format "reg/memXX, immXX"  (:modrm) (rw (:reg/memx) r  (:immx))                                 (:or #x181)  (:and #x481) (:xor #x681))
(define-instruction-format "reg/memXX, imm8"   (:modrm) (rw (:reg/memx) r  (:imm8))                                 (:or #x183)  (:and #x483) (:xor #x683))
(define-instruction-format "reg/mem8, reg8"    (:modrm) (rw (:reg/mem8) r  (:reg8))                                 (:or #x08)   (:and #x20)  (:xor #x30))
(define-instruction-format "reg/memXX, regXX"  (:modrm) (rw (:reg/memx) r  (:regx))                                 (:or #x09)   (:and #x21)  (:xor #x31))
(define-instruction-format "reg8, reg/mem8"    (:modrm) (rw (:reg8)     r  (:reg/mem8))                             (:or #x0a)   (:and #x22)  (:xor #x32))
(define-instruction-format "regXX, reg/memXX"  (:modrm) (rw (:regx)     r  (:reg/memx))                             (:or #x0b)   (:and #x23)  (:xor #x33))
                                                                                                                  
(define-instruction-format ">!reg/mem8"        (:modrm) (rw (:reg/mem8) r  :rflags)                                 (:seto  #x90) (:setno  #x91) (:setc   #x92) (:setnc  #x93)
                                                                                                                    (:setz  #x94) (:setnz  #x95) (:setna  #x96) (:seta   #x97)
                                                                                                                    (:sets  #x98) (:setns  #x99) (:setp   #x9a) (:setnp  #x9b)
                                                                                                                    (:setl  #x9c) (:setnl  #x9d) (:setng  #x9e) (:setg   #x9f))

(define-instruction-format ">regXX, reg/memXX" (:modrm) (rw (:regx)      r  (:reg/memx) r :rflags)                  (:cmovo #x40) (:cmovno #x41) (:cmovc  #x42) (:cmovnc #x43)
                                                                                                                    (:cmovz #x44) (:cmovnz #x45) (:cmovna #x46) (:cmova  #x47)
                                                                                                                    (:cmovs #x48) (:cmovns #x49) (:cmovp  #x4a) (:cmovnp #x4b)
                                                                                                                    (:cmovl #x4c) (:cmovnl #x4d) (:cmovng #x4e) (:cmovg  #x4f))

;; (define-instruction-format "<|AL, imm8"             (:rflags)                        (:al :imm8))                                   ;; CMP, TEST
;; (define-instruction-format "<|AX, imm16"            (:rflags)                        (:ax :imm16))                                  ;; CMP, TEST
;; (define-instruction-format "<|EAX, imm32"           (:rflags)                        (:eax :imm32))                                 ;; CMP, TEST
;; (define-instruction-format "<|RAX, imm32"           (:rflags)                        (:rax :imm32))                                 ;; CMP, TEST
;; (define-instruction-format "<|reg/mem8, imm8"       (:rflags)                        (:reg/mem8 :imm8))                             ;; CMP, TEST
;; (define-instruction-format "<|reg/mem16, imm16"     (:rflags)                        (:reg/mem16 :imm16))                           ;; CMP, TEST
;; (define-instruction-format "<|reg/mem32, imm32"     (:rflags)                        (:reg/mem32 :imm32))                           ;; CMP, TEST
;; (define-instruction-format "<|reg/mem64, imm32"     (:rflags)                        (:reg/mem64 :imm32))                           ;; CMP, TEST
;; (define-instruction-format "<|reg/mem16, imm8"      (:rflags)                        (:reg/mem16 :imm8))                            ;; CMP, BT
;; (define-instruction-format "<|reg/mem32, imm8"      (:rflags)                        (:reg/mem32 :imm8))                            ;; CMP, BT
;; (define-instruction-format "<|reg/mem64, imm8"      (:rflags)                        (:reg/mem64 :imm8))                            ;; CMP, BT
;; (define-instruction-format "<|reg/mem8, reg8"       (:rflags)                        (:reg/mem8 :reg8))                             ;; CMP, TEST
;; (define-instruction-format "<|reg/mem16, reg16"     (:rflags)                        (:reg/mem16 :reg16))                           ;; CMP, TEST, BT
;; (define-instruction-format "<|reg/mem32, reg32"     (:rflags)                        (:reg/mem32 :reg32))                           ;; CMP, TEST, BT
;; (define-instruction-format "<|reg/mem64, reg64"     (:rflags)                        (:reg/mem64 :reg64))                           ;; CMP, TEST, BT
;; (define-instruction-format "<|reg8, reg/mem8"       (:rflags)                        (:reg8 :reg/mem8))                             ;; CMP
;; (define-instruction-format "<|reg16, reg/mem16"     (:rflags)                        (:reg16 :reg/mem16))                           ;; CMP
;; (define-instruction-format "<|reg32, reg/mem32"     (:rflags)                        (:reg32 :reg/mem32))                           ;; CMP
;; (define-instruction-format "<|reg64, reg/mem64"     (:rflags)                        (:reg64 :reg/mem64))                           ;; CMP

;; (define-instruction-format "reg/mem8"               (:reg/mem8)                      (:reg/mem8))                                   ;; NOT
;; (define-instruction-format "reg/mem16"              (:reg/mem16)                     (:reg/mem16))                                  ;; NOT
;; (define-instruction-format "reg/mem32"              (:reg/mem32)                     (:reg/mem32))                                  ;; NOT
;; (define-instruction-format "reg/mem64"              (:reg/mem64)                     (:reg/mem64))                                  ;; NOT

;; (define-instruction-format "<reg/mem8"              (:rflags :reg/mem8)              (:reg/mem8))                                   ;; NEG, DEC, INC
;; (define-instruction-format "<reg/mem16"             (:rflags :reg/mem16)             (:reg/mem16))                                  ;; NEG, DEC, INC
;; (define-instruction-format "<reg/mem32"             (:rflags :reg/mem32)             (:reg/mem32))                                  ;; NEG, DEC, INC
;; (define-instruction-format "<reg/mem64"             (:rflags :reg/mem64)             (:reg/mem64))                                  ;; NEG, DEC, INC

;; (define-instruction-format "|reg16, mem32"          ()                               (:reg16 :mem32))                               ;; BOUND
;; (define-instruction-format "|reg32, mem64"          ()                               (:reg32 :mem64))                               ;; BOUND

;; (define-instruction-format "<reg16"                 (:rflags :reg16)                 (:reg16))                                      ;; DEC, INC
;; (define-instruction-format "<reg32"                 (:rflags :reg32)                 (:reg32))                                      ;; DEC, INC

;; (define-instruction-format "reg32"                  (:reg32)                         (:reg32))                                      ;; BSWAP
;; (define-instruction-format "reg64"                  (:reg64)                         (:reg64))                                      ;; BSWAP

;; ;;;;
;; ;;;; Interrupts
;; ;;;;
;; (define-instruction-format "$@<>imm8"               (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:rflags :imm8 :rip :rsp :cs :ss :mem)) ;; INT, actually potentially it touches a lot more...
;; (define-instruction-format "$@>"                    (:rip :cpl :cs :tss)                       (:rflags))                              ;; INTO, actually potentially it touches a lot more...
;; (define-instruction-format "$@<"                    (:rip :rflags)                   ())                                               ;; INT3, actually potentially it touches a lot more...
;; (define-instruction-format "$@@<"                   (:rflags :rip :rsp :cpl :cs :ss :mem :tss) (:cpl :cs :tss))                        ;; IRET, IRETD, IRETQ

;; ;;;;
;; ;;;; Jumps, calls, returns and branches
;; ;;;;
;; (define-instruction-format "@immoff8"               (:rip)                           (:immoff8))                                    ;; JMP
;; (define-instruction-format "@immoff16"              (:rip)                           (:immoff16))                                   ;; JMP
;; (define-instruction-format "@immoff32"              (:rip)                           (:immoff32))                                   ;; JMP
;; (define-instruction-format "@reg/mem16"             (:rip)                           (:reg/mem16))                                  ;; JMP
;; (define-instruction-format "@reg/mem32"             (:rip)                           (:reg/mem32))                                  ;; JMP
;; (define-instruction-format "@reg/mem64"             (:rip)                           (:reg/mem64))                                  ;; JMP

;; (define-instruction-format "@ptr16:16"              (:rip :cs :tss)                  (:ptr16/16))                                   ;; JMP FAR
;; (define-instruction-format "@ptr16:32"              (:rip :cs :tss)                  (:ptr16/32))                                   ;; JMP FAR
;; (define-instruction-format "@mem32"                 (:rip :cs :tss)                  (:mem32))                                      ;; JMP FAR
;; (define-instruction-format "@mem48"                 (:rip :cs :tss)                  (:mem48))                                      ;; JMP FAR

;; (define-instruction-format "@@immoff16"             (:rip :rsp :mem16)               (:rip :rbp :rsp :immoff16))                    ;; CALL
;; (define-instruction-format "@@immoff32"             (:rip :rsp :mem32)               (:rip :rsp :immoff32))                         ;; CALL
;; (define-instruction-format "@@reg/mem16"            (:rip :rsp :mem16)               (:rip :rsp :reg/mem16))                        ;; CALL
;; (define-instruction-format "@@reg/mem32"            (:rip :rsp :mem32)               (:rip :rsp :reg/mem32))                        ;; CALL
;; (define-instruction-format "@@reg/mem64"            (:rip :rsp :mem64)               (:rip :rsp :reg/mem64))                        ;; CALL

;; (define-instruction-format "@@"                     (:rip :rsp)                      (:rip :rsp :mem16))                            ;; RET
;; (define-instruction-format "@@imm8"                 (:rip :rsp)                      (:rip :rsp :mem16 :imm8))                      ;; RET

;; (define-instruction-format "@>immoff8"              (:rip)                           (:rflags :immoff8))                            ;; Jxx
;; (define-instruction-format "@>immoff16"             (:rip)                           (:rflags :immoff16))                           ;; Jxx
;; (define-instruction-format "@>immoff32"             (:rip)                           (:rflags :immoff32))                           ;; Jxx

;; (define-instruction-format "@CX, immoff8"           (:rip)                           (:cx :immoff8))                                ;; JCXZ
;; (define-instruction-format "@ECX, immoff8"          (:rip)                           (:ecx :immoff8))                               ;; JECXZ
;; (define-instruction-format "@RCX, immoff8"          (:rip)                           (:rcx :immoff8))                               ;; JRCXZ

;; (define-instruction-format "@@@ptr16:16"            (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :ptr16/16))       ;; CALL FAR
;; (define-instruction-format "@@@ptr16:32"            (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :ptr16/32))       ;; CALL FAR
;; (define-instruction-format "@@@mem32"               (:rip :rsp :cpl :cs :ss :mem16)  (:rip :rsp :cpl :cs :tss :ss :mem32))          ;; CALL FAR
;; (define-instruction-format "@@@mem48"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :tss :ss :mem48))          ;; CALL FAR
;; (define-instruction-format "@@@"                    (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16))               ;; RETF
;; (define-instruction-format "@@@imm16"               (:rip :rsp :cpl :cs :ss :mem32)  (:rip :rsp :cpl :cs :ss :mem16 :imm16))        ;; RETF

;; (define-instruction-format "!AX, AL"                (:ax)                            (:al))                                         ;; CBW
;; (define-instruction-format "!EAX, AX"               (:eax)                           (:ax))                                         ;; CWDE
;; (define-instruction-format "!RAX, EAX"              (:rax)                           (:eax))                                        ;; CDQE

;; (define-instruction-format "2|AX, DX"               (:ax :dx)                        (:ax))                                         ;; CWD
;; (define-instruction-format "2|EAX, EDX"             (:eax :edx)                      (:eax))                                        ;; CDQ
;; (define-instruction-format "2|RAX, RDX"             (:rax :rdx)                      (:rax))                                        ;; CQO

;; (define-instruction-format "<"                      (:rflags)                        ())                                            ;; CLC, CLD, STC, STD
;; (define-instruction-format "$<IF"                   (:rflags)                        (:cpl :cs))                                    ;; CLI, STI
;; (define-instruction-format "<>"                     (:rflags)                        (:rflags))                                     ;; CMC

;; (define-instruction-format "|mem8"                  ()                               (:mem8))                                       ;; CLFLUSH, INVLPG
;; (define-instruction-format "|RAX, ECX"              ()                               (:rax :ecx))                                   ;; INVLPGA

;; (define-instruction-format ""                       ()                               ())                                            ;; LFENCE, SFENCE, MFENCE, NOP, PAUSE
;; (define-instruction-format "|CPL"                   ()                               (:cpl :cs))                                    ;; INVD, WBINVD, HLT
;; (define-instruction-format "|!mem16/32/64"          ()                               ())                                            ;; NOP
;; (define-instruction-format "|!mem8"                 ()                               ())                                            ;; PREFETCH{,W,NTA,0,1,2}

;; ;;;;
;; ;;;; String formats
;; ;;;;                                                                    
;; (define-instruction-format "<>|mem8, mem8"          (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem8 :mem8))   ;; CMPS, CMPSB
;; (define-instruction-format "<>|mem16, mem16"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem16 :mem16)) ;; CMPS, CMPSW
;; (define-instruction-format "<>|mem32, mem32"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem32 :mem32)) ;; CMPS, CMPSD
;; (define-instruction-format "<>|mem64, mem64"        (:rflags :rsi :rdi)              (:rflags :segreg :rsi :es :rdi :mem64 :mem64)) ;; CMPS, CMPSQ

;; (define-instruction-format "!AL, mem8"              (:al  :rsi)                      (:ds :rsi :mem8))                              ;; LODS, LODSB
;; (define-instruction-format "!AX, mem16"             (:ax  :rsi)                      (:ds :rsi :mem16))                             ;; LODS, LODSW
;; (define-instruction-format "!EAX, mem32"            (:eax :rsi)                      (:ds :rsi :mem32))                             ;; LODS, LODSD
;; (define-instruction-format "!RAX, mem64"            (:rax :rsi)                      (:ds :rsi :mem64))                             ;; LODS, LODSQ

;; (define-instruction-format "!mem8, mem8"            (:rsi :rdi :mem8)                (:segreg :rsi :es :rdi :mem8))                 ;; MOVS, MOVSB
;; (define-instruction-format "!mem16, mem16"          (:rsi :rdi :mem16)               (:segreg :rsi :es :rdi :mem16))                ;; MOVS, MOVSW
;; (define-instruction-format "!mem32, mem32"          (:rsi :rdi :mem32)               (:segreg :rsi :es :rdi :mem32))                ;; MOVS, MOVSD
;; (define-instruction-format "!mem64, mem64"          (:rsi :rdi :mem64)               (:segreg :rsi :es :rdi :mem64))                ;; MOVS, MOVSQ

;; (define-instruction-format "<>|AL, mem8"            (:rflags :rdi)                   (:rflags :es :rdi :al :mem8))                  ;; SCAS, SCASB
;; (define-instruction-format "<>|AX, mem16"           (:rflags :rdi)                   (:rflags :es :rdi :ax :mem16))                 ;; SCAS, SCASW
;; (define-instruction-format "<>|EAX, mem32"          (:rflags :rdi)                   (:rflags :es :rdi :eax :mem32))                ;; SCAS, SCASD
;; (define-instruction-format "<>|RAX, mem64"          (:rflags :rdi)                   (:rflags :es :rdi :rax :mem64))                ;; SCAS, SCASQ

;; (define-instruction-format "!mem8, AL"              (:mem8  :rdi)                    (:es :rdi :al))                                ;; STOS, STOSB
;; (define-instruction-format "!mem16, AX"             (:mem16 :rdi)                    (:es :rdi :ax))                                ;; STOS, STOSW
;; (define-instruction-format "!mem32, EAX"            (:mem32 :rdi)                    (:es :rdi :eax))                               ;; STOS, STOSD
;; (define-instruction-format "!mem64, RAX"            (:mem64 :rdi)                    (:es :rdi :rax))                               ;; STOS, STOSQ
;; ;;;;

;; (define-instruction-format "<AL, reg/mem8, reg8"    (:rflags :al :reg/mem8)          (:al :reg/mem8 :reg8))                         ;; CMPXCHG
;; (define-instruction-format "<AX, reg/mem16, reg16"  (:rflags :al :reg/mem16)         (:al :reg/mem16 :reg16))                       ;; CMPXCHG
;; (define-instruction-format "<EAX, reg/mem32, reg32" (:rflags :al :reg/mem32)         (:al :reg/mem32 :reg32))                       ;; CMPXCHG
;; (define-instruction-format "<RAX, reg/mem64, reg64" (:rflags :al :reg/mem64)         (:al :reg/mem64 :reg64))                       ;; CMPXCHG

;; (define-instruction-format "<EDX:EAX, reg/mem64, ECX:EBX"  (:rflags :edx :eax :reg/mem64)  (:edx :eax :reg/mem64 :ecx :edx))        ;; CMPXCHG8B
;; (define-instruction-format "<RDX:RAX, reg/mem128, RCX:RBX" (:rflags :rdx :rax :reg/mem128) (:rdx :rax :reg/mem128 :rcx :rdx))       ;; CMPXCHG16B

;; (define-instruction-format "EAX, EBX, ECX, EDX"            (:eax :ebx :ecx :edx)     (:eax))                                        ;; CPUID
                                                                                                                         
;; (define-instruction-format "<AL, AH, reg/mem8"             (:rflags :ah :al)         (:ax :reg/mem8))                               ;; DIV, IDIV
;; (define-instruction-format "<DX, AX, reg/mem16"            (:rflags :dx :ax)         (:dx :ax :reg/mem16))                          ;; DIV, IDIV
;; (define-instruction-format "<EDX, EAX, reg/mem32"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
;; (define-instruction-format "<RDX, RAX, reg/mem64"          (:rflags :edx :eax)       (:edx :eax :reg/mem32))                        ;; DIV, IDIV
;; (define-instruction-format "<!AX, AL, reg/mem8"            (:rflags :ax)             (:al :reg/mem8))                               ;; MUL, IMUL
;; (define-instruction-format "<!DX, AX, AX, reg/mem16"       (:rflags :dx :ax)         (:ax :reg/mem16))                              ;; MUL, IMUL
;; (define-instruction-format "<!EDX, EAX, EAX, reg/mem32"    (:rflags :edx :eax)       (:eax :reg/mem32))                             ;; MUL, IMUL
;; (define-instruction-format "<!RDX, RAX, RAX, reg/mem64"    (:rflags :rdx :rax)       (:rax :reg/mem64))                             ;; MUL, IMUL
                                                                                                                         
;; (define-instruction-format "imm16, 0"                      (:rsp :rbp)               (:imm16 0 :rsp :rbp :ss))                      ;; ENTER
;; (define-instruction-format "imm16, 1"                      (:rsp :rbp)               (:imm16 1 :rsp :rbp :ss))                      ;; ENTER
;; (define-instruction-format "imm16, imm8"                   (:rsp :rbp)               (:imm16 :imm8 :rsp :rbp :ss))                  ;; ENTER
                                                                                                                         
;; (define-instruction-format "BP, SP"                        (:bp :sp)                 (:bp :mem16))                                  ;; LEAVE 
;; (define-instruction-format "EBP, ESP"                      (:ebp :esp)               (:ebp :mem32))                                 ;; LEAVE 
;; (define-instruction-format "RBP, RSP"                      (:rbp :rsp)               (:rbp :mem64))                                 ;; LEAVE 
                                                                                                                         
;; (define-instruction-format "<!reg16, reg/mem16, imm8"      (:rflags :reg16)          (:reg/mem16 :imm8))                            ;; IMUL
;; (define-instruction-format "<!reg32, reg/mem32, imm8"      (:rflags :reg32)          (:reg/mem32 :imm8))                            ;; IMUL
;; (define-instruction-format "<!reg64, reg/mem64, imm8"      (:rflags :reg64)          (:reg/mem64 :imm8))                            ;; IMUL
;; (define-instruction-format "<!reg16, reg/mem16, imm16"     (:rflags :reg16)          (:reg/mem16 :imm16))                           ;; IMUL
;; (define-instruction-format "<!reg32, reg/mem32, imm32"     (:rflags :reg32)          (:reg/mem32 :imm32))                           ;; IMUL
;; (define-instruction-format "<!reg64, reg/mem64, imm32"     (:rflags :reg64)          (:reg/mem64 :imm32))                           ;; IMUL
                                                                                                                         
;; (define-instruction-format "#!AL, DX"                      (:al)                     (:dx :tss))                                    ;; IN
;; (define-instruction-format "#!AX, DX"                      (:ax)                     (:dx :tss))                                    ;; IN
;; (define-instruction-format "#!EAX, DX"                     (:eax)                    (:dx :tss))                                    ;; IN
;; (define-instruction-format "#!AL, imm8"                    (:al)                     (:imm8 :tss))                                  ;; IN
;; (define-instruction-format "#!AX, imm8"                    (:ax)                     (:imm8 :tss))                                  ;; IN
;; (define-instruction-format "#!EAX, imm8"                   (:eax)                    (:imm8 :tss))                                  ;; IN
                                                                                                                               
;; (define-instruction-format "#|DX, AL"                      ()                        (:dx :al  :tss))                               ;; OUT
;; (define-instruction-format "#|DX, AX"                      ()                        (:dx :ax  :tss))                               ;; OUT
;; (define-instruction-format "#|DX, EAX"                     ()                        (:dx :eax :tss))                               ;; OUT
;; (define-instruction-format "#imm8, AL"                     ()                        (:imm8 :al  :tss))                             ;; OUT
;; (define-instruction-format "#imm8, AX"                     ()                        (:imm8 :ax  :tss))                             ;; OUT
;; (define-instruction-format "#imm8, EAX"                    ()                        (:imm8 :eax :tss))                             ;; OUT
                                                                                                                               
;; (define-instruction-format "#!>mem8, DX"                   (:mem8 :rdi)              (:rflags :es :rdi :dx :tss))                   ;; INS, INSB
;; (define-instruction-format "#!>mem16, DX"                  (:mem16 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSW
;; (define-instruction-format "#!>mem32, DX"                  (:mem32 :rdi)             (:rflags :es :rdi :dx :tss))                   ;; INS, INSD
;; (define-instruction-format "#|>DX, mem8"                   (:rsi)                    (:rflags :ds :rsi :dx :mem8  :tss))            ;; OUTS, OUTSB
;; (define-instruction-format "#|>DX, mem16"                  (:rsi)                    (:rflags :ds :rsi :dx :mem16 :tss))            ;; OUTS, OUTSW
;; (define-instruction-format "#|>DX, mem32"                  (:rsi)                    (:rflags :ds :rsi :dx :mem32 :tss))            ;; OUTS, OUTSD
                                                                                                                         
;; (define-instruction-format ">!AH"                          (:ah)                     (:rflags))                                     ;; LAHF
;; (define-instruction-format "<|!AH"                         (:rflags)                 (:ah))                                         ;; SAHF
                                                                                                                         
;; (define-instruction-format "!DS, reg16, mem32"             (:ds :reg16)              (:mem32))                                      ;; LDS
;; (define-instruction-format "!DS, reg32, mem48"             (:ds :reg32)              (:mem48))                                      ;; LDS
;; (define-instruction-format "!ES, reg16, mem32"             (:es :reg16)              (:mem32))                                      ;; LES
;; (define-instruction-format "!ES, reg32, mem48"             (:es :reg32)              (:mem48))                                      ;; LES
;; (define-instruction-format "!FS, reg16, mem32"             (:fs :reg16)              (:mem32))                                      ;; LFS
;; (define-instruction-format "!FS, reg32, mem48"             (:fs :reg32)              (:mem48))                                      ;; LFS
;; (define-instruction-format "!GS, reg16, mem32"             (:gs :reg16)              (:mem32))                                      ;; LGS
;; (define-instruction-format "!GS, reg32, mem48"             (:gs :reg32)              (:mem48))                                      ;; LGS
;; (define-instruction-format "!SS, reg16, mem32"             (:ss :reg16)              (:mem32))                                      ;; LSS
;; (define-instruction-format "!SS, reg32, mem48"             (:ss :reg32)              (:mem48))                                      ;; LSS
                                                                                                                         
;; (define-instruction-format "!reg16, mem"                   (:reg16)                  (:mem))                                        ;; LEA
;; (define-instruction-format "!reg32, mem"                   (:reg32)                  (:mem))                                        ;; LEA
;; (define-instruction-format "!reg64, mem"                   (:reg64)                  (:mem))                                        ;; LEA
                                                                                                                         
;; (define-instruction-format "@RCX, immoff8"                 (:rip :rcx)               (:rcx :immoff8))                               ;; LOOP
;; (define-instruction-format "@>RCX, immoff8"                (:rip :rcx)               (:rflags :rcx :immoff8))                       ;; LOOPxx
                                                                                                                         
;; (define-instruction-format "<!reg16, reg/mem16"            (:rflags :reg16)          (:reg/mem16))                                  ;; LZCNT, POPCNT
;; (define-instruction-format "<!reg32, reg/mem32"            (:rflags :reg32)          (:reg/mem32))                                  ;; LZCNT, POPCNT
;; (define-instruction-format "<!reg64, reg/mem64"            (:rflags :reg64)          (:reg/mem64))                                  ;; LZCNT, POPCNT
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; load/stores                                                                                                         
;; ;;;;                                                                                                                     
;; (define-instruction-format "!reg/mem8, reg8"               (:reg/mem8)               (:reg8))                                       ;; MOV
;; (define-instruction-format "!reg/mem16, reg16"             (:reg/mem16)              (:reg16))                                      ;; MOV
;; (define-instruction-format "!reg/mem32, reg32"             (:reg/mem32)              (:reg32))                                      ;; MOV
;; (define-instruction-format "!reg/mem64, reg64"             (:reg/mem64)              (:reg64))                                      ;; MOV
;; (define-instruction-format "!reg8, reg/mem8"               (:reg8)                   (:reg/mem8))                                   ;; MOV
;; (define-instruction-format "!reg16, reg/mem16"             (:reg16)                  (:reg/mem16))                                  ;; MOV
;; (define-instruction-format "!reg32, reg/mem32"             (:reg32)                  (:reg/mem32))                                  ;; MOV
;; (define-instruction-format "!reg64, reg/mem64"             (:reg64)                  (:reg/mem64))                                  ;; MOV

;; (define-instruction-format "!reg16, reg/mem8"              (:reg16)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (define-instruction-format "!reg32, reg/mem8"              (:reg32)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (define-instruction-format "!reg64, reg/mem8"              (:reg64)                  (:reg/mem8))                                   ;; MOVSX, MOVZX
;; (define-instruction-format "!reg32, reg/mem16"             (:reg32)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
;; (define-instruction-format "!reg64, reg/mem16"             (:reg64)                  (:reg/mem16))                                  ;; MOVSX, MOVZX
;; (define-instruction-format "!reg64, reg/mem32"             (:reg64)                  (:reg/mem32))                                  ;; MOVSXD (weird for 16bit op; separate format?)                     
                                                                                                    
;; (define-instruction-format "!mem32, reg32"                 (:mem32)                  (:reg32))                                      ;; MOVNTI
;; (define-instruction-format "!mem64, reg64"                 (:mem64)                  (:reg64))                                      ;; MOVNTI
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; RIP-relative load/stores                                                                                            
;; ;;;;                                                                                                                     
;; (define-instruction-format "!AL, immoff8"                  (:al)                     (:immoff8 :mem8))                              ;; MOV
;; (define-instruction-format "!AX, immoff16"                 (:ax)                     (:immoff16 :mem16))                            ;; MOV
;; (define-instruction-format "!EAX, immoff32"                (:eax)                    (:immoff32 :mem32))                            ;; MOV
;; (define-instruction-format "!RAX, immoff64"                (:rax)                    (:immoff64 :mem64))                            ;; MOV
;; (define-instruction-format "immoff8, AL"                   (:mem8)                   (:immoff8 :al))                                ;; MOV
;; (define-instruction-format "immoff16, AX"                  (:mem16)                  (:immoff16 :ax))                               ;; MOV
;; (define-instruction-format "immoff32, EAX"                 (:mem32)                  (:immoff32 :eax))                              ;; MOV
;; (define-instruction-format "immoff64, RAX"                 (:mem64)                  (:immoff64 :rax))                              ;; MOV
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; constant                                                                                                            
;; ;;;;                                                                                                                     
;; (define-instruction-format "!reg8, imm8"                   (:reg8)                   (:imm8))                                       ;; MOV
;; (define-instruction-format "!reg16, imm16"                 (:reg16)                  (:imm16))                                      ;; MOV
;; (define-instruction-format "!reg32, imm32"                 (:reg32)                  (:imm32))                                      ;; MOV
;; (define-instruction-format "!reg64, imm64"                 (:reg64)                  (:imm64))                                      ;; MOV
;; (define-instruction-format "!reg/mem8, imm8"               (:reg/mem8)               (:imm8))                                       ;; MOV
;; (define-instruction-format "!reg/mem16, imm16"             (:reg/mem16)              (:imm16))                                      ;; MOV
;; (define-instruction-format "!reg/mem32, imm32"             (:reg/mem32)              (:imm32))                                      ;; MOV
;; (define-instruction-format "!reg/mem64, imm32"             (:reg/mem64)              (:imm32))                                      ;; MOV
                                                                                                                         
;; ;;;;                                                                                                                     
;; ;;;; segment register                                                                                                    
;; ;;;;                                                                                                                     
;; (define-instruction-format "!reg16/32/64/mem16, segreg"    (:reg16/32/64/mem16)      (:segreg))                                     ;; MOV
;; (define-instruction-format "!segreg, reg/mem16"            (:segreg)                 (:reg/mem16))                                  ;; MOV

;; ;;;;                                                                                                                     
;; ;;;; MMX/XMM                                                                                                             
;; ;;;;                                                                                                                     
;; (define-instruction-format "!mmx, reg/mem32"               (:mmx)                    (:reg/mem32))                                  ;; MOVD
;; (define-instruction-format "!mmx, reg/mem64"               (:mmx)                    (:reg/mem64))                                  ;; MOVD
;; (define-instruction-format "!reg/mem32, mmx"               (:reg/mem32)              (:mmx))                                        ;; MOVD
;; (define-instruction-format "!reg/mem64, mmx"               (:reg/mem64)              (:mmx))                                        ;; MOVD
;; (define-instruction-format "!xmm, reg/mem32"               (:xmm)                    (:reg/mem32))                                  ;; MOVD
;; (define-instruction-format "!xmm, reg/mem64"               (:xmm)                    (:reg/mem64))                                  ;; MOVD
;; (define-instruction-format "!reg/mem32, xmm"               (:reg/mem32)              (:xmm))                                        ;; MOVD
;; (define-instruction-format "!reg/mem64, xmm"               (:reg/mem64)              (:xmm))                                        ;; MOVD
                                                                                                                         
;; (define-instruction-format "!reg32, xmm"                   (:reg32)                  (:xmm))                                        ;; MOVMSKPS, MOVMSKPD

;; ;;;;
;; ;;;; system
;; ;;;;                                                                                                                         
;; (define-instruction-format "$!cr, reg32"                   (:cr)                     (:reg32 :cpl :cs))                             ;; MOV
;; (define-instruction-format "$!cr, reg64"                   (:cr)                     (:reg64 :cpl :cs))                             ;; MOV
;; (define-instruction-format "!reg32, cr"                    (:reg32)                  (:cr :cpl :cs))                                ;; MOV
;; (define-instruction-format "!reg64, cr"                    (:reg64)                  (:cr :cpl :cs))                                ;; MOV

;; (define-instruction-format "$!CR8, reg32"                  (:cr8)                    (:reg32 :cpl :cs))                             ;; MOV
;; (define-instruction-format "$!CR8, reg64"                  (:cr8)                    (:reg64 :cpl :cs))                             ;; MOV
;; (define-instruction-format "!reg32, CR8"                   (:reg32)                  (:cr8 :cpl :cs))                               ;; MOV
;; (define-instruction-format "!reg64, CR8"                   (:reg64)                  (:cr8 :cpl :cs))                               ;; MOV

;; (define-instruction-format "$!dr, reg32"                   (:dr)                     (:reg32 :cpl :cs))                             ;; MOV
;; (define-instruction-format "$!dr, reg64"                   (:dr)                     (:reg64 :cpl :cs))                             ;; MOV
;; (define-instruction-format "!reg32, dr"                    (:reg32)                  (:dr :cpl :cs))                                ;; MOV
;; (define-instruction-format "!reg64, dr"                    (:reg64)                  (:dr :cpl :cs))                                ;; MOV

;; ;;;;
;; ;;;; Stack
;; ;;;;
;; (define-instruction-format "!reg/mem16, [SS:RSP]"          (:reg/mem16 :rsp)         (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!reg/mem32, [SS:RSP]"          (:reg/mem32 :rsp)         (:ss :rsp :mem32))                             ;; POP
;; (define-instruction-format "!reg/mem64, [SS:RSP]"          (:reg/mem64 :rsp)         (:ss :rsp :mem64))                             ;; POP
;; (define-instruction-format "!reg16, [SS:RSP]"              (:reg16 :rsp)             (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!reg32, [SS:RSP]"              (:reg32 :rsp)             (:ss :rsp :mem32))                             ;; POP
;; (define-instruction-format "!reg64, [SS:RSP]"              (:reg64 :rsp)             (:ss :rsp :mem64))                             ;; POP
;; (define-instruction-format "!DS, [SS:RSP]"                 (:ds :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!ES, [SS:RSP]"                 (:es :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!SS, [SS:RSP]"                 (:ss :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!FS, [SS:RSP]"                 (:fs :rsp)                (:ss :rsp :mem16))                             ;; POP
;; (define-instruction-format "!GS, [SS:RSP]"                 (:gs :rsp)                (:ss :rsp :mem16))                             ;; POP

;; (define-instruction-format "![SS:RSP], reg/mem16"          (:mem16 :rsp)             (:ss :rsp :reg/mem16))                         ;; PUSH
;; (define-instruction-format "![SS:RSP], reg/mem32"          (:mem32 :rsp)             (:ss :rsp :reg/mem32))                         ;; PUSH
;; (define-instruction-format "![SS:RSP], reg/mem64"          (:mem64 :rsp)             (:ss :rsp :reg/mem64))                         ;; PUSH
;; (define-instruction-format "![SS:RSP], reg16"              (:mem16 :rsp)             (:ss :rsp :reg16))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], reg32"              (:mem32 :rsp)             (:ss :rsp :reg32))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], reg64"              (:mem64 :rsp)             (:ss :rsp :reg64))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], imm8"               (:mem8  :rsp)             (:ss :rsp :imm8))                              ;; PUSH
;; (define-instruction-format "![SS:RSP], imm16"              (:mem16 :rsp)             (:ss :rsp :imm16))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], imm32"              (:mem32 :rsp)             (:ss :rsp :imm32))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], imm64"              (:mem64 :rsp)             (:ss :rsp :imm64))                             ;; PUSH
;; (define-instruction-format "![SS:RSP], CS"                 (:mem16 :rsp)             (:ss :rsp :cs))                                ;; PUSH
;; (define-instruction-format "![SS:RSP], DS"                 (:mem16 :rsp)             (:ss :rsp :ds))                                ;; PUSH
;; (define-instruction-format "![SS:RSP], ES"                 (:mem16 :rsp)             (:ss :rsp :es))                                ;; PUSH
;; (define-instruction-format "![SS:RSP], SS"                 (:mem16 :rsp)             (:ss :rsp :ss))                                ;; PUSH
;; (define-instruction-format "![SS:RSP], FS"                 (:mem16 :rsp)             (:ss :rsp :fs))                                ;; PUSH
;; (define-instruction-format "![SS:RSP], GS"                 (:mem16 :rsp)             (:ss :rsp :gs))                                ;; PUSH

;; (define-instruction-format "!DI, SI, BP, SP, BX, DX, CX, AX, [SS:SP]"          (:di :si :bp :sp :bx :dx :cx :ax)         (:ss :rsp :mem128)) ;; POPA
;; (define-instruction-format "!EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX, [SS:ESP]" (:edi :esi :ebp :esp :ebx :edx :ecx :eax) (:ss :rsp :mem256)) ;; POPAD

;; (define-instruction-format "![SS:SP], AX, CX, DX, BX, SP, BP, SI, DI"          (:ss :rsp :mem128)         (:di :si :bp :sp :bx :dx :cx :ax)) ;; PUSHA
;; (define-instruction-format "![SS:ESP], EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI" (:ss :rsp :mem256) (:edi :esi :ebp :esp :ebx :edx :ecx :eax)) ;; PUSHAD

;; (define-instruction-format "<>![SS:SP]"                    (:flags  :rsp)            (:flags  :cpl :cs :ss :rsp :mem16))            ;; POPF
;; (define-instruction-format "<>![SS:ESP]"                   (:eflags :rsp)            (:eflags :cpl :cs :ss :rsp :mem32))            ;; POPFD
;; (define-instruction-format "<>![SS:RSP]"                   (:rflags :rsp)            (:rflags :cpl :cs :ss :rsp :mem64))            ;; POPFQ

;; (define-instruction-format ">![SS:SP]"                     (:mem16 :rsp)             (:flags  :ss :rsp))                            ;; PUSHF
;; (define-instruction-format ">![SS:ESP]"                    (:mem32 :rsp)             (:eflags :ss :rsp))                            ;; PUSHFD
;; (define-instruction-format ">![SS:RSP]"                    (:mem64 :rsp)             (:rflags :ss :rsp))                            ;; PUSHFQ

;; (define-instruction-format "<>reg/mem8, 1"                 (:rflags :reg/mem8)       (:rflags :reg/mem8  1))                        ;; RCL, RCR
;; (define-instruction-format "<>reg/mem16, 1"                (:rflags :reg/mem16)      (:rflags :reg/mem16 1))                        ;; RCL, RCR
;; (define-instruction-format "<>reg/mem32, 1"                (:rflags :reg/mem32)      (:rflags :reg/mem32 1))                        ;; RCL, RCR
;; (define-instruction-format "<>reg/mem64, 1"                (:rflags :reg/mem64)      (:rflags :reg/mem64 1))                        ;; RCL, RCR
;; (define-instruction-format "<>reg/mem8, CL"                (:rflags :reg/mem8)       (:rflags :reg/mem8  :cl))                      ;; RCL, RCR
;; (define-instruction-format "<>reg/mem16, CL"               (:rflags :reg/mem16)      (:rflags :reg/mem16 :cl))                      ;; RCL, RCR
;; (define-instruction-format "<>reg/mem32, CL"               (:rflags :reg/mem32)      (:rflags :reg/mem32 :cl))                      ;; RCL, RCR
;; (define-instruction-format "<>reg/mem64, CL"               (:rflags :reg/mem64)      (:rflags :reg/mem64 :cl))                      ;; RCL, RCR
;; (define-instruction-format "<>reg/mem8, imm8"              (:rflags :reg/mem8)       (:rflags :reg/mem8  :imm8))                    ;; RCL, RCR
;; (define-instruction-format "<>reg/mem16, imm8"             (:rflags :reg/mem16)      (:rflags :reg/mem16 :imm8))                    ;; RCL, RCR
;; (define-instruction-format "<>reg/mem32, imm8"             (:rflags :reg/mem32)      (:rflags :reg/mem32 :imm8))                    ;; RCL, RCR
;; (define-instruction-format "<>reg/mem64, imm8"             (:rflags :reg/mem64)      (:rflags :reg/mem64 :imm8))                    ;; RCL, RCR

;; (define-instruction-format "<reg/mem8, 1"                  (:rflags :reg/mem8)       (:reg/mem8 1))                                 ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem16, 1"                 (:rflags :reg/mem16)      (:reg/mem16 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem32, 1"                 (:rflags :reg/mem32)      (:reg/mem32 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem64, 1"                 (:rflags :reg/mem64)      (:reg/mem64 1))                                ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem8, CL"                 (:rflags :reg/mem8)       (:reg/mem8 :cl))                               ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem16, CL"                (:rflags :reg/mem16)      (:reg/mem16 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem32, CL"                (:rflags :reg/mem32)      (:reg/mem32 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem64, CL"                (:rflags :reg/mem64)      (:reg/mem64 :cl))                              ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem8, imm8"               (:rflags :reg/mem8)       (:reg/mem8 :imm8))                             ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem16, imm8"              (:rflags :reg/mem16)      (:reg/mem16 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem32, imm8"              (:rflags :reg/mem32)      (:reg/mem32 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR
;; (define-instruction-format "<reg/mem64, imm8"              (:rflags :reg/mem64)      (:reg/mem64 :imm8))                            ;; ROL, ROR, SHL, SAL, SHR, SAR

;; (define-instruction-format "<reg/mem16, reg16, CL"         (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :cl))                     ;; SHLD, SHRD
;; (define-instruction-format "<reg/mem32, reg32, CL"         (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :cl))                     ;; SHLD, SHRD
;; (define-instruction-format "<reg/mem64, reg64, CL"         (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :cl))                     ;; SHLD, SHRD
;; (define-instruction-format "<reg/mem16, reg16, imm8"       (:rflags :reg/mem16 :reg16) (:reg/mem16 :reg16 :imm8))                   ;; SHLD, SHRD
;; (define-instruction-format "<reg/mem32, reg32, imm8"       (:rflags :reg/mem32 :reg32) (:reg/mem32 :reg32 :imm8))                   ;; SHLD, SHRD
;; (define-instruction-format "<reg/mem64, reg64, imm8"       (:rflags :reg/mem64 :reg64) (:reg/mem64 :reg64 :imm8))                   ;; SHLD, SHRD

;; (define-instruction-format "2|reg/mem8,  reg8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XADD, XCHG
;; (define-instruction-format "2|reg/mem16, reg16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XADD, XCHG
;; (define-instruction-format "2|reg/mem32, reg32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XADD, XCHG
;; (define-instruction-format "2|reg/mem64, reg64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XADD, XCHG

;; (define-instruction-format "2|AX,  reg16"                  (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
;; (define-instruction-format "2|EAX, reg32"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
;; (define-instruction-format "2|RAX, reg64"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;; ;;;;
;; ;;;; XCHG's identicalities
;; ;;;;
;; (define-instruction-format "2|reg8,  reg/mem8"             (:reg/mem8  :reg8)        (:reg/mem8  :reg8))                            ;; XCHG
;; (define-instruction-format "2|reg16, reg/mem16"            (:reg/mem16 :reg16)       (:reg/mem16 :reg16))                           ;; XCHG
;; (define-instruction-format "2|reg32, reg/mem32"            (:reg/mem32 :reg32)       (:reg/mem32 :reg32))                           ;; XCHG
;; (define-instruction-format "2|reg64, reg/mem64"            (:reg/mem64 :reg64)       (:reg/mem64 :reg64))                           ;; XCHG
;; (define-instruction-format "2|reg16, AX"                   (:ax  :reg16)             (:ax  :reg16))                                 ;; XCHG
;; (define-instruction-format "2|reg32, EAX"                  (:eax :reg32)             (:eax :reg32))                                 ;; XCHG
;; (define-instruction-format "2|reg64, RAX"                  (:rax :reg64)             (:rax :reg64))                                 ;; XCHG

;; ;;;;
;; ;;;; assorted system stuff
;; ;;;;
;; (define-instruction-format "AL, seg:[RBX + AL]"            (:al)                     (:segreg :rbx :al))                            ;; XLAT, XLATB

;; (define-instruction-format "<$reg/mem16, reg16"            (:segreg)                 (:segreg :reg16))                              ;; ARPL
;; (define-instruction-format "$!GIF"                         (:gif)                    ())                                            ;; CLGI, STGI

;; (define-instruction-format "$CR0"                          (:cr0)                    ())                                            ;; CLTS

;; (define-instruction-format "<!$reg16, reg/mem16"           (:rflags :reg16)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
;; (define-instruction-format "<!$reg32, reg/mem16"           (:rflags :reg32)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL
;; (define-instruction-format "<!$reg64, reg/mem16"           (:rflags :reg64)          (:reg/mem16 :cpl :cs :dpl))                    ;; LAR, LSL

;; (define-instruction-format "|$mem48"                       ()                        (:mem48 :cpl :cs))                             ;; LGDT, LIDT
;; (define-instruction-format "|$mem80"                       ()                        (:mem80 :cpl :cs))                             ;; LGDT, LIDT

;; (define-instruction-format "!mem48"                        (:mem48)                  ())                                            ;; SGDT, SIDT
;; (define-instruction-format "!mem80"                        (:mem80)                  ())                                            ;; SGDT, SIDT

;; (define-instruction-format "!$sysreg16, reg/mem16"         (:sysreg16)               (:reg/mem16 :cpl :cs))                         ;; LIDT, LMSW, LTR

;; (define-instruction-format "$segreg:[EAX], ECX, EDX"       ()                        (:segreg :eax :ecx :edx :cpl :cs))             ;; MONITOR
;; (define-instruction-format "$EAX, ECX"                     ()                        (:eax :ecx :cpl :cs))                          ;; MWAIT

;; (define-instruction-format "2!2|EDX:EAX, ECX, sysreg64"    (:eax :edx)               (:ecx :sysreg64 :cpl :cs))                     ;; RDMSR, RDPMC
;; (define-instruction-format "2!2|EDX:EAX, sysreg64"         (:eax :edx)               (:sysreg64 :cpl :cs :cr4))                     ;; RDTSC
;; (define-instruction-format "2!2|3!3|EDX:EAX:ECX, sysreg64, sysreg32" (:eax :edx :ecx)(:sysreg64 :sysreg32 :cpl :cs :cr4))           ;; RDTSCP

;; (define-instruction-format "$!sysreg64, EDX:EAX, ECX"      (:sysreg64)               (:eax :edx :ecx :cpl :cs))                     ;; RDMSR, RDPMC

;; (define-instruction-format "!reg16, sysreg16"              (:reg16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (define-instruction-format "!reg32, sysreg16"              (:reg32)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (define-instruction-format "!reg64, sysreg16"              (:reg64)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (define-instruction-format "!mem16, sysreg16"              (:mem16)                  (:sysreg16))                                   ;; SLDT, SMSW, STR
;; (define-instruction-format "2|sysreg16, GS"                (:gs :sysreg16)           (:gs :sysreg16 :cpl :cs))                      ;; SWAPGS

;; (define-instruction-format "$@<!CX"                        (:eflags :eip :cpl :cs :ss :cx)       (:star))                           ;; SYSCALL (short mode)
;; (define-instruction-format "$@<!2|RCX, R11"                (:rflags :rip :cpl :cs :ss :rcx :r11) (:cstar))                          ;; SYSCALL (long mode)
;; (define-instruction-format "$@<|CX"                        (:eflags :eip :cpl :cs :ss)           (:efer :cpl :cs :star :ecx))       ;; SYSRET (short mode)
;; (define-instruction-format "$@<|RCX, R11"                  (:rflags :rip :cpl :cs :ss)           (:efer :cpl :cs :cstar :rcx :r11)) ;; SYSRET (long mode)

;; (define-instruction-format "$@<SS:ESP"                     (:eflags :eip :cpl :cs :ss :esp)      ())                                ;; SYSENTER
;; (define-instruction-format "$@<SS:ESP, CX, DX"             (:eflags :eip :cpl :cs :ss :esp)      (:cx :dx))                         ;; SYSEXIT

;; (define-instruction-format "$@"                            (:rip)                                ())                                ;; UD2, VMMCALL

;; (define-instruction-format "<$reg/mem16"                   (:rflags)                             (:reg/mem16 :cpl :cs))             ;; VERR, VERW

;; (define-instruction-format "$<"                            (:rflags :cr0 :cr3 :cr4 :cr6 :cr7 :efer) (:cr0 :cr3 :cr4 :cr6 :cr7 :efer))                          ;; RSM
;; (define-instruction-format "<|$[EAX]"                      (:rflags :cr0 :cs :ss :eax :edx :esp :ebx :ecx :edx :esi :edi :rgpr :efer :gif) (:eax :efer :cppl)) ;; SKINIT

;; (define-instruction-format "$!2|FS, GS, CS, [RAX]"         (:fs :gs :tr :star :lstar :cstar :sfmask) (:rax :mem :cpl :cs :efer))                               ;; VMLOAD
;; (define-instruction-format "$![RAX], CS, FS, GS"           (:mem)                                    (:rax :cpl :cs :efer :fs :gs :tr :star :lstar :cstar))    ;; VMSAVE
;; (define-instruction-format "$<>@![RAX]"                    (:rflags :es :cs :ss :ds :efer :cr0 :cr4 :cr3 :cr2 :rip :rsp :rax :dr6 :dr7 :cpl :mem :gif) 
;;                                                            (:rflags :rip :rsp :rax :mem :cpl :cs :efer :sysreg64 :es :cs :ss :ds :cr0 :cr4 :cr3))              ;; VMRUN

;;;;
;;;; Total of 483 instruction formats
;;;;

;;;;
;;;; Not an instruction
;;;;
;; (define-instruction-format "$<>@"                       (:gif :efer :cr0 :cr4 :cr3 :rflags :rip :rsp :rax :dr7 :cpl :es :cs :ss :ds)
;;                                              (:es :cs :ss :ds :efer :cr4 :cr3 :cr2 :cr0 :rflags :rip :rsp :rax :dr7 :dr6 :cpl))                  ;; #VMEXIT
