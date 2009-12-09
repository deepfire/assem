;;; -*- Mode: Lisp; indent-tabs-mode: nil -*-

(defsystem :assem
  :depends-on (:alexandria :iterate :pergamum :custom-harness :semi-precious :symtable)
  :components
  ((:file "package")
   ;;;
   (:file "isa" :depends-on ("package"))
   ;;;
   (:file "unturing" :depends-on ("isa"))
   (:file "isa-mips" :depends-on ("isa"))
   (:file "assem" :depends-on ("isa"))
   ;;;
   #+(or)
   (:file "comp" :depends-on ("assem"))
   (:file "assem-emission" :depends-on ("assem"))
   (:file "unturing-mips" :depends-on ("unturing" "isa-mips"))
   ;;;
   (:file "assem-mips" :depends-on ("isa-mips" "assem-emission"))
   ))
