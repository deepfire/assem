;;; -*- Mode: Lisp; indent-tabs-mode: nil -*-

(defsystem :assem
  :depends-on (:alexandria :iterate :pergamum :custom-harness :semi-precious :symtable)
  :components
  ((:file "package")
   ;;;
   (:file "isa" :depends-on ("package"))
   ;;;
   (:file "isa-mips" :depends-on ("isa"))
   #+nil
   (:file "isa-amd64" :depends-on ("isa"))
   (:file "assem" :depends-on ("isa"))
   ;;;
   (:file "assem-emission" :depends-on ("assem"))
   ;;;
   (:file "assem-mips" :depends-on ("isa-mips" "assem-emission"))
   ))
