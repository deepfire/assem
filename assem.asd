(defpackage :assem.system
  (:use :cl :asdf))

(in-package :assem.system)

(defsystem :assem
  :depends-on (:alexandria :iterate :pergamum :custom-harness :semi-precious)
  :components
  ((:file "package")
   ;;;
   (:file "assembly" :depends-on ("package"))
   ;;;
   (:file "unturing" :depends-on ("assembly"))
   (:file "mips-assembly" :depends-on ("assembly"))
   (:file "assem-mini" :depends-on ("assembly"))
   ;;;
   (:file "assem-mini-mips" :depends-on ("mips-assembly" "assem-mini"))
   (:file "unturing-mips" :depends-on ("unturing"))))
