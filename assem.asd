(defpackage :assem.system
  (:use :cl :asdf))

(in-package :assem.system)

(defsystem :assem
  :depends-on (:alexandria :iterate :pergamum :custom-harness)
  :components
  ((:file "assembly")
   (:file "mips-assembly" :depends-on ("assembly"))
   (:file "assem-mini" :depends-on ("assembly"))
   (:file "assem-mini-mips" :depends-on ("mips-assembly" "assem-mini"))))
