(in-package :asm-mips)

(defun lick-it (&optional (filename "pestilence/to4fpu/preparee.o"))
  (let* ((vector (pergamum:file-as-vector filename))
         (ehdr (bintype:parse 'elf:ehdr vector))
         (section (car (elf:ehdr-sections ehdr #'elf:shdr-executable-p)))
         (bbs (unturing:insn-vector-to-basic-blocks mips-assembly:*mips-isa* section)))
    (unturing::pprint-bignode-graph-linear bbs)))