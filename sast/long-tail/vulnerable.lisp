;;;; File:    vulnerable.lisp
;;;; Purpose: SAST fixture (Common Lisp). Dynamic evaluation of untrusted input
;;;;          and external program launching.
;;;; Author:  Vigilnz Security Engineering
;;;; Date:    2026-10-16
;;;; Expected rules: lisp-eval, lisp-read-from-string, lisp-run-program,
;;;;   lisp-launch-program

(defpackage :vulnerable
  (:use :cl)
  (:export #:evaluate #:parse-input #:ping #:archive))

(in-package :vulnerable)

;; CWE-95: evaluating untrusted source
(defun evaluate (form)
  (eval form))

(defun parse-input (source)
  (read-from-string source))

;; CWE-78: command injection
(defun ping (host)
  (uiop:run-program (list "sh" "-c" (format nil "ping -c 1 ~a" host))
                    :output :string))

(defun archive (dir)
  (uiop:launch-program (format nil "tar -czf /tmp/out.tgz ~a" dir)))

(defun legacy-ping (host)
  (sb-ext:run-program "/bin/sh" (list "-c" (format nil "ping -c 1 ~a" host))))
