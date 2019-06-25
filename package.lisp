;;;; package.lisp

(defpackage #:dhcp-server
  (:use #:cl
	)
  (:export
   :dhcp
   :setup-prototype
   :dhcpd
   )
  )
