;;;; package.lisp

(defpackage #:dhcp-server
  (:use #:cl
	)
  (:export
   
   :dhcp
   :dhcpd
   :dhcp-options
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :options
   :setup-prototype
   :yiaddr
   :ciaddr
   )
  )
