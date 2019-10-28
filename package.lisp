;;;; package.lisp

(defpackage #:dhcp-server
  (:use #:cl
	#:numex
	;;#:cl-syslog
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
   :setup-hostapd
   :configure-parent-router
   :yiaddr
   :ciaddr
   
   :address-list
   :broadcast-address
   )
  )
