;;;; package.lisp

(defpackage #:dhcp
  (:use #:cl
	#:numex
	;;#:cl-syslog
	)
  (:export
   :*this-net*
   :*hook-ip-allocated*
   :address-list
   :alog
   :broadcast-address
   :ciaddr
   :cidr-subnet
   :*dhcp-nets*
   :configure-parent-router
   :dhcp
   :run
   :dhcp-options
   :dhcpd
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :options
   :yiaddr
   )
  )
