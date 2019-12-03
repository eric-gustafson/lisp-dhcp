;;;; package.lisp

(defpackage #:dhcp-server
  (:use #:cl
	#:numex
	;;#:cl-syslog
	)
  (:export
   :*this-net* 
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
   :nat-routing
   :options
   :setup-dhcp-network-interfaces
   :yiaddr
   )
  )
