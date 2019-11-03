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
   :configure-parent-router
   :dhcp
   :dhcp-options
   :dhcpd
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :nat-routing
   :options
   :setup-dhcp-network-interfaces
   :setup-hostapd
   :setup-prototype
   :yiaddr
   )
  )
