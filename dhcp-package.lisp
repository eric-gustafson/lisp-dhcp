;;;; package.lisp

(defpackage #:dhcp
  (:use #:cl
	#:numex
	;;#:cl-syslog
	)
  (:export

   :server-socket
   :client-socket
   :poll/async-inbound-dhcp-pdu
   :request-client-address
   :deserialize-into-dhcp-from-buff!
   :dhcp->list
   
   :*this-net*
   :*hook-ip-allocated*
   :address-list
   :alog
   :broadcast-address
   :ciaddr
   :cidr-subnet
   :*dhcp-nets*
   ;;:configure-parent-router
   :dhcp
   :run
   :dhcp-options
   :dhcpd
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :options
   :yiaddr
   :obj->pdu
   )
  )
