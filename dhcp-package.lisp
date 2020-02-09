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
   :receive/as-pdu
   :decode-dhcp-options
   :restof
   :as-wait-for-dhcp
   :pdu-seq->udhcp
   :options-obj
   
   :msg-type
   :msg-type!
   
   :handle-dhcpc-message
   :handle-dhcpd-message
   
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
   :dhcp-options
   :run
   :dhcpd
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :options
   :yiaddr
   :obj->pdu
   )
  )
