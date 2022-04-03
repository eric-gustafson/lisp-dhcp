;;;; package.lisp

(defpackage #:dhcp
  (:use #:cl
	#:numex
	)

  (:local-nicknames 
   (:al  :alexandria)
   (:a :alexandria)
   (:pm :trivia)
   ;(:pme :trivia.extra)
   (:re :ppcre)
   (:pm.re :trivia.ppcre)
   (:s :serapeum)
   (:r :rutils)
   )  
  
  (:export

   :update-dhcps-iface-ip-addresses!

   :compute-servers-ip-for-address
   
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
   
   :*hook-ip-allocated*
   :address-list
   :broadcast-address
   :ciaddr
   :cidr-subnet
   :*dhcp-nets*
   ;;:configure-parent-router
   :dhcp-options
   :run
   :dhcpd
   :encode-dhcp-options
   :handle-dhcp-message
   :ip=?
   :options
   :yiaddr
   :obj->pdu

   :cl-async-call-with-dhcp-address
   :call-with-dhcp-address

   :dhcp-allocate-ip
   :dhcp-generate-ip
   
   :first-ip


   :add-cidr-net-reservation!
   :search-cidr-net-reservations
   :address-allocated
   :ip-cidr-net-incompatible
   :dhcp-allocate-ip-via-mac
   )
  )
