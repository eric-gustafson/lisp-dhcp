

(in-package #:dhcp)


(defconstant +dhcp-client-port+ 68)

(defvar *client-socket-table* (serapeum:dict))

(defun client-socket (&key
			(host nil) 
			(port +dhcp-client-port+))
  "Returns a server socket for the given port. It's a singleton on the port number.  Asking for the same port gets you the same object.  If host is nil, then we broadcast the message"
  (alexandria:ensure-gethash
   port
   *client-socket-table*
   (let ((sock-obj (usocket:socket-connect
		    host
		    port
		    :protocol :datagram
		    :element-type '(unsigned-byte 8) ;;char
		    :local-host
		    #+(or sbcl)nil
		    #+(or ccl)(local-host-addr)
		    ;;:local-port port
		    )))
     (setf (usocket:socket-option sock-obj :broadcast) t)
     sock-obj)))

(defun rand-xid ()
  (random 1000000))

;;    TODO Make this work with snot as well
(defun request-client-address (&key iface-name)
  "Send out a broadcast for a dhcp address"
  (unless (stringp iface-name)
    (error "iface name must be given an be a string"))
  (let ((link-obj (find iface-name (lsa:/sys->link-obj) :key #'lsa:name :test #'equal)))
    (unless link-obj (error (format nil "No interface found for ~a" iface-name)))
    (let* ((oobj (make-instance 'dhcp-options
				:mtype +MSG-TYPE-DHCPDISCOVER+
				:restof `((:hostname "athena")
					  (:lease-time 300)))))
      (make-instance 'dhcp 
		     :op +MSG-TYPE-DHCPDISCOVER+
		     :htype (or (lsa:hwtype link-obj)
				+HWT-ETHERNET-10MB+)
		     ;; this is what the kernel returned
		     ;; it's part of /proc
		     :hlen (or (lsa:addr-len link-obj) 
			       6)
		     :hops 0
		     :xid (rand-xid)
		     :options oobj
		     :chaddr (ensure-length
			      (numex:hexstring->octets (lsa:mac link-obj))
			      16)
		     )))
  
  )


