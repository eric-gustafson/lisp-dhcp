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

;;
(defun request-client-address (&key iface-name)
  "Create a dhcp object for DHCPDISCOVER message. Returns a udhcp object"
  (unless (stringp iface-name)
    (error "iface name must be given an be a string"))
  (let ((link-obj (find iface-name (lsa:/sys->link-obj) :key #'lsa:name :test #'equal)))
    (unless link-obj (error (format nil "No interface found for ~a" iface-name)))
    (let* ((oobj (make-instance 'dhcp-options
				:mtype +MSG-TYPE-DHCPDISCOVER+
				:restof `((:hostname ,(uiop:hostname))
					  (:lease-time 300)))))
      (make-instance 'udhcp 
		     :op +MSG-TYPE-DHCPDISCOVER+
		     :htype (or (lsa:hwtype link-obj)
				+HWT-ETHERNET-10MB+)
		     ;; this is what the kernel returned
		     ;; it's part of /proc
		     :hlen (or (lsa:addr-len link-obj) 
			       6)
		     :hops 0
		     :xid (rand-xid)
		     :options-obj oobj
		     :chaddr (ensure-length
			      (numex:hexstring->octets (lsa:mac link-obj))
			      16
			      :pad-value 0)
		     )))
  )

(defgeneric handle-dhcpc-message (obj)
  (:documentation "Handles dhcp client messages.  This doens't send or
  receive messages, rather just handles the accounting needed in the
  return value to send back to the server.  It handles two types of
  message, {offer,ack}.  address, which is embedded in the return
  message")
  ;;(error "Not implemented")
  )

(defmethod handle-dhcpc-message ((msg-from-server dhcp))
  ;; This a deserialized PDU
  (let* ((options (options-obj msg-from-server)))
    (ecase
	(msg-type msg-from-server)
      (:offer
       ;; we are going to accept the first offer we get
       ;; TODO: We'LL compute what we want to do based on policy...
       (msg-type! msg-from-server :request)
       msg-from-server
       )
      (:ack
       :done
       )
      )
    )
  )

(defvar *cs* nil)

(defun dhcp-client-socket-up! ()
  (serapeum:synchronized(*cs*)
    (unless *cs*
      (setf *cs*   (server-socket :port +dhcp-client-port+)))
    ))

(defun dhcp-client-socket-down! ()
  (serapeum:synchronized(*cs*)  
    (when *cs*
      (usocket:socket-close *cs*)
      (setf *cs* nil))
    )
  )

(defmethod client-snd-pdu (socket (dhcpobj dhcp))
  (let ((pdu (obj->pdu dhcpObj)))
    (usocket:socket-send *cs*
			 pdu 
			 (length pdu)
			 :port +DHCP-SERVER-PORT+
			 :host #(255 255 255 255)
			 )
    ))

;;
(defun cl-async-call-with-dhcp-address (dhcp-answer-proc &key (iface-name "wlo1"))
  "A function that can be called on/in an cl-async thread loop to send and receive dhcp client messages"
  (let* (
	 (dhcpReq (request-client-address :iface-name iface-name))
	 (pdu (obj->pdu dhcpReq))
	 )
    (dhcp-client-socket-up!)
    (setf (usocket:socket-option *cs* :broadcast) t)
    (client-snd-pdu *cs* dhcpReq)
    ;; Wait for an offer
    ;; send out a request
    ;; wait for an ack
    (as-wait-for-dhcp
	:offer
	(*cs* server-dhcp-obj)
      ;; Set the type to request
      (msg-type! server-dhcp-obj :request)
      (client-snd-pdu *cs* server-dhcp-obj)
      ;;send request
      (as-wait-for-dhcp
	  :ack
	  (*cs* sack-dhcpobj)
	(let ((ip (numex:num->octets (yiaddr sack-dhcpobj) :endian :net)))
	  (dhcp-client-socket-down!)
	  (funcall dhcp-answer-proc ip)
	  )
	)
      )
    )
  )

(defun call-with-dhcp-address/as (thunk &key (iface-name "wlan0"))
  (cl-async:with-event-loop ()
    (cl-async-call-with-dhcp-address #'(lambda(ip)
					 (format t "dhcp-addr: ~a" ip)
					 (funcall thunk ip)
					 )
				     :iface-name iface-name)
    )
  )

(defmethod clog ((str string))
  (syslog:log "dhcp-client" :user :warning str))

(defun call-with-dhcp-address (thunk &key (iface-name "wlan0"))
  "Traditional socket, with waits.  You probably want to call this one
on a thread"
  (let* (
	 (dhcpReq (request-client-address :iface-name iface-name))
	 (pdu (obj->pdu dhcpReq))
	 (buff (make-array 1024 :element-type '(unsigned-byte 8)))
	 )
    (dhcp-client-socket-up!)
    (setf (usocket:socket-option *cs* :broadcast) t)
    (clog "sending dhcp request")
    (client-snd-pdu *cs* dhcpReq)
    (clog "waiting for dhcp offers")
    (handler-case
	(multiple-value-bind (buff n remote-addr remote-port)
	    (usocket:socket-receive *cs* buff 1024)
	  (let* ((pdu (subseq  buff 0 n))
		 (server-offer (pdu-seq->udhcp pdu))
		 (request (handle-dhcpc-message server-offer)))
	    (optima:match
		request
	      ((equal :done) ;;We got an ack right away
	       (clog (format nil "~a" server-offer))
	       )
	      ((type dhcp)
	       (clog (format nil "~a" (msg-type server-offer)))
	       (clog (format nil "sending dhcp-ip request - we've picked a winner ~a" (type-of request)))
	       (client-snd-pdu *cs* request)
	       (multiple-value-bind (buff n remote-addr remote-port)
		   (usocket:socket-receive *cs* buff 1024)
		 (let* ((pdu (subseq  buff 0 n))
			(server-ack (pdu-seq->udhcp pdu)))
		   ;; checks the type and returns done
		   (handle-dhcpc-message server-ack)
		   ;; TODO: get the ip address send only that
		   (format t "~a" server-ack)
		   (funcall thunk server-ack)
		   )
		 )))
	    )
	  )
      (t (c)
	(clog (format nil "!!~a ~&" c))
	(let ((path (uiop/stream:with-temporary-file
			(:stream bout :pathname x :keep t :element-type '(unsigned-byte 8))
		      (write-sequence buff bout)
		      x)))
	  (clog (format nil "saving dhcp message ~s" path))
	  nil))
      )
    )
  )
    

