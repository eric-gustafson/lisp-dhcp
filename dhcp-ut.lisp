

(in-package #:dhcptest)

(defun as-close-out (obj)
  "Shutdown the cl-async object so that the loop can exit cleanly"
  (typecase
      obj
    (cl-async:poller   (cl-async:free-poller obj))
    (cl-async:event    (cl-async:remove-event obj))
    (otherwise
     (if (functionp obj)
	 (cl-async:remove-interval obj)
	 (error (format nil "Unexpected async object: ~a" obj))))
    )
  )


(fiasco:deftest server-socket-test ()
    (fiasco:is
     (eq (server-socket :port 1025)
	 (server-socket :port 1025))
     ))

(fiasco:deftest client-socket-test ()
    (fiasco:is
     (eq (client-socket :port 1025)
	 (client-socket :port 1025)))
    )

(fiasco:deftest msg-identity ()
  (let* ((dhcpReq (request-client-address :iface-name "wlo1"))
	 (pdu (obj->pdu dhcpReq))
	 (their-message (make-instance 'dhcp:dhcp))
	 (dhcpReply (deserialize-into-dhcp-from-buff! their-message pdu)))
    (fiasco:is (equal (dhcp->list dhcpReq)
		      (dhcp->list dhcpReply))))
  )

(fiasco:deftest wtf-match ()
  (fiasco:is
   (trivia:match
       (list 2 2 3)
     ((list (= +MSG-TYPE-DHCPOFFER+)
	    2 3 ) t)))
  )

(fiasco:deftest
    send-and-receive-dhcp-pdu-simple ()
    ;; Can we send and recieve dhcp pdus.  This is not a hdcp functional test, this
    ;; is meant to simply test that we can send pud
    (let (nb
	  event
	  poller
	  (rsocket (server-socket :port 1025)))
      (labels ((done ()
		 (mapcar #'as-close-out (list poller event))
		 ))
	(cl-async:with-event-loop (:catch-app-errors t)
	  (setf	event (cl-async:with-delay (2.5)
			(fiasco:is nil "no dhcp message received")
			(done)
			))
	  (setf poller
		(poll/async-inbound-dhcp-pdu
		 rsocket
		 #'(lambda(pdu)
		     (fiasco:is (eq nb (length pdu))
				"Send bytes ~a == receive bytes ~a"
				nb
				(length pdu))
		     (let ((their-message (make-instance 'dhcp:dhcp)))
		       (deserialize-into-dhcp-from-buff! their-message pdu)
		       (let ((our-response (handle-dhcp-message their-message)))
			 (fiasco:is our-response "all good")
			 (fiasco:is t  "~a" our-response)
			 (done)
			 )
		       )
		     )
		 )
		)
	  (let* ((cs (client-socket :host "127.0.0.1"
				    :port 1024))
		 (dhcpReq (request-client-address :iface-name "wlo1"))
		 (pdu (obj->pdu dhcpReq))
		 )
	    (setf nb (usocket:socket-send cs
					  pdu 
					  (length pdu)
					  :port 1025
					  :host "127.0.0.1"
					  ))
	    (fiasco:is (> nb 0))
	    )
	  )
	)
      )
  )
