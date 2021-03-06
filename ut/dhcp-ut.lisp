
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

(defparameter *this-net*
  (make-instance 'cidr-net
		 :cidr 24
		 :cidr-subnet 8
		 :ipnum (numex:octets->num #(10 0 0 0))
		 :mask (numex:octets->num #(255 255 255 0))
		 )
  )

(defparameter cnet-10.1 (make-instance 'dhcp:cidr-net
				       :cidr 24
				       :cidr-subnet 8
				       :ipnum (numex:octets->num #(10 1 0 0))
				       :mask (numex:octets->num #(255 255 0 0))))

(defparameter cnet-10.2 (make-instance 'dhcp:cidr-net
				       :cidr 24
				       :cidr-subnet 8
				       :ipnum (numex:octets->num #(10 2 0 0))
				       :mask (numex:octets->num #(255 255 0 0))))


(defparameter *dhcp-nets*  (numex:cidr-subnets
			    (first-ip *this-net*)
			    (cidr *this-net*)
			    ;;(cidr-subnet *this-net*)
			    :n 4
			    )
  )


(defparameter dhcp-req-msg (dhcp:request-client-address
			    :iface-name
			    (lsa:name (find "link/ether" (lsa:ip-addr-objs) :key #'lsa:ltype :test #'string-equal))
			    ))

;;

(fiasco:deftest dhcp-allocate-ip-test ()
  (fiasco:is (dhcp:dhcp-allocate-ip dhcp-req-msg cnet-10.2) )
  (fiasco:is (handle-dhcpd-message cnet-10.2 dhcp-req-msg))
  )

(fiasco:deftest dhcp-multiple-requests-from-same-mac ()
  (fiasco:is (equalp
	      (dhcp:dhcp-allocate-ip dhcp-req-msg cnet-10.2)
	      (dhcp:dhcp-allocate-ip dhcp-req-msg cnet-10.2)))
  )


(fiasco:deftest dhcp-allocate-test ()
  (fiasco:skip)
  (clrhash dhcp::*dhcp-allocated-table*)
  (fiasco:is
   (equalp
    (numex:num->octets (dhcp:ipnum (dhcp:dhcp-generate-ip "0:1:2:3:4:5" cnet-10.2)))
    #(10 2 0 2)))
  (fiasco:is
   (equalp
    (numex:num->octets (dhcp:ipnum (dhcp:dhcp-generate-ip "0:1:2:3:4:5" cnet-10.2)))
    #(10 2 1 2))
   )
  )

(fiasco:deftest compute-servers ()
  (fiasco:is
   (equalp
    (dhcp:compute-servers-ip-for-address cnet-10.1 (numex:octets->num (vector 10 2 0 (random 255))))
    '(10 2 0 1)))
  (fiasco:is
   (equalp (dhcp:compute-servers-ip-for-address cnet-10.2 (numex:octets->num (vector 10 3 0 (random 255))))
	   '(10 3 0 1)))
  )
	

(fiasco:deftest server-socket-test ()
    (fiasco:is
     (eq (server-socket :port 1024)
	 (server-socket :port 1024))
     ))

(fiasco:deftest client-socket-test ()
    (fiasco:is
     (eq (client-socket :port 1025)
	 (client-socket :port 1025)))
    )

(fiasco:deftest msg-identity ()
  (let* ((dhcpReq (request-client-address :iface-name "wlo1"))
	 (pdu (obj->pdu dhcpReq))
	 (dhcpReply (pdu-seq->udhcp  pdu)))
    (fiasco:is (equalp (obj->pdu dhcpReq)
		       (obj->pdu dhcpReply))))
  )

(fiasco:deftest hex2octs ()
  (fiasco:is (numex:hexstring->octets "1:1:1:1:1:2")
      (list 1 1 1 1 1 2))
  (fiasco:is (numex:hexstring->octets " 1:2:tt:0304:5:06:7:g8g:9:a ")
      (list 1 2 3 4 5 6 7 8 9 10))
  )

(fiasco:deftest dhcp-reservation ()
  ;;(fiasco:skip)
  (clrhash dhcp:*net-allocation-table*)
  (dhcp:update-dhcps-iface-ip-addresses! (list (cons *this-net* (numex:hexstring->octets "1:2:3:4:5:6"))))
  (dhcp:add-cidr-net-reservation! *this-net* "1:1:1:1:1:2" "10.0.3.7")
  (fiasco:is
      (equalp
       (mapcar #'dhcp:ipnum
	       (loop :for i :from 0 :upto 8
		     :collect
		     (dhcp:dhcp-allocate-ip-via-mac *this-net* (list 1 1 1 1 1 i) )))
       (loop :for i :in `("10.0.0.2"
			  "10.0.1.2"
			  "10.0.3.7"
			  "10.0.2.2"  
			  "10.0.3.2"
			  "10.0.4.2"
			  "10.0.5.2"
			  "10.0.6.2"
			  "10.0.7.2"
			  ;"10.0.9.2"
			  )
	     :collect (numex:->num i))))
  )

;; Objective:  To ensure that we receive a valid dhcp exchange
;;  between our server and our client.
(defparameter *our-response* nil)

(defun kwc (ka kb)
  (string-greaterp (format nil "~a" ka) (format nil "~ab" kb))
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; tools to make it easier to write protocol testing code

(defvar *as-shutdown-lst* nil) 
(defvar *step* 0)

(defmacro with-as-nsec-countdown-timer ((nsecs error-mesg) &body body)
  "cl-async countdown timer. Goes boom! if you don't cut the red-wire"
  (let ((var (gensym)))
    `(let ((,var 
	    (cl-async:with-delay (,nsecs)
	      (fiasco:is nil ,error-mesg)
	      (done)
	      )))
       (push ,var *as-shutdown-lst*)
       ,@body))
  )

(defmacro receive/as-pdu ((rsocket pdu) &body body)
  (let ((async-obj (gensym)))
    `(let ((,async-obj
	    (cl-async:poll
	     #+sbcl(sb-bsd-sockets:socket-file-descriptor (usocket:socket ,rsocket))
	     #+ccl(openmcl-socket:socket-os-fd (usocket:socket ,rsocket))	     
	     #'(lambda(event-named)
		 (declare (ignore event-named))
		 (format t "receive/as-pdu~%")
		 (let ((gbuff (make-array 2048 :element-type '(unsigned-byte 8) ))
		       )
		   (multiple-value-bind (buff n)
		       (usocket:socket-receive ,rsocket gbuff (array-total-size gbuff))
		     (let ((,pdu (subseq  buff 0 n)))
		       ,@body
		       )
		     )
		   )
		 )
	     :poll-for '(:readable)
	     :socket t		
	     )
	     ))
       (push ,async-obj *as-shutdown-lst*))
    )
  )


(defvar *client-portn* 2025)
(defvar *server-portn* 2024)

(defvar *cs* nil)
(defvar *ss*  nil)
(defparameter *offer-received* nil)

(defun send-rec-up ()
  (setf *cs*   (server-socket :port *client-portn*))
  #+nil(client-socket :host "localhost" :port *client-portn*)
  (setf *ss* (server-socket :port *server-portn*))
  )

(defun send-rec-down()
  (when *cs*
    (usocket:socket-close *cs*)
    (setf *cs* nil))
  (when *ss*
    (usocket:socket-close *ss*)
    (setf  *ss* nil)))

;; Test our numbers against flexi
(fiasco:deftest
 nbo ()
 (let ((obj (random 1000000)))
   (fiasco:is
    (equalp
     (flexi-streams:with-output-to-sequence (out)
       (nibbles:write-ub32/be obj out))
     (numex:num->octets obj :octets-endian :big)))
   ))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(fiasco:deftest
 send-and-receive-dhcp-pdu-simple ()
 ;; Can we send and recieve dhcp pdus.  This is not a hdcp functional test, this
  ;; is meant to simply test that we can send pud
  (let ((da-net
	  (make-instance 'cidr-net
			 :cidr 24
			 :cidr-subnet 8
			 :ipnum (numex:octets->num #(10 1 0 0))
			 :mask (numex:octets->num #(255 255 255 0))
			 )))
    (unwind-protect
	 (let ((nb 0)) ;; used to compare that snd/receive use the same # of octets
	   (send-rec-up)
	   (labels ((done ()
		      (mapcar #'as-close-out *as-shutdown-lst*))
		    (step! (num)
		      (fiasco:is (= (+ *step* 1) num) "Unexpected step ~a" num)
		      (incf *step*))
		    )
	     (setf *step* 0)
	     (setf *as-shutdown-lst* '())
	     ;; we get memory faults when we fail an 'is'.  Catching the
	     ;; error :catch-app-errors, doesn't make a difference
	     (cl-async:with-event-loop (;;:catch-app-errors t
					;; We MUST catch app-errors or we get memory violations
					)
	       (let (
		     (server2client-nb 0)
		     )
		 ;; If the test lasts longer than 2.5 seconds, it fails
		 (with-as-nsec-countdown-timer 
		     (5 "dhcp test took too long, step")
		   ;; Server: recieve pdu handler 
		   (receive/as-pdu (*ss* pdu)
		     (format t "recieved dhcpdiscover on server socket: ~a~%~%" *step*)
		     (step! 2)
		     (format t "step 2~%")
		     ;; Test that we got the same size as we sent
		     (fiasco:is (eq nb (length pdu)) "~a==~a snd/rcv" nb (length pdu))
		     (format t "passed~%")
		     (let ((their-message (pdu-seq->udhcp pdu)))
		       (format t "their-msg:~a~%" their-message)
		       ;; handle-dhcpd-message handles [:offer :ack :nack :info] messages
		       (let* ((server-rmesg (handle-dhcpd-message da-net their-message))
			      (oobj (options-obj server-rmesg))
			      (buff (obj->pdu server-rmesg)))
			 (format t "wtf??~%")
			 (setf *our-response*  server-rmesg) ;; for interactive debugging
			 ;; send the message to the client
			 (format t "sending dhcp offer from server socket~%")
			 (setf server2client-nb
			       (usocket:socket-send *ss* buff (length buff)
						    :port *client-portn*
						    :host "127.0.0.1"))
			 (format t "server send client offer ~a~%" server2client-nb)
			 (step! 3)
			 (fiasco:is (> server2client-nb 0))
			 ;; Ensure the signature of the reply, plus this helps with the
			 ;; coding of the rest of the tests
			 (fiasco:is (equalp
				     (sort (map 'vector #'car  (restof oobj)) #'kwc) ;; assoc-keys
				     (sort-new '(:SUBNET :ROUTERS :LEASE-TIME
						 :DHCP-SERVER :DNS-SERVERS)
					       #'kwc)
				     ))
			 (step! 4)
			 ))
		     )
		   ;; Client: create and send dhcp request
		   (let* (
			  (dhcpReq (request-client-address :iface-name "wlo1"))
			  (pdu (obj->pdu dhcpReq))
			  )
		     (step! 1)
		     (format t "~%sending dhcpdiscover using client socket~%")
		     ;; We've created a DISCOVER 
		     (setf nb (usocket:socket-send *cs*
						   pdu 
						   (length pdu)
						   :port *server-portn*
						   :host "127.0.0.1"
						   ))
		     (fiasco:is (> nb 0))
		     ;; OFFER and then ACK
		     (format t "waiting for pdu (client)~a~%" *cs*)
		     (receive/as-pdu (*cs* pdu)
		       (step! 5)
		       (let ((server-offer (pdu-seq->udhcp pdu)))
			 (setf *offer-received* server-offer)		      
			 (fiasco:is (eq (msg-type server-offer) :offer))
			 (let ((ack-reply  (handle-dhcpc-message server-offer)))
			   (format t "ack:~a~%" ack-reply)
			   (fiasco:is (eq (msg-type ack-reply) :request))
			   (done)
			   (let ((ip (numex:num->octets (yiaddr server-offer) :octets-endian :net)))
			     ;;(format t "~a ~a~%" dhcpObj dhcpOptionsObj)
			     (fiasco:is (equalp ip
						#(10 1 0 2)))
			     (format t "calling done~%")
			     (format t "~s~%" *as-shutdown-lst*)
			  
			     )
			   )
			 )
		       )
		     )
		   )
		 )
	       )
	     )
	   )
      (send-rec-down))
    )
  )

(defparameter *pdu-seq* nil)

(defun get-captures-as-hash ()
  "Return a hash table of the captures so we can run quick tests on things.  The filename is the key, and the value is a udhcp object"
  (let ((data-dir "/home/egustafs/secapp/lisp-dhcp/devdocs/dhcp-captures/")
	(htable (serapeum:dict)))
    (fiasco:is (uiop:directory-exists-p data-dir))
    (loop :for file :in (uiop:directory-files data-dir)
	  :do
	     (with-open-file (ip file  :element-type '(unsigned-byte 8))
	       (let ((buff (make-array 1024 :element-type '(unsigned-byte 8))))
		 (let ((nb (read-sequence buff ip :start 0 :end 1024)))
		   (setf *pdu-seq* (subseq buff 0 nb))
		   (let ((pduObj (pdu-seq->udhcp *pdu-seq*)))
		     (setf (gethash file htable) pduObj)
		     )
		   )
		 )
	       ))
    htable))

(defvar *data* (get-captures-as-hash))


(fiasco:deftest
    captured1 ()
  (let ((data-dir "/home/egustafs/secapp/lisp-dhcp/devdocs/dhcp-captures/"))
    (fiasco:is (uiop:directory-exists-p data-dir))
    (loop :for file :in (uiop:directory-files data-dir)
	:collect
	(with-open-file (ip file  :element-type '(unsigned-byte 8))
	  (let ((buff (make-array 1024 :element-type '(unsigned-byte 8))))
	    (let ((nb (read-sequence buff ip :start 0 :end 1024)))
	      (setf *pdu-seq* (subseq buff 0 nb))
	      (let ((pduObj (pdu-seq->udhcp *pdu-seq*)))
		(cons file (dhcp:options-obj pduObj)))
	      )
	    )
	  )
	:do
	   (format t "~a~%" file)
	)
    )
  )
 
