;;;; dhcp-server.lisp

(in-package #:dhcp-server)


(defvar *dhcp-server-port* 67)
(defvar *dhcp-client-port* 68)

(defclass cidr-net ()
  ;; A network defined using cidr notation
  ;;
  (
   (ipnum :accessor ipnum :initarg :ipnum)
   (cidr :accessor cidr :initarg :cidr)
   (mask :accessor mask :initarg :mask)
   )
  )

(defclass dhcp-address ()
  (
   (mac :accessor mac :initarg :mac :initform "")
   (ipnum :accessor ipnum :initarg :ipnum :initform 0)
   (tla :accessor tla :initarg :tla :initform (get-universal-time))
   (lease-time :accessor lease-time :initarg :lease-time :initform  300)
   )
  )

(defmethod print-object ((obj dhcp-address) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots
	  (mac ipnum tla lease-time)
	(format stream "~a,~a,~a~a" mac ipnum tla lease-time))
    )
  )

(defparameter *ns* 1)
(defparameter *dhcp-magic-cookie* '(99 130 83 99))

(defmacro clos-code (name)
  ;; Use the global dhcp symbol table, and create a CLOS class
  ;; for dhcp and bootp packets
  `(defclass ,(intern (string-upcase (format nil "~a"  name)))
       ()
     ,(mapcar #'(lambda(row)
		  (trivia:match
		      row
                       ((list field octets description type notes)
                        (list (->symbol field)
                              :documentation description
                              :accessor (->symbol field)
                              :initarg (->keyword field)))))
	      *dhcp-bootp-base-fields*)
     )
  )

(defmacro gen-deserialize-code (name )
  ;; generate a dehydrate command given the symbol table
  (labels ((dehydrate-operation (st-row)
	     (trivia:match 
		st-row
	       ((list field octets descr da-type notes)
		(let ((type (intern (string-upcase da-type) :keyword)))
		  (cond
		    ((eq type :mac) ;; 
		     `(setf (,(->symbol field) obj)
			    (loop :for i :below ,octets :collect (read-byte input-stream))))
		    ((eq type :rest)
		     `(setf (,(->symbol field) obj) (loop
						       :for x = (read-byte  input-stream nil nil)
						       :while x :collect x
						       )))

		    ;; Strings have a fixed length
		    ;; Maybe we should handle fixed-length, pascal, and c with different
		    ;; keywords?
		    ((eq type :string)
		     `(setf (,(->symbol field) obj)
			    (loop :for i :below ,octets :collect (read-byte input-stream))))
		    ((eq type :int)
		     `(setf (,(->symbol field) obj) (numex:octets->num (numex:read-octets ,octets input-stream) :endian :big)))
		    (t
		     (error "Unexpected type ~a" st-row))
		    ))))))
     `(progn
        (defmethod stream-deserialize ((obj ,(->symbol name)) (input-stream  stream))
          ,@(mapcar #'dehydrate-operation  *dhcp-bootp-base-fields*))
	)
        )
  )

(defmacro gen-serialize-code (name)
  `(defmethod ,(intern (string-upcase (format nil "stream-serialize" name))) ((obj ,name)  (out stream))
     ,@(mapcar #'(lambda(row)
		   (trivia:match 
		       row
		     ((list field octets descr da-type notes)
		      (let ((type (intern (string-upcase da-type) :keyword)))
			(cond
			  ((eq type :mac)
			   `(write-sequence (,(->symbol field) obj) out))
			  ((eq type :rest)
			   `(write-sequence (,(->symbol field) obj) out))
			  ((eq type :string)
			   `(write-sequence (,(->symbol field) obj) out))
			  ((eq type :int)
			   `(write-sequence (numex:num->octets (,(->symbol field) obj) :length ,octets :endian :big) out))
			  (t
			   (error "Unexpected type ~a" row))
			  )))))
	       *dhcp-bootp-base-fields*
	       )
     ))


(clos-code dhcp)

;;(dhcp-bootp-base-fields-code-gen)

(gen-serialize-code dhcp)

(gen-deserialize-code dhcp)

(defmethod deserialize-into-dhcp-from-buff! ((dhcpObj dhcp) (buff sequence))
  (flexi-streams:with-input-from-sequence (inport buff)
    (stream-deserialize dhcpObj inport))
  dhcpObj)

;;                              code generation                               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defun serve ()
  t)
  ;; (cond
  ;;   ((numberp *ns*)
  ;;    (cond
  ;;      ((> *ns* 0)
  ;; 	(decf *ns*)
  ;; 	t)
  ;;      (t nil)))
  ;;   (t
  ;;    t)))

(defvar *last* nil)

(defun save-binary-packet-to-file (path buff)
  (with-open-file (bout path :direction :output :element-type '(unsigned-byte 8)  :if-exists :overwrite :if-does-not-exist :create)
    (write-sequence buff bout))
  )

(defun network-addr? (obj)
  (and (or (vectorp obj) (listp obj))
       (eq 5 (length obj)))
  )

(defparameter *this-net*
  (make-instance 'cidr-net
		 :cidr 24
		 :ipnum (numex:octets->num #(192 168 12 0))
		 :mask (numex:octets->num #(255 255 255 0)))
  ) 

(defparameter *pnet* ;; parent's network
  (make-instance 'cidr-net
		 :cidr 24
		 :ipnum (numex:octets->num #(192 168 11 0))
		 :mask (numex:octets->num #(255 255 255 0)))
  )

(defun this-ip ()
  (first-ip *this-net*)
)

(defun cidr-mask (bits)
  "returns a netmask for the number of bits"
  )

(defun ip-cidrn (bits)
  "return the number of lower order 0ed bits"
  (loop :for i from 0
     :while (and
	     (> bits 0)
	     (= (logand bits 1) 0))
     :counting i
     :do (setf bits (ash bits -1)))
  )

(defun ip-cidrn-octets (num)
  (loop :for o :across (numex:num->octets num :endian :net)
     :while (> o 0)
     :summing 8))


(defmethod print-object ((obj cidr-net) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots (cidr ipnum)
	obj
      (format stream "~a/~a" (numex:num->octets ipnum) cidr)
      ))
  )

(defmethod cidr-in? ((obj cidr-net) (ip number))
  (with-slots (mask ipnum)
      obj
    (eq (logand mask ipnum) (logand mask ip))
    )
  )

(defmethod cidr-in? ((obj cidr-net) (ip-addr list))
  (cidr-in? obj (octets->num ip-addr)))

(defmethod cidr-in? ((obj cidr-net) (ip-addr vector))
  (cidr-in? obj (octets->num ip-addr)))


(defmethod first-ip ((obj cidr-net))
  "return the first IP address in this net"
  (with-slots (ipnum)
      obj
    (+ ipnum 1)))

(defun invert-bits2 (n)
  (if (> n 0)
      (logxor (1- (expt 2 (integer-length #xffffffff))) n)
      0))

(defmethod last-ip ((obj cidr-net))
  "Return the last IP address of this net"
  (with-slots (ipnum mask)
      obj
    (- (+ ipnum (invert-bits2 mask)) 1)))

(defmethod total-ips ((obj cidr-net))
  (1+ (- (last-ip obj) (first-ip obj))))

(defparameter *dhcp-allocated-table* (list
				      (make-instance 'dhcp-address
						     :ipnum (first-ip *this-net*)
						     :lease-time nil))
  )

(defun ip-allocated? (net ip)
  (declare (ignore net))
  (find ip *dhcp-allocated-table*  :key #'ipnum))
						     

(defun dhcp-allocate-ip (net)
  (let ((f (first-ip net))
	(l (last-ip net)))
    (loop :for ip :from f :upto l :do
       (unless (ip-allocated? net ip)
	 (let ((addrObj (make-instance 'dhcp-address :ipnum ip :tla (get-universal-time))))
	   (push addrObj *dhcp-allocated-table*)
	   (return-from dhcp-allocate-ip addrObj)))
       )
    )
  )

(defun deallocate-ip (net ip)
    (setf *dhcp-allocated-table* (delete ip *dhcp-allocated-table* :key #'ipnum :test #'equalp)))


(defmethod get-address ((reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (let* ((new-addr (dhcp-allocate-ip *this-net*))
	 (replyMsg (make-instance 'dhcp
				  :op 2
				  :htype (htype reqMsg)				    
				  :hlen (hlen reqMsg)
				  :hops (hops reqMsg)
				  :xid (xid reqMsg)
				  :secs (secs reqMsg)
				  :flags (flags reqMsg)
				  :yiaddr (ipnum new-addr)
				  :siaddr (numex:octets->num (this-ip) :endian :net)
				  :giaddr (giaddr reqMsg)
				  :chaddr (chaddr reqMsg)
				  :ciaddr (ciaddr reqMsg)
				  :mcookie (mcookie reqMsg)
				  :file (file reqMsg)
				  :sname (sname reqMsg)
				  ))
	 (replyMsgOptions (make-instance 'dhcp-options
					 :mtype 2
					 :restof
					 `(
					   (:subnet 255 255 255 0)
					   (:routers ,(this-ip))
					   (:lease-time 120)
					   (:dhcp-server ,@(this-ip))
					   (:dns-servers (8 8 8 8) (4 4 4 4)))
					 )))
    (setf (options replyMsg) (encode-dhcp-options replyMsgOptions))
    replyMsg))

(defmethod get-ack ((reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (let ((replyMsg (make-instance 'dhcp
				 :op 2
				 :htype (htype reqMsg)				    
				 :hlen (hlen reqMsg)
				 :hops (hops reqMsg)
				 :xid (xid reqMsg)
				 :secs (secs reqMsg)
				 :flags (flags reqMsg)
				 :yiaddr (numex:octets->num (this-ip) :endian :net)
				 :siaddr (numex:octets->num (this-ip) :endian :net)
				 :giaddr (giaddr reqMsg)
				 :chaddr (chaddr reqMsg)
				 :ciaddr (ciaddr reqMsg)
				 :mcookie (mcookie reqMsg)
				 :file (file reqMsg)
				 :sname (sname reqMsg)
				 ))
	(replyMsgOptions (make-instance 'dhcp-options
					:mtype 5
					:restof
					`(
					  (:subnet 255 255 255 0)
					  (:routers ,(this-ip))
					  (:lease-time 120)
					  (:dhcp-server ,@(this-ip))
					  (:dns-servers (8 8 8 8) (4 4 4 4)))
					)))
    (setf (options replyMsg) (encode-dhcp-options replyMsgOptions))
    replyMsg))

(defmethod handle-dhcp-message ((obj dhcp))
  (let* ((options (decode-dhcp-options (options obj)))
	 (sig
	  (list (op obj)
		(htype obj)
		(mtype options))))
    (trivia:match
	sig
      ((list 1 1 1) ;; dhcp discover
       ;; create a dhcp offer message
       (get-address obj)
       )
      ((list 1 1 3)
       (format t "dhcp request received~%")
       ;; Send the ack
       (get-ack obj)
       )
      (otherwise
       (error "handle-network-message - Unimplemented functionality ~a" sig))
      )
    )
  )

(defmethod response->buff ((obj dhcp))
  (flexi-streams:with-output-to-sequence (opp :element-type '(unsigned-byte 8))
    (stream-serialize obj opp)))

(defun create-dhcpd-handler ()
  (labels ((run ()
	     (let* ((dhcpObj (make-instance 'dhcp))
		    (buff (make-array 1024 :element-type '(unsigned-byte 8)))
		    (rsocket (usocket:socket-connect nil
						     nil
						    :protocol :datagram
						    :element-type 'char
						    ;;ocal-host "172.200.1.1"
						    :local-port *dhcp-server-port*))
		    #+nil(ssocket (usocket:socket-connect "255.255.255.255" ;;nil
						    *dhcp-client-port*
						    :protocol :datagram
						    :element-type 'char
						    ;;:local-port *dhcp-client-port*
						    ))
		    )
	       (setf (usocket:socket-option rsocket :broadcast) t)
	       (unwind-protect
		    (loop while (serve) do
			 (multiple-value-bind (buff size client receive-port)
			     (usocket:socket-receive rsocket buff 1024)
			   (format t "got request~%")
			   (setf *last* (copy-seq buff))
			   (deserialize-into-dhcp-from-buff! dhcpObj buff)
			   (let* ((m (handle-dhcp-message dhcpObj))
				  (buff (response->buff m)))
			     (format t "sending response~%")
			     (let ((nbw (usocket:socket-send rsocket buff nil ;;(length buff)
							     :port *dhcp-client-port*
							     :host  #(172 200 1 255))))
			       (format t "number of bytes sent:~a~%" nbw))
			     )
			   (force-output *standard-output*)
			   )
			 )
		 ;;(usocket:socket-close ssocket)
		 (usocket:socket-close rsocket)
		 ))))
    (run)))

(defmethod print-object ((obj dhcp) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots (op htype xid chaddr)
	obj
      (format stream "op=~a,chaddr=~X" op chaddr))
    )
  )

(defmethod find-options ((seq list))
  (search *dhcp-magic-cookie* seq))

(defmethod has-magic-cookie ((obj dhcp))
  (eq (mcookie *a*) (numex:octets->num *dhcp-magic-cookie*))
  )

(defparameter *router-table* '())

(defun make-router-if-id ()
  (trivia:match
      (mapcar #'id *router-table*)
    (() 1)
    ((trivia:guard l (listp l))
     (1+ (apply #'max L)))))

(eval-when (:COMPILE-TOPLEVEL :LOAD-TOPLEVEL :EXECUTE)
  ;; Using eval-when to Publish for macro compile using trivia:match
  (defclass router-if ()
    (
     (id :accessor id :initform (make-router-if-id) :initarg :id :documentation "An id as an easy way to access")
     (iface :accessor iface :initarg :iface  :documentation "Iface")
     (dest :accessor dest :initarg :dest  :documentation "Destination")
     (gw :accessor gw :initarg :gw  :documentation "Gateway")
     (flags :accessor flags :initarg :flags  :documentation "Flags")
     (refcnt :accessor refcnt :initarg :refcnt  :documentation "RefCnt")
     (use :accessor use :initarg :use  :documentation "Use")
     (metric :accessor metric :initarg :metric  :documentation "Metric")
     (mask :accessor mask :initarg :mask  :documentation "Mask")
     (mtu :accessor mtu :initarg :mtu  :documentation "MTU")
     (window :accessor window :initarg :window  :documentation "Window")
     (irtt :accessor irtt :initarg :irtt  :documentation "IRTT")
     (tlm :accessor tlm :initarg :tlm :initform (get-universal-time))
     (host-id :accessor host-id :initarg :host-id :initform nil
	      :documentation "Every host we manage will be marked with
     a uuid.  We will tie mac addresses and interfaces together using
     this host id)"
	      )
     )
    )

  

  )

(defclass remote-router-if (router-if)
    (
     (ipaddr :accessor ipaddr :initform nil :initarg :ipaddr)
     (un :accessor un :initform nil :initarg :un)
     (pw :accessor pw :initform nil :initarg :pw)
     )
    )

(defmethod print-object ((obj router-if) out)
  ;; 12/17/17 -- removing this.  no more frame-slot
  (print-unreadable-object (obj out :type t)
    (format out "[~a :id ~a :dest ~a :gw ~a :mask ~a :tlm ~a]"
	    (iface obj) (id obj) (dest obj) (gw obj) (mask obj)
	    (- (get-universal-time) (tlm obj))
	    )
    )
  )


(defun get-route (piface pdest pmask pgw)
  (find-if (trivia:lambda-match
	     ((router-if iface dest mask gw)
	      (and (equal iface piface)
		   (equalp mask pmask)
		   (equalp dest pdest)
		   (equalp gw pgw))))
	   *router-table*))

(defun get-routes ()
  (let ((results (ssh:with-connection
		     (conn "192.168.11.1" (ssh:pass "root" "locutusofborg"))
		   (ssh:with-command
		       (conn iostream "cat /proc/net/route")
		     (loop
			for l = (read-line iostream nil)
			while l
			collect (ppcre::split "\\s+" l))))))
    (cons
     (car results)
     (mapcar
      (trivia:lambda-match
	((list iface dest gate flags refcnt use metric mask mtu window irtt)
	 (make-instance 'router-if
			:iface iface
			:dest (numex:string->octet-list dest)
			:gw (numex:string->octet-list gate)
			:flags flags
			:refcnt refcnt
			:use use
			:metric metric
			:mask (numex:string->octet-list mask)
			:mtu mtu
			:window window
			:irtt irtt
			:tlm (get-universal-time))
	 ))
      (cdr results))
     ))
  )

(defmethod remove-route ((rte router-if))
  (ssh:with-connection
      (conn "192.168.11.1" (ssh:pass "root" "locutusofborg"))
    (ssh:with-command
	(conn iostream (format nil "route del -net ~a gw ~a netmask ~a dev ~a" (dest rte) (gw rte) (mask rte) (iface rte)))
      (loop
	 for l = (read-line iostream nil)
	 while l
	 collect (ppcre::split "\\s+" l))))
  )

(defmethod route-add-cmd ((rte router-if))
  (format nil "route add -net ~a gw ~a netmask ~a dev ~a"
			       (numex:addr->dotted (dest rte))
			       (numex:addr->dotted (gw rte))
			       (numex:addr->dotted (mask rte))
			       (iface rte))
  )

(defmethod add-route ((rte router-if))
  (ssh:with-connection
      (conn "192.168.11.1" (ssh:pass "root" "locutusofborg"))
    (ssh:with-command
	(conn iostream (route-add-cmd rte))
      (loop
	 for l = (read-line iostream nil)
	 while l
	 collect (ppcre::split "\\s+" l))))
  )

(defun setup-prototype ()
  (let ((r (make-instance 'remote-router-if
			  :ipaddr "192.168.11.1"
			  :un "root"
			  :pw "locutusofborg"
			  :dest #(192 168 12 0)
			  :gw #(192 168 11 125)
			  :mask #(255 255 255 0)
			  :iface "br0"
			  )
	  ))
    (add-route r)
    ))


