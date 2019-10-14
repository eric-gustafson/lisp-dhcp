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
   (mac		:accessor mac :initarg :mac :initform #())
   (ipnum	:accessor ipnum :initarg :ipnum :initform 0)
   (tla		:accessor tla :initarg :tla :initform (get-universal-time))
   (lease-time	:accessor lease-time :initarg :lease-time :initform  300)
   )
  )

(defmethod print-object ((obj dhcp-address) stream)
  (let ((now (get-universal-time)))
    (print-unreadable-object
	(obj stream :type t)
      (with-slots
	    (mac ipnum tla lease-time mac)
	  obj
	(format stream "~a,~a,~a,~a"
		mac
		(when (numberp ipnum)
		  (numex:num->dotted ipnum))
		(- now tla) lease-time))
      )
    )
  )

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
                              :initarg (->keyword field)
			      :initform nil
			      ))))
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
			   ;; support a number, or a list/vector octet in the field of the
			   ;; object
			   `(let ((value (,(->symbol field) obj)))
			      (etypecase
				  value
				(integer
				 (write-sequence (numex:num->octets value :length ,octets :endian :big) out))
				(sequence
				 (unless (eq (length value) ,octets)
				   (error "integer sequence size mismatch"))
				 (write-sequence value out)))
			      )
			   )
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

(defmethod mac ((dhcpObj dhcp))
  (let ((len (hlen dhcpObj)))
    (subseq (chaddr dhcpObj) 0 len)))

;;                              code generation                               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defun serve ()
  t)

(defvar *last* nil)

(defun save-binary-packet-to-file (path buff)
  (with-open-file (bout path :direction :output :element-type '(unsigned-byte 8)  :if-exists :overwrite :if-does-not-exist :create)
    (write-sequence buff bout))
  )

(defun save-last-packet ()
  (save-binary-packet-to-file "a.bin" *last*)
  )

(defun network-addr? (obj)
  (and (or (vectorp obj) (listp obj))
       (eq 5 (length obj)))
  )

(defparameter *this-net*
  (make-instance 'cidr-net
		 :cidr 24
		 :ipnum (numex:octets->num #(10 0 12 0))
		 :mask (numex:octets->num #(255 255 255 0)))
  ) 

(defparameter *pnet* ;; parent's network
  (make-instance 'cidr-net
		 :cidr 24
		 :ipnum (numex:octets->num #(10 0 1 0))
		 :mask (numex:octets->num #(255 255 255 0)))
  )

(defun this-ip ()
  (coerce (numex:num->octets (first-ip *this-net*) :endian :net) 'list)
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

(defmethod cidr-in? ((obj cidr-net) (ip integer))
  (with-slots (mask ipnum)
      obj
    (eq (logand mask ipnum) (logand mask ip))
    )
  )

(defmethod cidr-in? ((obj cidr-net) (ip-addr list))
  (cidr-in? obj (numex:octets->num ip-addr)))

(defmethod cidr-in? ((obj cidr-net) (ip-addr vector))
  (cidr-in? obj (numex:octets->num ip-addr)))

(defmethod cidr-in? ((obj cidr-net) (ip-addr string))
  (cidr-in? obj (numex:dotted->num ip-addr)))

(defmethod get-cidr ((obj string))
  "extract cidr notation from string, or nil if there isn't any"
  (ppcre:register-groups-bind (ip cidr)
      (numex:*ip-cidr-scanner* obj)
    (and ip cidr
	 (parse-integer cidr))
    )
  )

(defmethod get-net-using-cidr ((obj string))
  (ppcre:register-groups-bind (ip cidr)
      (numex:*ip-cidr-scanner* obj)
    (serapeum:and-let* ((numbits (and ip cidr
				      (parse-integer cidr)))
			(addrnum (numex:dotted->num ip))
			(mask (numex:make-cidr-mask numbits)))
      (numex:num->octets (logand mask addrnum)))
    ))
  
(defmethod get-addr-num ((obj string))
  "extract the ip address out of string"
  (numex:dotted->num obj)
  )

;; Isn't this what cidr-in really is?
(defmethod net=? ((a string) (b string))
  ;;
  (let ((a-ncbits (get-cidr a))
	(b-ncbits (get-cidr b))
	(aan (numex:dotted->num a))
	(ban (numex:dotted->num b))
	)
    (cond
      ((and (integerp a-ncbits) (integerp b-ncbits))
       (when (eq a-ncbits b-ncbits)
	 (let ((mask (numex:make-cidr-mask a-ncbits)))
	   ;; same cidr block
	   (= (logand mask aan)
	      (logand mask ban)))))
      ((or a-ncbits b-ncbits) ;; Use the cidr from either one of the parameters
       (let ((mask (numex:make-cidr-mask (or a-ncbits b-ncbits))))
	 (= (logand mask aan)
	    (logand mask ban))))
      )
    )
  )

(defmethod ip=? (a b)
  (cond
    ((numberp a)
     (ip=? (numex:num->octets a) b))
    ((numberp b)
     (ip=? a (numex:num->octets b)))
    ((stringp a)
     (ip=? (numex:dotted->vector a) b))
    ((stringp b)
     (ip=? a (numex:dotted->vector b)))
    ((and (vectorp a) (vectorp b))
     (equalp a b))
    ((listp a)
     (ip=? (coerce a 'vector) b))
    ((listp b)
     (ip=? a (coerce b 'vector)))
    (t nil)))
  
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
						     
(defun dhcp-search-allocated-by-mac (mac)
  (let ((x (find mac *dhcp-allocated-table* :key #'mac :test #'equalp)))
    (when x
      (setf (tla x) (get-universal-time))
      x)
    )
  )

(defun dhcp-allocate-ip (reqMsg net)
  ;; TODO: Handle the case whe we run out of addresses
  (or (dhcp-search-allocated-by-mac (mac reqMsg))
      (let ((f (first-ip net))
	    (l (last-ip net)))
	(loop :for ip :from f :upto l :do
	   (unless (ip-allocated? net ip)
	     (let ((addrObj (make-instance 'dhcp-address
					   :ipnum ip
					   :tla (get-universal-time)
					   :mac (mac reqMsg)
					   )))
	       (push addrObj *dhcp-allocated-table*)
	       (return-from dhcp-allocate-ip addrObj)))
	   )
	)
      )
  )

(defun deallocate-ip (net ip)
    (setf *dhcp-allocated-table* (delete ip *dhcp-allocated-table* :key #'ipnum :test #'equalp)))


(defmethod get-address ((reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (let* ((new-addr (dhcp-allocate-ip reqMsg *this-net*))
	 (replyMsg (make-instance 'dhcp
				  :op 2
				  :htype (htype reqMsg)				    
				  :hlen (hlen reqMsg)
				  :hops (hops reqMsg)
				  :xid (xid reqMsg)
				  :secs (secs reqMsg)
				  :flags (flags reqMsg)
				  :yiaddr (ipnum new-addr)
				  :siaddr  (this-ip)
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
					   (:lease-time 1800)
					   (:dhcp-server ,@(this-ip))
					   (:dns-servers (8 8 8 8) (4 4 4 4)))
					 )))
    (setf (options replyMsg) (encode-dhcp-options replyMsgOptions))
    (format t "get-address: ~a~%" (numex:num->octets (yiaddr replyMsg)))
    replyMsg))

(defmethod get-ack ((reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (format t "get-ack: ~a~%" (numex:num->octets (yiaddr reqMsg)))
  (let* ((new-ip (dhcp-allocate-ip reqMsg *this-net*))
	 (replyMsg (make-instance 'dhcp
				 :op 2
				 :htype (htype reqMsg)				    
				 :hlen (hlen reqMsg)
				 :hops (hops reqMsg)
				 :xid (xid reqMsg)
				 :secs (secs reqMsg)
				 :flags (flags reqMsg)
				 :yiaddr (numex:octets->num #(10 0 12 3) :endian :net)
				 ;; They send 0.0.0.0 back ...
				 ;;(yiaddr reqMsg) #+nil(numex:octets->num (numex:num->octets
				 ;;(ipnum new-ip) :endian :net) :endian :net)
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
					  (:lease-time ,(* 3600 2))
					  (:dhcp-server ,@(this-ip))
					  (:dns-servers (8 8 8 8) (4 4 4 4)))
					))
	 )
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
       (format t "dhcp discover received~%")       
       (let ((offer (get-address obj)))
	 (format t "returning dhcp offer~%")
	 offer)
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

(defun local-host-addr ()
  #+(or ccl) (return-from local-host-addr "255.255.255.255")
  (numex:addr->dotted (this-ip)))
  
(defun dhcpd ()
  (labels ((run ()
	     (let* ((dhcpObj (make-instance 'dhcp))
		    (buff (make-array 1024 :element-type '(unsigned-byte 8)))
		    (rsocket (usocket:socket-connect nil
						     nil
						     :protocol :datagram
						     :element-type '(unsigned-byte 8) ;;char
						     :local-host (local-host-addr)
						     :local-port *dhcp-server-port*))
		    )
	       (format t "~a created~%" rsocket)
	       (setf (usocket:socket-option rsocket :broadcast) t)
	       (format t "broadcast enabled~%")
	       (unwind-protect
		    (loop while (serve) do
			 (multiple-value-bind (buff size client receive-port)
			     (usocket:socket-receive rsocket buff 1024)
			   (handler-case
			       (progn
				 (format t "got request~%")
				 (setf *last* (copy-seq buff))
				 (deserialize-into-dhcp-from-buff! dhcpObj buff)
				 (let* ((m (handle-dhcp-message dhcpObj))
					(buff (response->buff m)))
				   (format t "sending response:~a~%" (numex:num->octets (yiaddr m)))
				   (setf (usocket:socket-option rsocket :broadcast) t)			     
				   (let ((nbw (usocket:socket-send
					       rsocket buff (length buff)
					       :port *dhcp-client-port*
					       :host #(10 0 12 255)
					       ;;:host  (coerce (this-ip) 'vector)
					       )))
				     (format t "number of bytes sent:~a~%" nbw))
				   )
				 (force-output *standard-output*)
				 )
			     (error (c)
			       (syslog:log "dhcp-server" :user :warning "Error parsing or processing dhcp message")
			       (syslog:log "path ~a"
					   (uiop/stream:with-temporary-file (:stream bout :element-type '(unsigned-byte 8))
					     (write-sequence buff bout)
					     ))
			       (values nil c))
			     )
			   ))
		 ;;(usocket:socket-close ssocket)
		 (usocket:socket-close rsocket)
		 ))))
    (run)))

(defun run ()
  (bt:make-thread #'create-dhcpd-handler :name "dhcp thread"))

(defmethod print-object ((obj dhcp) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots (op yiaddr ciaddr htype xid chaddr)
	obj
      (format stream "op=~a,ciaddr=~a,yiaddr=~a,chaddr=~X"
	      op
	      (or (and (numberp ciaddr)
		       (numex:num->octets ciaddr :endian :net))
		  nil)
	      (or (and (numberp yiaddr)
		       (numex:num->octets yiaddr :endian :net))
		  nil)
	      chaddr))
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
  (let ((results (catch/log
		  (ssh:with-connection
		      (conn "10.0.1.1" (ssh:pass "root" "locutusofborg"))
		    (ssh:with-command
			(conn iostream "cat /proc/net/route")
		      (loop
			 for l = (read-line iostream nil)
			 while l
			 collect (ppcre::split "\\s+" l)))))))
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
  (catch/log
   (ssh:with-connection
       (conn "10.0.1.1" (ssh:pass "root" "locutusofborg"))
     (ssh:with-command
	 (conn iostream (format nil "route del -net ~a gw ~a netmask ~a dev ~a" (numex:addr->dotted (dest rte)) (numex:addr->dotted (gw rte)) (numex:addr->dotted (mask rte)) (iface rte)))
       (loop
	  for l = (read-line iostream nil)
	  while l
	  collect (ppcre::split "\\s+" l))))
       ))

(defmethod route-add-cmd ((rte router-if))
  (format nil "route add -net ~a gw ~a netmask ~a dev ~a"
			       (numex:addr->dotted (dest rte))
			       (numex:addr->dotted (gw rte))
			       (numex:addr->dotted (mask rte))
			       (iface rte))
  )

(defmethod add-route ((rte router-if))
  (catch/log
   (ssh:with-connection
       (conn "10.0.1.1" (ssh:pass "root" "locutusofborg"))
     (ssh:with-command
	 (conn iostream (route-add-cmd rte))
       (loop
	  for l = (read-line iostream nil)
	  while l
	  collect (ppcre::split "\\s+" l))))
       ))

(defparameter *firewall-reset-cmds* (list
				     "/usr/sbin/iptables -P INPUT ACCEPT"
				     "/usr/sbin/iptables -P FORWARD ACCEPT"
				     "/usr/sbin/iptables -P OUTPUT ACCEPT"
				     "/usr/sbin/iptables -t nat -F"
				     "/usr/sbin/iptables -t mangle -F"
				     "/usr/sbin/iptables -F"
				     "/usr/sbin/iptables -X"))

(defun generate-nat-commands (external-if internal-if)
  (append
   *firewall-reset-cmds*
   (list

    "echo 1 > /proc/sys/net/ipv4/ip_forward"
    (format nil "/usr/sbin/iptables -t nat -F")
    (format nil "/usr/sbin/iptables -t mangle -F")
    ;;(format nil "/usr/sbin/iptables -t nat -A POSTROUTING -o ~a -j SNAT --to 192.168.1.8" external-if)
    (format nil "/usr/sbin/iptables -t nat -A POSTROUTING -o ~a -j MASQUERADE" external-if)
    ;;(format nil "/usr/sbin/iptables -A FORWARD -i ~a -o ~a -m state --state RELATED,ESTABLISHED -j ACCEPT" external-if internal-if)
    ;;(format nil "/usr/sbin/iptables -A FORWARD -i ~a -o ~a -j ACCEPT" internal-if external-if)
    ;;(format nil "/usr/sbin/iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    ;;(format nil "/usr/sbin/iptables -A FORWARD -i ~a -o ~a -j ACCEPT" internal-if external-if)
    
    )
   )
  )


(defmacro catch/log (&body body)
  ;; #+nil(handler-case
  ;;      (progn
  ;; 	 ,@body)
  ;;    (error (c)
  ;;      (format *standard-output*
  ;; 	       "We caught a condition. ~&")
  ;;      (force-output *standard-output*)
  ;;      (values nil c)))
  `(progn
     ,@body
     )
  )
  

(defun disable-firewall (external-if internal-if)
  (catch/log
    (ssh:with-connection
       (conn "10.0.1.1" (ssh:pass "root" "locutusofborg"))
     (loop :for command :in (generate-nat-commands external-if internal-if)  :do
	(catch/log
	 (ssh:with-command
	     (conn iostream command)
	   (loop
	      for l = (read-line iostream nil)
	      while l
	      do (print l *standard-output*))
	   ))
	)
     )))

(defun network-watchdog ()
  (let ((channel (lparallel:make-channel)))
    ;;(submit-task channel '+ 3 4)
    (future
     (loop
	(lparallel:try-receive-result channel :timeout (* 1 600))
	)))
  )

;;(defvar *hostapd-proc-obj* '())

#+nil(defun hostapd (iface)
  ;; Geneate and save hostapd file
  (with-open-file (hfile #P"/tmp/hostapd.conf"
			 :direction :output
			 :if-exists :overwrite
			 :if-does-not-exist :create
			 ;;:element-type 'character ;'(unsigned-byte 8)
			 :external-format :utf-8
			 )
    (princ (lsa:hostapd iface) hfile))
  (setf *hostapd-proc-obj*
	(uiop:launch-program "/usr/sbin/hostapd -d /tmp/hostapd.conf"
			     :output :interactive :error-output :interactive))
  )

;; (defun hostapd-down ()
;;   (when *hostapd-proc-obj*
;;     (uiop:terminate-process *hostapd-proc-obj* :urgent t)
;;     (uiop:wait-process *hostapd-proc-obj*)
;;     (setf *hostapd-proc-obj* nil)
;;     )
;;   )

(defun not-local-host-ip-addr-objs ()
  (serapeum:filter
   #'(lambda(obj)
       (trivia:match
	   obj
	 ((lsa:ip-addr :addr addr)
	  (not (ip=? addr #(127 0 0 1))))))
   (lsa::ip-addr-objs))
  )
  
(defun get-ip-of-this-hosts-lan-card ()
  (trivia:match
      (not-local-host-ip-addr-objs)
    ((cons first rest)
     first)
    )
  )

(defun connected-ip ()
  (get-ip-of-this-hosts-lan-card))


(progn
  (defvar *machine-class* nil)
  (defun machine-class ()
    (cond
      ((null *machine-class*)
       (let ((uname-string (inferior-shell:run/s "uname -a")))
	 (cond
	   ((ppcre:scan "yocto" uname-string)
	    (setf *machine-class* `(:yocto :bbb)))
	   )
	 ))
      (t
       *machine-class*)))
  )

(defun get-wifi-gateway-candidates ()
  "filter out localhost and ip address of the network we are bringing up"
  (serapeum:filter
   (trivia:lambda-match
     ((lsa:link :state sstate :name name)
      (and
       (or (ppcre:scan "wlx.*" name)
	   (ppcre:scan "wlan" name))
       (string-equal (string-upcase sstate) "DOWN"))
      ))
   (lsa:ip-link-objs)
   )
  )

(defun calc-next-hop-ip (ip)
  (trivia:cmatch
      ip
    ((vector a b c d)
     (vector a b c 1))))


(defun configure-parent-router ()
  ;; This is a primary use case.  Get this working and we can go
  ;; to the next level of testing/developing.
  (let* ((neo (get-ip-of-this-hosts-lan-card))
	 (this-addr (numex:dotted->vector (lsa:addr neo)))
	 (mesh-parent (calc-next-hop-ip this-addr))
	 ;;(mesh-net (get-net-using-cidr mesh-parent))
	 (r (make-instance 'remote-router-if
			   :ipaddr mesh-parent
			   :un "root"
			   :pw "locutusofborg"
			   :dest #(10 0 12 0)
			   :gw this-addr ;; #(192 168 11 125)
			   :mask #(255 255 255 0)
			   ;; this is the interface on the router,
			   ;; not this host
			   :iface "br0" 
			   )
	   ))
    (loop :for re in (cdr (get-routes)) :do
       (if (equal '(10 0 12 0) (dest re))
	   (remove-route re)))
    (add-route r)
    (disable-firewall "eth1" "br0")
    )
  )  

(defun hostapd-file ()
  "/etc/hostapd/hostapd.conf")

(defun find-and-kill-wpa-supplicant ()
  1)


(defun setup-hostapd ()
  (serapeum:and-let*
      ((x (car (get-wifi-gateway-candidates)))
       (filename (hostapd-file))
       (pathname (pathname filename)))
    (uiop:ensure-all-directories-exist (list pathname))
    (with-open-file
	(out  pathname
	      :direction :output
	      ;;:element-type :utf-8 ;;'(unsigned-byte 8)
	      :if-exists :supersede
	      :if-does-not-exist :create)
      (princ
       (lsa:hostapd (lsa:name x)
		    "g3"
		    "bustergus25")
       out)
      ))
  )

;; wlx9cefd5fdd60e
(defun compute-wifi-interface ()
  (let ((uname-string (inferior-shell:run/s "uname -a")))
    (cond
      ((ppcre:scan "yocto" uname-string)
       "wlan0"))
    
    ))

(defun unblock-wifi ()
  ""
  (handler-case
      (inferior-shell:run/s "rfkill unblock all")
    (t (c)
      (format t "We caught a condition.~&")
      (values nil c)))
  )

(defun run-hostapd-in-background ()
  (handler-case
      (inferior-shell:run/s (format nil "hostapd  ~a &" (hostapd-file)))
    (t (c)
      (format t "Error running hostapd in background: ~&")
      (values nil c)))
  )

(defun nat-routing ()
  (handler-case
      (loop :for cmd :in 
	 (list "echo 1 > /proc/sys/net/ipv4/ip_forward"
	       "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
	       "iptables -A FORWARD -i wlan0 -j ACCEPT")
	 :do
	 (inferior-shell:run/s cmd))
    (t (c)
      (format t "Error condition in nat-routing: ~&")
      (values nil c)
      )
    ))

  
(defun setup-prototype ()
  (unless lparallel:*kernel*
    (setf lparallel:*kernel* (lparallel:make-kernel 4)))
  (handler-case 
      (inferior-shell:run/s (format nil "/sbin/ip addr add ~a/24 brd + dev ~a" (numex:addr->dotted (this-ip)) (compute-wifi-interface)))
    (t (c)
      (format t "Error condition setting ip address.~&")
      (values nil c)
      ))
  (unblock-wifi)
  (run-hostapd-in-background)
  (nat-routing)
  ;;(network-watchdog)
  ;;(configure-parent-router)
  )

(defun apply-configuration ()
  ;; macchager --mac oldmac+1
  (inferior-shell:run/lines "ifdown --force wlan0 && ifdown --force ap0")
  (inferior-shell:run/lines "wpa_cli reconfigure")
  ;;(inferior-shell:run/lines "systemctl restart dnsmasq")
  ;;(inferior-shell:run/lines "systemctl restart hostapd") 
  )

