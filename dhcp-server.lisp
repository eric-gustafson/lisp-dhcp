;;;; dhcp-server.lisp
(in-package #:dhcp)

(defconstant +dhcp-server-port+ 67)

(defvar *dhcp-iface-ip-addresses* '()
  "We broadcast DHCP messages only to interfaces that have these
  IPs. These values are cidr-net objects from the numex package")

(defmethod alog ((str string) &rest args)
  (syslog:log "dhcp-server" :user :warning (apply #'format (cons nil (cons str args)))))

(defclass cidr-net ()
  ;; A network defined using cidr notation
  ;;
  (
   (ipnum :accessor ipnum :initarg :ipnum)
   (cidr :accessor cidr :initarg :cidr)
   (cidr-subnet :accessor cidr-subnet :initarg :cidr-subnet)
   (mask :accessor mask :initarg :mask)
   (broadcast :accessor broadcast :initarg :broadcast)
   ;;  A mac=>dhcp-address hash
   (reservations :accessor reservations :initarg :reservations :initform (make-hash-table :test #'equalp)
		 :documentation "A map of mac addresses to
		 dhcp-address objects.  The mac adress is represented
		 as a list of numbers" ) )
  )


(defclass dhcp-address ()
  (
   (mac		:accessor mac :initarg :mac :initform #())
   (ipnum	:accessor ipnum :initarg :ipnum :initform 0 :documentation "A machine number representing an IP address")
   (tla		:accessor tla :initarg :tla :initform (get-universal-time))
   (lease-time	:accessor lease-time :initarg :lease-time :initform  300)
   )
  )

(export '(cidr-net cidr ipnum cidr-subnet mask broadcast reservations
	  mac ipnum tla lease-time dhcp-address ))


(defmethod print-object ((obj dhcp-address) stream)
  (let ((now (get-universal-time)))
    (print-unreadable-object
	(obj stream :type t)
      (with-slots
	    (mac ipnum tla lease-time mac)
	  obj
	(format stream "~a,~a,~a,~a"
		(numex:octet-list->hexstr mac)
		(when (numberp ipnum)
		  (numex:num->dotted ipnum))
		(- now tla) lease-time))
      )
    )
  )


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

#+nil(defparameter *this-net*
  (make-instance 'cidr-net
		 :cidr 8
		 :cidr-subnet 24
		 :ipnum (numex:octets->num #(10 0 0 0))
		 :mask (numex:octets->num #(255 255 0 0)))
  )


#+nil(defun this-ip ()
  (coerce (numex:num->octets (first-ip *this-net*) :octets-endian :net) 'list)
  )

(defmethod compute-servers-ip-for-address ((net cidr-net) client-addr)
  "Get the router IP address (as a list in network byte order) for the subnet we share with the client address."
  (cond
    ((eq 'dhcp-address (type-of client-addr))
     (compute-servers-ip-for-address net (ipnum client-addr)))
    ((numberp client-addr)
     (coerce (numex:num->octets (+ 1 (numex:cidr-net client-addr (cidr net)))
				:octets-endian :net) 'list))
    (t
     (error "compute-servers-ip-for-address -- unexpected parameter ~a" client-addr)))
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
  (loop :for o :across (numex:num->octets num :octets-endian :net)
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

(defmethod address-list ((obj cidr-net))
  "returns a list of ip addresses for the object"
  (let ((mask (mask obj)))
    (loop :for i :upto mask :collect (+ (ipnum obj) i)))
  )

(defmethod broadcast-address ((obj cidr-net))
  "Returns the broadcast address for the object"
  (+ (ipnum obj) (mask obj))
  )

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

(defparameter *net-allocation-table* (make-hash-table :test #'equalp)
  
  )

(export 'get-all-dhcp-networks)
(defun get-all-dhcp-networks ()
  "return all of the dhcp networks from all of the interfaces"
  (apply #'append (mapcar #'alexandria:hash-table-values (alexandria:hash-table-values dhcp::*net-allocation-table*)))
  )

(defgeneric get-net-allocation-table (netobj)
  (:documentation "Returns a hashtable of the IP addresses we have
sent out on the interface represented by 'netobj'.  There values are
all dhcp-address objects, and for each object there will be two keys
in the table pointing to an instance.  A 'mac' key is a list of
integers ala (180 213 189 19 125 186).  A numerical IP
address (machine integer representation) is the second key.")
  (:method ((net cidr-net))
    (serapeum:ensure (gethash net *net-allocation-table*) (make-hash-table :test #'equalp))
    )
  )

;;(export '*dhcp-allocated-table*)
(export '(get-net-allocation-table *net-allocation-table*))

(defgeneric make-dhcp-address (net ip mac)
  (:documentation "Create a new dhcp-address object, and update the
  keys in the *net-allocation-table*")
  (:method ((net cidr-net) (ip number) (mac list))
    (let ((addrObj (make-instance 'dhcp-address
				  :ipnum ip
				  :tla (get-universal-time)
				  :mac mac
				  )))
      (setf (gethash (ipnum addrObj) (get-net-allocation-table net)) addrObj)
      (setf (gethash (mac addrObj) (get-net-allocation-table net)) addrObj)
      addrObj))
  (:method ((net cidr-net) (ip number) (mac string))
    (make-dhcp-address net ip (numex:hexstring->octets mac)))
  )

(defmethod ipnum-reservations ((net cidr-net))
  (alexandria:hash-table-values (reservations net)))

(defgeneric ip-allocated? (net ip)
  (:documentation "Search the reservation system and then the
  allocated hash to determine if this ip has been allocated.  It
  returns the dhcp-addres object if found, nil otherwise.")
  (:method ((net cidr-net) (ip number))
    (or (find ip (ipnum-reservations net))
	(gethash ip (get-net-allocation-table net))
	)
    )
  )

(defgeneric dhcp-search-allocated-by-mac (net mac)
  (:documentation "Search an interface represented by the 'net'
  parameter for an IP address that has been assigned to the 'mac'")
  (:method ((net cidr-net) (mac sequence))
    (let ((x (gethash mac (get-net-allocation-table net))))
      (when x
	(setf (tla x) (get-universal-time))
	x)
      )
    )
  )

(defgeneric search-cidr-net-reservations (net-obj mac)
  (:documentation "Searches the cidr-net object for a dhcp
  reservation. If one is found, it returns a type of dhcp-address,
  otherwise NIL")
  (:method ((net-obj cidr-net) (mac list))
    (gethash mac (reservations net-obj))
    )
  )

(define-condition address-allocated (error)
 ((ip :initarg :ip
      :initform nil
      :reader ip)) ;; <-- we'll get the dividend with (dividend condition). See the CLOS tutorial if needed.
  (:documentation "The IP address is allocatted and in use.")
  )

(define-condition ip-cidr-net-incompatible (error)
  (
   (ip :initarg :ip
      :initform nil
       :reader ip)
   (cidr-addr :initarg cidr-addr :initform nil :reader cidr-addr)
   (cidr :initarg cidr :initform nil :reader cidr)
   )
  (:documentation "The IP address is incompatible with the cidr-net.")  
  )

(defgeneric add-cidr-net-reservation! (net-obj mac addr)
  (:documentation "Add a mac->addr reservation.  The address must be
  in the net-obj's cidr definition.  Throws an address-allocated error
  if the address is already in use.")
  (:method ((net-obj cidr-net) (mac string) (ip string))
    (let ((mac (numex:hexstring->octets mac))
	  (ip (numex:->num ip)))
      (when (dhcp-search-allocated-by-mac net-obj mac)
	(error (make-condition 'address-allocated :ip ip)))
      #+nil(unless (cidr-in? net-obj ip)
	(error (make-condition 'ip-cidr-net-incompatible
			       :ip ip
			       :cidr-addr (ipnum net-obj)
			       :cir (cidr net-obj))))
      (let ((addrObj (make-dhcp-address net-obj ip mac)))
	(setf (gethash mac (reservations net-obj)) addrObj)
	)))
  )

(defun get-all-reservations ()
  "Returns all of the dhcp reservations for the engine"
  (mapcar #'alexandria:hash-table-values (apply #'append (mapcar #'reservations *dhcp-iface-ip-addresses*)))
  )

(defmethod subnets ((net-obj cidr-net) &key cidr)
  (let ((f (first-ip net-obj))
	(l (last-ip net-obj))
	(subnet-size (expt 2 (- 32 cidr) )))
    ;; Subtrack 1 additional from the upto number, to account for
    ;; the subnet broadcast
    (loop :for ip :from f :upto  l :by subnet-size
	  :collect
	  (make-instance 'cidr-net
			 :ipnum ip
			 :cidr cidr
			 :broadcast (logior ip (- subnet-size 1))
			 :mask (numex:make-cidr-mask cidr))
	  ))
    )

(defmethod addresses ((net-obj cidr-net))
  ;;"returns a list of all of the addreses in the cidr-net"
  (loop :for ip :from (first-ip net-obj) :upto (last-ip net-obj) :collect ip)
  )

(defmethod subnet-info ((net-obj cidr-net) subnet-num)
  "f=ma like stuff"
  (list :num-nets (floor (/ (- (last-ip net-obj) (first-ip net-obj)) subnet-num))
	)
  )

(defmethod dhcp-addresses ((net-obj cidr-net))
  "returns a list of ip addresses that will be dished out by the system"
  (let ((net-increment (logand #xffffffff (lognot (mask net-obj)))))
    (declare (integer net-increment))
    (let ((f (first-ip net-obj))
	  (l (last-ip net-obj)))    
      (loop :for ip :from f :upto l :by 4 :collect ip))
    )
  )

#+nil(defparameter *dhcp-nets*
  (numex:cidr-subnets
   (first-ip *this-net*)
   (cidr *this-net*)
   ;;(cidr-subnet *this-net*)
   :n 16
   )
  ""
  )

(defun addr-count ()
  (with-input-from-string (x (inferior-shell:run/s "ip addr | grep inet  | wc"))
    (read x)))

#+nil(defun teardown-dhcp-network-interfaces (iface)
  (loop
     :for ipn in (cdr *dhcp-nets*)
     :do
     (lsa:del-vlan iface (+ 1 ipn) 24))
  )

(defvar *hook-ip-allocated* nil
  "Invoked when an IP address is allocated.  Has")

(defgeneric dhcp-generate-ip (net mac)
  (:documentation
   "For prototyping, we allocate an IP address 1 time to a mac-address,
and it's always allocated untile the server is restarted.")
  (:method ((net cidr-net) (mac list) )
    ;; TODO: Handle the case whe we run out of addresses
    (loop
      :for ip in (numex:cidr-subnets
		  (first-ip net)
		  (cidr net)
		  :n 16)
      :do
	 (incf ip 2)
	 (unless (ip-allocated? net ip)
	   (let ((addrObj (make-dhcp-address net ip mac)))
	     (handler-case
		 (serapeum:run-hook '*hook-ip-allocated*
				    (ipnum addrObj)
				    (mac addrObj))
	       (t (c)
		 (alog "Error in dhcp-ip-allocated chain ~a" c)
		 (values nil c)))
	     (return-from dhcp-generate-ip addrObj)))
      )
    nil)
  (:method ((mac string) (net cidr-net))
    (dhcp-generate-ip net (numex:hexstring->octets  mac) ))
  )

;; TODO: Handle the case whe we run out of addresses
(defgeneric dhcp-allocate-ip-via-mac (net mac)
  (:documentation "A lower level function that doesn't have anything
  to do with dhcp per say, so we can test schemes, unit test, and run
  simulations and the like")
  (:method ((net cidr-net) (mac list) )
    (alexandria:when-let* ((value (or (dhcp-search-allocated-by-mac net mac)
				      (search-cidr-net-reservations net mac)
				      )))
      (return-from dhcp-allocate-ip-via-mac value))
    (or
     (dhcp-generate-ip net mac )
     (error "Out of ip addresses")
     )
    )
  )

;;  "Search for an unallocated ip within the range defined in the cidr-net object."
(defgeneric dhcp-allocate-ip (reqmsg net)
  (:documentation "For prototyping, we allocate an IP address 1 time to a mac-address,
and it's always allocated untile the server is restarted.")
  (:method ((reqMsg dhcp) (net cidr-net))
    (dhcp-allocate-ip-via-mac net (mac reqMsg))
    )
  )

(defun deallocate-ip (net ip)
  (let ((obj (gethash ip (get-net-allocation-table net))))
    (remhash (mac obj) (get-net-allocation-table net))
    (remhash (ipnum obj) (get-net-allocation-table net))
    ))

(defmethod make-dhcp-offer ((net-obj cidr-net) (reqMsg udhcp))
  "return an DHCP 'offer' to be broadcast that provides an IP address"
  (let* ((new-addr (dhcp-allocate-ip reqMsg net-obj))
	 (replyMsg (make-instance 'udhcp
				  :op +MSG-TYPE-DHCPOFFER+
				  :htype (htype reqMsg)				    
				  :hlen (hlen reqMsg)
				  :hops (hops reqMsg)
				  :xid (xid reqMsg)
				  :secs (secs reqMsg)
				  :flags (flags reqMsg)
				  :yiaddr (ipnum new-addr)
				  :siaddr  (compute-servers-ip-for-address net-obj new-addr)
				  :giaddr (giaddr reqMsg)
				  :chaddr (chaddr reqMsg)
				  :ciaddr (ciaddr reqMsg)
				  :mcookie (mcookie reqMsg)
				  :file (file reqMsg)
				  :sname (sname reqMsg)
				  :options-obj (make-instance 'dhcp-options
							      :mtype +MSG-TYPE-DHCPOFFER+
							      :restof
							      `(
								(:subnet 255 255 255 0)
								(:routers ,(compute-servers-ip-for-address net-obj new-addr))
								(:lease-time 1800)
								(:dhcp-server ,@(compute-servers-ip-for-address net-obj new-addr))
								(:dns-servers (8 8 8 8)))
							      ))))
    (alog (format nil "make-dhcp-offer: ~a~%" (numex:num->octets (yiaddr replyMsg))))
    replyMsg))

(defmethod handle-dhcp-request ((reqMsg udhcp))
  ;; From Wikipedia
  ;; 
  ;; In response to the DHCP offer, the client replies with a
  ;; DHCPREQUEST message, broadcast to the server,[a] requesting the
  ;; offered address. A client can receive DHCP offers from multiple
  ;; servers, but it will accept only one DHCP offer. Based on
  ;; required server identification option in the request and
  ;; broadcast messaging, servers are informed whose offer the client
  ;; has accepted.[10]:Section 3.1, Item 3 When other DHCP servers
  ;; receive this message, they withdraw any offers that they have
  ;; made to the client and return the offered IP address to the pool
  ;; of available addresses.
  1
  ;; TODO: look @ the mac address, and the parameters.
  ;; If the client did not accept our offer, then don't
  ;; send the ack, and don't
  )
  
(defmethod get-ack ((net-obj cidr-net) (reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (alog (format nil "get-ack: yiaddr:~a,siaddr:~a,ciaddr:~a~%"
		(numex:num->octets (yiaddr reqMsg))
		(numex:num->octets (siaddr reqMsg))
		(numex:num->octets (ciaddr reqMsg))
		))
  (let* ((new-ip (dhcp-allocate-ip reqMsg net-obj))
	 (replyMsg (make-instance 'udhcp
				 :op 2
				 :htype (htype reqMsg)				    
				 :hlen (hlen reqMsg)
				 :hops (hops reqMsg)
				 :xid (xid reqMsg)
				 :secs (secs reqMsg)
				 :flags (flags reqMsg)
				 :yiaddr (ipnum new-ip)				 
				 ;; They send 0.0.0.0 back ...
				 ;;(yiaddr reqMsg) #+nil(numex:octets->num (numex:num->octets
				 ;;(ipnum new-ip) :endian :net) :endian :net)
				 :siaddr (compute-servers-ip-for-address net-obj new-ip) 
				 :giaddr (giaddr reqMsg)
				 :chaddr (chaddr reqMsg)
				 :ciaddr (ciaddr reqMsg)
				 :mcookie (mcookie reqMsg)
				 :file (file reqMsg)
				 :sname (sname reqMsg)
				 :options-obj (make-instance 'dhcp-options
							     :mtype 5
							     :restof
							     `(
							       (:subnet 255 255 255 0)
							       (:routers ,(compute-servers-ip-for-address net-obj new-ip))
							       (:lease-time 1800)
							       (:dhcp-server ,@(compute-servers-ip-for-address net-obj new-ip))
							       (:dns-servers (8 8 8 8)))
							     ))))
    replyMsg))

#+nil(defun local-host-addr ()
  #+(or ccl) (return-from local-host-addr "255.255.255.255")
  (numex:->dotted (this-ip)))

(defmethod compute-destination-net-addresses-for-dhcp-response ((m dhcp))
  "Compute a list of network addresses to send the dhcp-response"
  )

(defmethod handle-dhcpd-message ((net-obj cidr-net) (client-msg-dhcp-obj udhcp))
   ;;"handle dhcp server messages.  dished out an ip address, which is embedded in the return message"
  (let* ((dhcp-type (msg-type client-msg-dhcp-obj)))
    (alog (format nil "dhcpd msg type ~a" dhcp-type))
    (ecase
	dhcp-type
      (:discover
       (make-dhcp-offer net-obj client-msg-dhcp-obj))
      (:request
       (handle-dhcp-request client-msg-dhcp-obj)
       (get-ack net-obj client-msg-dhcp-obj))
      (:discover-decline
       (alog (format nil "client has declined our offer ~a ~a"
		     (ciaddr client-msg-dhcp-obj)
		     (yiaddr client-msg-dhcp-obj)
		     ))
       ;;(deallocate-ip net-obj (ciaddr client-msg-dhcp-obj))
       nil
       )
      (:nack
       (alog "dhcp nack")
       )
      (:info
       (alog "dhcp info")
       )
      )
    )
  )

(defun update-dhcps-iface-ip-addresses! (cidr-net-list)
  "The DHCP communicates via network broadcasts, since the clients to
this service do not have IP addresses.  We only send/respond to
interfaces that have an IP address and that have been 'marked'"
  (loop :for cidr :in cidr-net-list :do
       (unless (equal (type-of (car cidr)) 'numex:cidr-net)
	 (error "Illegal parameter type ~a" (car cidr))))
  (serapeum:synchronized (*dhcp-iface-ip-addresses*)
    (setf *dhcp-iface-ip-addresses* (mapcar #'car cidr-net-list))
    (loop :for (cidr . if-mac) :in cidr-net-list
	  :for i :from 1
	  :do
      (let ((ipnum (first-ip cidr)))
	(make-dhcp-address cidr
			   ipnum
			   (if if-mac
			       if-mac
			       (list 0 0 0 0 0 i)))
	))
    )
  )

;; TODO: (GUS 2020-09-24) extract the gaddr address and use that as
;; the destination if this was sent by a dhcp gateway
(defmethod dest-addr ((m udhcp) (destination-net cidr-net))
  "Returns who we should send the response back to.  This handles dhcp
gateways that forward dhcp packets from subnets and the like, by
increasing the HOP count and setting the giaddr field.  If this
message was a result of a local broadcast message, then it uses the
destination-net when formulating the broadcast response."
  (let* ((giaddr (giaddr m))
	 (hops (hops m))
	 (ip-num
	   (cond
	     ((and (> hops 0) (> giaddr 0))
	      (numex:num->octets giaddr)
	      )
	     (t
	      (cidr-bcast (yiaddr m)
			  ;;(dhcp:cidr-subnet destination-nets)
			  (cidr destination-net)
			  )))))
    (coerce ip-num 'vector)))
(export 'dest-addr)

		   
(defun dhcp-handler (rsocket buff size client receive-port)
  "A dhcp message was received"
  (alog "dhcp-server-pdu-handler")
  (setf *last* (copy-seq buff))
  (let* ((dhcpObj (pdu-seq->udhcp buff))
	 )
    (when (null *dhcp-iface-ip-addresses*)
	(alog "dhcp-handler - no interfaces marked for dhcps"))
    (loop :for destination-nets :in *dhcp-iface-ip-addresses* :do
      (let ((m (handle-dhcpd-message destination-nets dhcpObj)))
	(when m
	  (let* ((response-type (msg-type m))
		 (buff (obj->pdu m))
		 (destination-address (dest-addr m destination-net)))
	    (alog "snd type=~a, to addr: ~a via ~a" response-type (numex:num->octets (yiaddr m)) destination-address)
	    (setf (usocket:socket-option rsocket :broadcast) t)
	    (let ((nbw (usocket:socket-send
			rsocket buff (length buff)
			:port +dhcp-client-port+
			:host destination-address
			)))
	      (alog (format nil "number of bytes sent:~a~%" nbw))
	      )
	    )
	  )
	)
	  )
    )
  )

(defvar *server-socket-table* (serapeum:dict))

(defun server-socket (&key (port +dhcp-server-port+))
  "Returns a server socket for the given port. It's a singleton on the
port number.  Asking for the same port gets you the same object"
  (serapeum:ensure
      (gethash port *server-socket-table*)
    (let ((sock-obj (usocket:socket-connect nil
					    nil
					    :protocol :datagram
					  :element-type '(unsigned-byte 8) ;;char
					  :local-host
					  #+(or sbcl)nil
					  #+(or ccl)"255.255.255.255" ;;(local-host-addr)
					  :local-port port)))
      (setf (usocket:socket-option sock-obj :broadcast) t)
      sock-obj))
  )

(defvar *buff* (make-array 1024 :element-type '(unsigned-byte 8)))
(defun poll/async-inbound-dhcp-pdu (rsocket obj-thunk)
  "using cl-async to poll the socket for an in-bound pdu.  Returns an async poller"
  #+(or ccl sbcl)(return-from
	      poll/async-inbound-dhcp-pdu
	       (cl-async:poll
		#+sbcl(sb-bsd-sockets:socket-file-descriptor (usocket:socket rsocket))
		#+ccl(openmcl-socket:socket-os-fd (usocket:socket rsocket))		
		#'(lambda(event-named)
		    (let ((inbound-dhcp-obj (make-instance 'dhcp))
			  )
		      (multiple-value-bind (buff n client receive-port)
			  (usocket:socket-receive rsocket *buff* (array-total-size *buff*))
			(funcall obj-thunk  (subseq  buff 0 n))
			)
		      )
		    )
		:poll-for '(:readable)
		:socket t		
		)
	       )
  (error "poll4-inbound-pdu error")
  1)

(defun dhcpd (&key (port +dhcp-server-port+))
  "Listen on port for dhcp client requests"
  (let* (;;(dhcpObj (make-instance 'dhcp))
	 (buff (make-array 1024 :element-type '(unsigned-byte 8)))
	 (rsocket (server-socket :port port)))
    (let ((bcast (usocket:socket-option rsocket :broadcast)))
      (alog (format nil "socket: ~a created, bcast=~a" rsocket bcast))
      ;; GUS: 2020-02-23: Testing on a real network, turning  broadcast back on
      (setf bcast (usocket:socket-option rsocket :broadcast))
      #+nil(alog (format nil  "broadcast enabled :~a" bcast))
      (unwind-protect
	   (loop :while (serve)
	      :do
		(handler-case
		    (multiple-value-bind (buff size client receive-port)
			(usocket:socket-receive rsocket buff 1024)
		      (alog (format nil "dhcp pdu received from ~a:~a" client receive-port))
		      (dhcp-handler rsocket  buff size client receive-port)
		      )
		  (t (c)
		    (alog (format nil "Error processing dhcp request ~a ~&" c))
		    (let ((path (uiop/stream:with-temporary-file
				    (:stream bout :pathname x :keep t :element-type '(unsigned-byte 8))
				  (write-sequence buff bout)
				  x)))
		      (alog (format nil "saving dhcp message ~s" path))
		      nil))
		  ))
	(progn
	  (usocket:socket-close rsocket)
	  )
	)
      )
    )
  )

(defun catch-and-log (thunk)
  #'(lambda()
      (handler-case
	  (funcall thunk)
	(t (c)
	  (alog (format nil "~a~&" c))
	  nil))))

(defun run ()
  (alog "starting dhcp background thread")
  (bt:make-thread (catch-and-log #'dhcpd) :name "dhcp thread")
  )

(defmethod print-object ((obj dhcp) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots (op yiaddr ciaddr htype xid chaddr)
	obj
      (format stream "op=~a,ciaddr=~a,yiaddr=~a,chaddr=~X"
	      op
	      (or (and (numberp ciaddr)
		       (numex:num->octets ciaddr :octets-endian :net))
		  nil)
	      (or (and (numberp yiaddr)
		       (numex:num->octets yiaddr :octets-endian :net))
		  nil)
	      chaddr))
    )
  )

(defmethod find-options ((seq list))
  (search *dhcp-magic-cookie* seq))

(defparameter *router-table* '())

(defun make-router-if-id ()
  (trivia:match
      (mapcar #'id *router-table*)
    (() 1)
    ((trivia:guard l (listp l))
     (1+ (apply #'max L)))))

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

(defun calc-next-hop-ip (ip)
  (trivia:cmatch
      ip
    ((vector a b c d)
     (vector a b c 1))))

;; wlx9cefd5fdd60e
(defun compute-wifi-interface ()
  (let ((uname-string (inferior-shell:run/s "uname -a")))
    (cond
      ((ppcre:scan "yocto" uname-string)
       "wlan0"))
    ))

(defun apply-configuration (iface)
  ;; macchager --mac oldmac+1
  (inferior-shell:run/lines (format "ifdown --force ~a && ifdown --force ap0" iface))
  (inferior-shell:run/lines "wpa_cli reconfigure")
  ;;(inferior-shell:run/lines "systemctl restart dnsmasq")
  ;;(inferior-shell:run/lines "systemctl restart hostapd") 
  )

