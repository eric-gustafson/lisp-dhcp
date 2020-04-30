;;;; dhcp-server.lisp
(in-package #:dhcp)

(defconstant +dhcp-server-port+ 67)

(defmethod alog ((str string))
  (syslog:log "dhcp-server" :user :warning str))

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

(defparameter *dhcp-allocated-table* (make-hash-table :test #'equalp)
  "A hashtable of the IP addresses we have sent out.  There values are
all dhcp-address objects, and for each object there will be two keys
in the table pointing to an instance.  A 'mac' key is a list of
integers ala (180 213 189 19 125 186).  A numerical IP
address (machine integer representation) is the second key."
  )

(defgeneric make-dhcp-address (ip mac)
  (:documentation "Create a new dhcp-address object, and update the
  keys in the *dhcp-allocated-table*")
  (:method ((ip number) (mac list))
    (let ((addrObj (make-instance 'dhcp-address
				  :ipnum ip
				  :tla (get-universal-time)
				  :mac mac
				  )))
      (setf (gethash (ipnum addrObj) *dhcp-allocated-table*) addrObj)
      (setf (gethash (mac addrObj) *dhcp-allocated-table*) addrObj)
      addrObj))
  )

(defgeneric ip-allocated? (net ip)
  (:documentation "Search the reservation system and then the
  allocated hash to determine if this ip has been allocated.  It
  returns the dhcp-addres object if found, nil otherwise.")
  (:method ((net cidr-net) (ip number))
    (or (gethash ip (reservations net))
	(gethash ip *dhcp-allocated-table*)
	)
    )
  )
						     
(defun dhcp-search-allocated-by-mac (mac)
  (let ((x (gethash mac *dhcp-allocated-table*)))
    (when x
      (setf (tla x) (get-universal-time))
      x)
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
      (when (dhcp-search-allocated-by-mac mac)
	(error (make-condition 'address-allocated :ip ip)))
      #+nil(unless (cidr-in? net-obj ip)
	(error (make-condition 'ip-cidr-net-incompatible
			       :ip ip
			       :cidr-addr (ipnum net-obj)
			       :cir (cidr net-obj))))
      (let ((addrObj (make-dhcp-address ip mac)))
	(setf (gethash mac (reservations net-obj)) addrObj)
	)))
  )

(defmethod subnets ((net-obj cidr-net) &key cidr)
  (declare (integer subnet-num))
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


(defgeneric dhcp-generate-ip (mac net)
  (:documentation
   "For prototyping, we allocate an IP address 1 time to a mac-address,
and it's always allocated untile the server is restarted.")
  (:method ((mac list) (net cidr-net))
    ;; TODO: Handle the case whe we run out of addresses
    (loop
      :for ip in (numex:cidr-subnets
		  (first-ip net)
		  (cidr net)
		  :n 16)
      :do
	 (incf ip 2)
	 (unless (ip-allocated? net ip)
	   
	   (let ((addrObj (make-dhcp-address ip mac)))
	     (serapeum:run-hook 'dhcp:*hook-ip-allocated*
				(ipnum addrObj)
				(mac addrObj))
	     (return-from dhcp-generate-ip addrObj)))
      )
    nil)
  (:method ((mac string) (net cidr-net))
    (dhcp-generate-ip (numex:hexstring->octets  mac) net))
  )

;; TODO: Handle the case whe we run out of addresses
(defgeneric dhcp-allocate-ip-via-mac (mac net)
  (:documentation "A lower level function that doesn't have anything
  to do with dhcp per say, so we can test schemes, unit test, and run
  simulations and the like")
  (:method ((mac list) (net cidr-net))
    (alexandria:when-let* ((value (or (dhcp-search-allocated-by-mac mac)
				      (search-cidr-net-reservations net mac)
				      )))
      (return-from dhcp-allocate-ip-via-mac value))
    (or
     (dhcp-generate-ip mac net)
     (error "Out of ip addresses")
     )
    )
  )

;;  "Search for an unallocated ip within the range defined in the cidr-net object."
(defgeneric dhcp-allocate-ip (reqmsg net)
  (:documentation "For prototyping, we allocate an IP address 1 time to a mac-address,
and it's always allocated untile the server is restarted.")
  (:method ((reqMsg dhcp) (net cidr-net))
    (dhcp-allocate-ip-via-mac (mac reqMsg) net)
    )
  )

(defun deallocate-ip (net ip)
  (let ((obj (gethash ip *dhcp-allocated-table*)))
    (remhash (mac obj) *dhcp-allocated-table*)
    (remhash (ipnum obj) *dhcp-allocated-table*)
    ;;(setf *dhcp-allocated-table* (delete ip *dhcp-allocated-table* :key #'ipnum :test #'equalp))
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
								(:dns-servers (8 8 8 8) (4 4 4 4)))
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
							       (:dns-servers (8 8 8 8) (4 4 4 4)))
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
      (:nack
       (alog "dhcp nack")
       )
      (:info
       (alog "dhcp info")
       )
      )
    )
  )

(defvar *dhcp-iface-ip-addresses* '()
  "We broadcast DHCP messages only to interfaces that have these
  IPs. These values are cidr-net objects from the numex package")

(defun update-dhcps-iface-ip-addresses! (cidr-net-list)
  "The DHCP communicates via network broadcasts, since the clients to
this service do not have IP addresses.  We only send/respond to
interfaces that have an IP address and that have been 'marked'"
  (loop :for cidr :in cidr-net-list :do
       (unless (equal (type-of cidr) 'cidr-net)
	 (error "Illegal parameter type ~a" cidr)))
  (serapeum:synchronized (*dhcp-iface-ip-addresses*)
    (setf *dhcp-iface-ip-addresses* cidr-net-list)
    (loop :for cdir :in cidr-net-list
	  :for i :from 1
	  :do
      (let ((ipnum (first-ip cdir)))
	(make-dhcp-address ipnum (list 0 0 0 0 0 i))
	#+nil(setf (gethash ipnum *dhcp-allocated-table*)
		 (make-instance 'dhcp-address
				:ipnum ipnum
				:lease-time nil))
	))
    )
  )
		   
(defun dhcp-handler (rsocket buff size client receive-port)
  "A dhcp message was received"
  (alog "dhcp-server-pdu-handler")
  (setf *last* (copy-seq buff))
  (let* ((dhcpObj (pdu-seq->udhcp buff))
	 )
    (when (null *dhcp-iface-ip-addresses*)
	(alog "dhcp-handler - no interfaces marked for dhcps"))
    (loop :for destination-nets :in *dhcp-iface-ip-addresses* :do
	 (let* (
		(m (handle-dhcpd-message destination-nets dhcpObj))
		(response-type (msg-type m))
		(buff (obj->pdu m))
		(destination-address
		 (coerce
		  (numex:num->octets (cidr-bcast (yiaddr m)
						 ;;(dhcp:cidr-subnet destination-nets)
						 (dhcp:cidr destination-nets)
						 ))
		  'vector)))
	   (alog (format nil
			 "sending pdu type:~a, to addr: ~a via ~a"
			 response-type
			 (numex:num->octets (yiaddr m))
			 destination-address))
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


(defmethod route-add-cmd ((rte router-if))
  (format nil "route add -net ~a gw ~a netmask ~a dev ~a"
			       (numex:->dotted (dest rte))
			       (numex:->dotted (gw rte))
			       (numex:->dotted (mask rte))
			       (iface rte))
  )

(defun network-watchdog ()
  (let ((channel (lparallel:make-channel)))
    ;;(submit-task channel '+ 3 4)
    (future
     (loop
	(lparallel:try-receive-result channel :timeout (* 1 600))
	)))
  )

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

