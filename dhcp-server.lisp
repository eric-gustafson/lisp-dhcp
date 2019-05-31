;;;; dhcp-server.lisp

(in-package #:dhcp-server)


(defvar *dhcp-dest-port* 67)
(defvar *dhcp-client-port* 68)

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
		     `(setf (,(->symbol field) obj) (nums-and-txt:octets->num (nums-and-txt:read-octets ,octets input-stream) :endian :big)))
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
			   `(write-sequence (nums-and-txt:num->octets (,(->symbol field) obj) :length ,octets :endian :big) out))
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

(defmethod decode-network-dhcp-packet! ((dhcpObj dhcp) (buff sequence))
  (flexi-streams:with-input-from-sequence (inport buff)
    (stream-deserialize dhcpObj inport))
  dhcpObj)

;;                              code generation                               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defun serve ()
  (cond
    ((numberp *ns*)
     (cond
       ((> *ns* 0)
	(decf *ns*)
	t)
       (t nil)))
    (t
     t)))

(defvar *last* nil)

(defun save-binary-packet-to-file (path buff)
  (with-open-file (bout path :direction :output :element-type '(unsigned-byte 8)  :if-exists :overwrite :if-does-not-exist :create)
    (write-sequence buff bout))
  )

(defun this-ip ()
  (list 192 168 1 1)
  )

(defmethod get-address ((reqMsg dhcp))
  "return an dhcp packet to be broadcast that provides an IP address"
  (let ((replyMsg (make-instance 'dhcp
				 :op 2
				 :htype (htype reqMsg)				    
				 :hlen (hlen reqMsg)
				 :hops (hops reqMsg)
				 :xid (xid reqMsg)
				 :secs (secs reqMsg)
				 :flags (flags reqMsg)
				 :yiaddr (this-ip)
				 :siaddr (this-ip)
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
    (otherwise
     (error "handle-network-message - Unimplemented functionality ~a" sig))
    )
  )
  )
  
(defun create-dhcpd-handler ()
  (labels ((run ()
	     (let* ((dhcpObj (make-instance 'dhcp))
		    (buff (make-array 1024 :element-type '(unsigned-byte 8)))
		    (socket (usocket:socket-connect nil
						    nil
						    :protocol :datagram
						    :element-type 'char
						    :local-port *dhcp-dest-port*)))
	       (unwind-protect
		    (loop while (serve) do
			 (multiple-value-bind (buff size client receive-port)
			     (usocket:socket-receive socket buff 1024)
			   (flexi-streams:with-input-from-sequence (bin buff)
			     (decode-network-dhcp-packet! dhcpObj bin))
			   (let* ((m (handle-dhcp-message dhcpObj))
				  (buff (flexi-streams:with-output-to-sequence (opp)
					  (stream-serialize m opp))))
			     (usocket:socket-send socket buff (length buff)
						  :port *dhcp-client-port*
						  :host  #(255 255 255 0))
			     )
			   )
			 (setf *last* (copy-seq buff))
			 )
		 (usocket:socket-close socket)))))
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
  (eq (mcookie *a*) (nums-and-txt:octets->num *dhcp-magic-cookie*))
  )

