

(in-package #:dhcp)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ->symbol (&rest stuff)
    (alexandria:ensure-symbol
     (string-upcase (with-output-to-string (port)
		      (loop :for x :in stuff :do
			 (princ x port))))
     )
    ))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ->keyword (&rest stuff)
    (alexandria:ensure-symbol
     (string-upcase (with-output-to-string (port)
		      (loop :for x :in stuff :do
			 (princ x port))))
     :keyword
     )
    )
  )

(defun sequence-type (obj)
  (etypecase
   obj
    (list 'list)
    (string 'string)
    (vector 'vector)
    ))

(defun load-packet-from-file (path)
  "Returns a pdu in a vector from a file"
  (let* ((rpath (probe-file path)))
    (with-open-file (bin-port rpath :element-type '(unsigned-byte 8))
      (let ((obj (make-instance 'dhcp)))
	(stream-deserialize obj bin-port)	
	obj
	)))
  )

(defun ensure-length (seq n &key pad-value)
  "make sure that a sequence matches a specified length"
  (let ((l (length seq)))
    (cond
      ((= l n) seq)
      ((< l n)
       (let ((seqt (sequence-type seq))
	     (x (- n l)))
	 (concatenate seqt
		      seq
		      (make-sequence seqt x :initial-element (if (null pad-value)
								 (elt (make-sequence seqt 1) 0)
								 pad-value)))))
      (t
       (serapeum:take n seq)))))

(defparameter *dhcp-magic-cookie* '(99 130 83 99))

(defmacro clos-code (name)
  ;; Use the global dhcp symbol table, and create a CLOS class
  ;; for dhcp and bootp packets
  `(defclass ,(->symbol name)
       ()
     ,(mapcar #'(lambda(row)
		  (trivia:match
		      row
		    ((list field octets description type _)
		     (list (->symbol field)
                           :documentation description
                           :accessor (->symbol field)
                           :initarg (->keyword field)
			   :initform (if (equal type "int")
					 0
					 `(make-array ,octets :element-type `(unsigned-byte 8) :initial-element 0)
					 )
			   ))))
	      *dhcp-bootp-base-fields*)
     )
  )


(defmacro gen-serialize-code (name)
  (let (code
	(clazz-name name))
    (labels ((field-serialize-fn-name  (field)
	       (intern (string-upcase (format nil "~a-~a-stream-serialize" clazz-name field))))
	     (pf (field sexp)
	       (push `(defmethod ,(field-serialize-fn-name field) ((obj ,clazz-name) (out stream))
			(declare (optimize (speed 0) (safety 3)))
			;(format t "~a~%" (quote ,field))
			,sexp)
		     code)
	       ))
      ;; Generate a serialize function for each slo
      (loop :for row :in *dhcp-bootp-base-fields* :do
	   (trivia:match 
	       row
	     ((list field octets _ da-type _)
	      (let ((type (intern (string-upcase da-type) :keyword)))
		(pf field
		    (cond
		      ((eq type :mac)
		       `(let ((value (,(->symbol field) obj)))
			  (etypecase
			      value
			    (string (write-sequence (ensure-length value ,octets :pad-value #\nul) out))
			    (t
			     (write-sequence (ensure-length value ,octets :pad-value 0)  out)))))
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
			       (error "~a: integer sequence size mismatch" ,field))
			     (write-sequence value out)))
			  )
		       )
		      (t
		       (error "Unexpected type ~a" row))
		      ))))))
      `(progn
	 ,@code	 
	 (defmethod stream-serialize ((obj ,name)  (out stream))
	   ,@(mapcar #'(lambda(row)
			 `(,(field-serialize-fn-name (car row)) obj out))
		     *dhcp-bootp-base-fields*)
	   )
	 )
      )
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

(clos-code dhcp)

(gen-serialize-code dhcp)

(gen-deserialize-code dhcp)

(defclass udhcp (dhcp)
  (
   (options-obj
    :accessor options-obj
    :initarg :options-obj
    :initform nil
    :documentation "An object that maps to the dhcp.options octets")
   )
  )

(defmethod deserialize-into-dhcp-from-buff! ((dhcpObj dhcp) (buff sequence))
  (flexi-streams:with-input-from-sequence (inport buff)
    (stream-deserialize dhcpObj inport))
  dhcpObj)

(defmethod pdu-seq->udhcp ((buff sequence))
  (let ((obj (make-instance 'udhcp)))
    (flexi-streams:with-input-from-sequence (inport buff)
      (stream-deserialize obj inport)
      (setf (options-obj obj) (decode-dhcp-options (options obj)))
      obj
      )
    )
  )

(defmethod mac ((dhcpObj dhcp))
  (let ((len (hlen dhcpObj)))
    (subseq (chaddr dhcpObj) 0 len)))

(defmethod obj->pdu ((dhcp-obj udhcp))
  (flexi-streams:with-output-to-sequence (opp :element-type '(unsigned-byte 8))
    (let ((oobj (options-obj dhcp-obj)))
      (setf (options dhcp-obj) (encode-dhcp-options oobj))
      (stream-serialize dhcp-obj opp)
      )
    )
  )

(defmethod dhcp-msg-sig ((obj udhcp))
  "Reurns a list which the key parts needed to determine what kind of message the pdu is."
  (list (op obj)
	(mtype (options-obj obj)))
  )

;; 
(defmethod msg-type ((dhcp-msg-obj udhcp))
  ;"returns a symbol [:release :ack :request :offer  :discover] designating what kind of dhcp pdu"
  (let ((sig (dhcp-msg-sig dhcp-msg-obj)))
    (cond
      ((equalp sig (list +MSG-TYPE-DHCPDISCOVER+  +MSG-TYPE-DHCPDISCOVER+)) :discover) ;; 1 1
      ((equalp sig (list +MSG-TYPE-DHCPOFFER+  +MSG-TYPE-DHCPOFFER+)) :offer)
      ((equalp sig (list +MSG-TYPE-DHCPDISCOVER+  +MSG-TYPE-DHCPREQUEST+)) :request)
      ((equalp sig (list +MSG-TYPE-DHCPOFFER+   +MSG-TYPE-DHCPACK+)) :ack)
      )
    )
  )

(defmethod msg-type! ((dhcp-msg-obj udhcp) stype)
  (let ((options (options-obj dhcp-msg-obj)))
    (ecase
	stype
      (:discover
       (setf (op dhcp-msg-obj) +MSG-TYPE-DHCPDISCOVER+  (mtype options)  +MSG-TYPE-DHCPDISCOVER+))
      (:offer
       (setf (op dhcp-msg-obj) +MSG-TYPE-DHCPOFFER+ (mtype options)  +MSG-TYPE-DHCPOFFER+))
      (:request
       (setf (op dhcp-msg-obj) +MSG-TYPE-DHCPDISCOVER+ (mtype options)  +MSG-TYPE-DHCPREQUEST+))
      (:ack
       (setf (op dhcp-msg-obj) +MSG-TYPE-DHCPOFFER+ (mtype options)  +MSG-TYPE-DHCPACK+))
      )
    )
  )

(defmacro as-wait-for-dhcp (type (rsocket recv-obj-var-name) &body body)
  (let ((async-obj (gensym))
	(pdu-var-name (gensym))
	(msg-type-var (gensym)))
    `(let ((,async-obj
	    (cl-async:poll
	     (sb-bsd-sockets:socket-file-descriptor (usocket:socket ,rsocket))
	     #'(lambda(event-named)
		 (declare (ignore event-named))
		 (let ((gbuff (make-array 2048 :element-type '(unsigned-byte 8) ))
		       )
		   (multiple-value-bind (buff n)
		       (usocket:socket-receive ,rsocket gbuff (array-total-size gbuff))
		     (let* ((,pdu-var-name (subseq  buff 0 n))
			    (,recv-obj-var-name 
			     (pdu-seq->udhcp ,pdu-var-name))
			    )
		       (let ((,msg-type-var (msg-type ,recv-obj-var-name)))
			 (unless (eq  ,msg-type-var type)
			   (error "as-wait-for-dhcp -- unexpected dhcp message type ~a" ,msg-type-var))
			 ,@body
			 )
		       )
		     )
		   )
		 )
	     :poll-for '(:readable)
	     :socket t		
	     )
	     ))
       ,async-obj))
  )
