;;;; dhcp-server.lisp

(in-package #:dhcp-server)


(defvar *dhcp-dest-port* 67)

(defparameter *ns* 0)
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

(defmacro dhcp-bootp-base-fields-code-gen ()
  ;; todo: make this work
  ;; todo: add one that creaes from sequence
  (let* ((name 'dhcp)
	 (fname (intern (string-upcase (format nil  "make-~a-from-stream" name)))))
    (labels ((st-row->instantiate-from-stream (st-row)
	       (trivia:match 
		   st-row
		 ((list field octets _ da-type _)
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
		       (error "Unexpected type ~a" row))
		      )))
		 )))
      `(progn
	 (defmethod ,fname ((obj ,name) input-stream)
	   ,@(mapcar #'st-row->instantiate-from-stream	 *dhcp-bootp-base-fields*))
	 )
      )
    )
  )

;;;;;;;;;;;;;;;;;;;;  dehydrate  ;;;;;;;;;;;;;;;;;;;;

(defmacro dehydrate-code (name )
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
        (defmethod ,(intern (string-upcase (format nil "read-~a-from-stream" name))) ((obj ,(->symbol name)) input-stream)
          ,@(mapcar #'dehydrate-operation  *dhcp-bootp-base-fields*))
	)
        )
  )



(defmacro hydrate-code (name)
  `(defmethod ,(intern (string-upcase (format nil "~a-packet" name))) ((obj ,name))
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
			   `(write-sequence (number->octets (,(->symbol field) obj) :n ,octets :endian :big) out))
			  (t
			   (error "Unexpected type ~a" row))
			  )))))
	       *dhcp-bootp-base-fields*
	       )
     ))


(clos-code dhcp)
(dhcp-bootp-base-fields-code-gen)
(dehydrate-code dhcp)
(hydrate-code dhcp)

;;                              code generation                               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defun serve ()
  (if (> *ns* 0)
      nil
      (progn (incf *ns*)
	     t)))

(defvar *last* nil)

(defun save-binary-packet-to-file (path buff)
  (with-open-file (bout path :direction :output :element-type '(unsigned-byte 8)  :if-exists :overwrite :if-does-not-exist :create)
    (write-sequence buff bout))
  )


(defun create-dhcpd-handler ()
  (labels ((run ()
	     (let* ((buff (make-array 1024 :element-type '(unsigned-byte 8)))
		    (socket (usocket:socket-connect nil
						    nil
						    :protocol :datagram
						    :element-type 'char
						    :local-port *dhcp-dest-port*)))
	       (unwind-protect
		    (loop while (serve) do
			 (multiple-value-bind (buff size client receive-port)
			     (usocket:socket-receive socket buff 1024)
			   (format t "Got one~%")
			   (setf *last* (copy-seq buff))
			   
			   ))
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

