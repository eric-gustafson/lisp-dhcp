(in-package :dhcp-server)

(defclass dhcp-options ()
  (
   (mtype :documentation "Type type of dhcp/bootp message"
	  :accessor mtype
	  :initarg :mtype)
   (restof :documentation "Everything else"
	   :initarg :restof
	   :accessor restof)
   )
  )

;; mtype print should show symbol too
;; 1 - discover
;; 2 - offer
;; 3 - request
;; 4 - decline
;; 5 - ack
;; 6 - nak
;; 7 - release
;; 8 - inform
(defmethod print-object ((obj dhcp-options) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots (mtype restof)
	obj
      (format stream "mtype=~a,restof=~X" mtype restof))
    )
  )

(EVAL-WHEN (:COMPILE-TOPLEVEL :LOAD-TOPLEVEL :EXECUTE)
    
  (defclass meta-dhcp-option ()
    (
     (match-code :documentation "The pattern match code to parse the thing"
		 :accessor match-code
		 :initarg :match-code)
     (binary-extract-code :documentation "read octets and create a document/object"
			  :accessor binary-extract-code
			  :initarg :binary-extract-code)
     (name :accessor name :initarg :name)
     (id :accessor id :initarg :id)
     (symb :accessor symb :initarg :symb)
     )
    )
  )

(eval-when (:COMPILE-TOPLEVEL :LOAD-TOPLEVEL :EXECUTE)
  (defun ip-match (clause-name num)
    `((or (list ,clause-name a b c d)
	  (list ,clause-name (list a b c d))
	  (list ,clause-name (vector a b c d)))
      (list ,num 4 a b c d)
      )
    )
  (defparameter *dhcp-options-objs*
    (list
     (make-instance 'meta-dhcp-option
		    :name "subnet"
		    :id 1
		    :symb :subnet
		    :match-code (ip-match :subnet 1)
		    :binary-extract-code '((list* 1 4 a b c d rest)
					   (cons (list :subnet a b c d)
					    (decode-options rest)))
		    )
     (make-instance 'meta-dhcp-option
		    :name "routers"
		    :id 3
		    :symb :routers
		    :match-code `((list* :routers rest)
				  (apply #'append  (cons (list 3 (* 4 (length rest))) rest)))
		    :binary-extract-code `((list* 3 len rest)
					   (cons (list :routers (subseq rest 0 len))
						 (decode-options (subseq rest len))))
		    )
     )
    )
  )

(defmacro m-encode-options ()
  ;; generates the function to encode dhcp options into
  ;; a sequence
  `(defmethod  encode-dhcp-options ((obj dhcp-options))
     (labels ((_encode-options (options-doc)
		(trivia:match
		    options-doc
		  (() '())
		  ,@(mapcar #'match-code *dhcp-options-objs*)
		  ((list* :domain-server rest)
		   ;; n must be a multiple of 4
		   ;; rest is n number of addesses
		   (apply #'append  (cons (list 6 (* 4 (length rest))) rest)))    

		  ((list :client-hostname str)
		   (list* 12 (length str)  (map 'list #'char-code str)))
    
		  ((list :broadcast octets)
		   (append (list 28 4) octets))    
    
		  ((list :lease-time secs)
		   (cons 51 (cons 4 (coerce (nums-and-txt:num->octets secs :length 4) 'list))))

		  ((list :server-id a b c d)
		   (list 54 4 a b c d))
    
		  ((list :requested-ip-address (list a b c d))
		   (list 50 4 a b c d))
		  ((trivia:guard str (stringp str)) (cons (length str) (map 'list #'char-code str)))
		  ((list :hostname name-str)
		   (cons 12 (cons (length name-str) (map 'list #'char-code name-str))))
		  ((trivia:guard a (atom a)) (list a))
		  (otherwise
		   (append (_encode-options (car options-doc))
			   (_encode-options (cdr options-doc)))))))
       (append
	(list 53 1 (mtype obj))
	(_encode-options (restof obj)))
       )
     ))


(defmacro m-decode-dhcp-options ()
  `(defun decode-dhcp-options (pseq &key debug accum)
     "returns a dhcp-options object"
     (let ((dhcp-options-obj (make-instance 'dhcp-options)))
       (labels ((decode-options (seq)
		  (trivia:match
		      seq
		    (() '())
		    ,@(mapcar #'binary-extract-code *dhcp-options-objs*)
		    ((list* 0 rest)
		     ;; This is the Pad option
		     (decode-options rest))
		    ((list* 255 _)
		     '())
		    ((list* 12 n rest) ;; hostname option
		     (let ((hn (map 'string #'code-char (subseq rest 0 n))))
		       (when debug (format t "hostname=~a~%" hn))
		       (cons
			(list :client-hostname hn)
			(decode-options (subseq rest n) ))))
		    ((list* 50 4 a b c d rest)
		     (let ((req-ip (vector a b c d))) 
		       (when debug (format t "request ip address=~a~%" req-ip))
		       (cons (list :requested-ip req-ip)
			     (decode-options rest ))))
		    ((list* 53 1 type rest) ;; dhcp discover
		     (when debug (format t "dhcp-message-type discover~%"))
		     (setf (mtype dhcp-options-obj) type)
		     (decode-options rest)
		     )
		    ((list* 54 4 a b c d rest)
		     ;; This is the 'id', or the IP address of the dhcp server.
		     (let ((server (vector a b c d)))
		       (when debug (format t "server-identifier: ~a ~%" server))
		       (cons (list :server-id server) (decode-options rest))))
		    ((list* 55 n rest) 
		     (when debug (format t "dhcp parameter requests~%"))
		     (let ((code-list
			    (loop :for i below n
			       :for e in rest 
			       :collect e)))
		       (cons (cons :client-params-request code-list) (decode-options (subseq rest n))))
		     )
		    ((list* 57 2 l1 l2 rest) ;; max size
		     (let ((num (nums-and-txt:octets->num (list l1 l2))))
		       (when debug (format t "dhcp max message size:~a~%" num))
		       (cons (list :max-dhcp-message-size num) (decode-options rest))))

		    ((list* 60 n rest) ;; vendor class
		     (let ((payload (subseq rest 0 n)))
		       (when debug (format t "vendor class identifier:~a~%" (map 'string #'code-char payload)))
		       (cons (list :vendor-class payload )
			     (decode-options (subseq rest n)))))

		    ((list* 61 rest) ;; client-identifier
		     (trivia:match
			 rest
		       ((list* n type rest)
			(let ((client-id (subseq rest 0 (- n 1))))
			  (when debug (format t "client-identifier ~a" client-id))
			  (cons
			   (list :client-identifier client-id)
			   (decode-options (subseq rest (- n 1)))))))
		     )

		    ((list* 83 n rest)
		     (when debug (format t "rfc4174 - iSNS,n=~a,len(seq)=~a" n (length rest)))
		     (let ((after (subseq rest n)))
		       (cons (cons :iSNS (subseq rest 0 n))
			     (decode-options after))
		       ))
		    ((list* 99 n rest)
		     (let ((after (subseq rest n)))
		       (cons (list :GEO (subseq rest 0 n))
			     (decode-options after))))
		    ((list* 119 n rest)
		     (let ((after (subseq rest n)))
		       (cons (list :domain-search
				   (subseq rest 0 n))
			     (decode-options after))))
		    ((list* 112 n rest)
		     (let ((after (subseq rest n)))
		       (cons (list :netinfo-address
				   (subseq rest 0 n))
			     (decode-options after))))
		    (otherwise
		     (error "Could not decode dhcp option: ~a" seq))
		    )
		  ))
	 (setf (restof dhcp-options-obj) (decode-options pseq))
	 dhcp-options-obj
	 )
       )
     )
  )

(m-encode-options)
(m-decode-dhcp-options)
