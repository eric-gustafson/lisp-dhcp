(in-package :dhcp-server)


(defun encode-options (options-doc)
  ;; Based on flatten.
  ;; 2     DHCPOFFER
  ;; 3     DHCPREQUEST
  ;; 4     DHCPDECLINE
  ;; 5     DHCPACK
  ;; 6     DHCPNAK
  ;; 7     DHCPRELEASE
  ;; 8     DHCPINFORM
  (trivia:match
      options-doc
    (() '())
    ((list :subnet a b c d)     (list 1 4  a b c d))

    ((list* :routers rest)
     (apply #'append  (cons (list 3 (* 4 (length rest))) rest)))

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
    (:dhcp-discover (list 53 1 1)) ;; DHCPDISCOVER
    (:dhcp-offer (list 53 1 2))
    (:dhcp-request (list 53 1 3))
    (:dhcp-decline (list 53 1 4))
    (:dhcp-ack (list 53 1 5))
    (:dhcp-nak (list 53 1 6))
    (:dhcp-release (list 53 1 7))
    (:dhcp-inform (list 53 1 8))
    ((list :hostname name-str)
     (cons 12 (cons (length name-str) (map 'list #'char-code name-str))))
    ((trivia:guard a (atom a)) (list a))
    (otherwise
     (append (encode-options (car options-doc))
	     (encode-options (cdr options-doc))))))

(defun decode-options (seq &key debug)
  ;; maybe rename to decde?
  (trivia:match
      seq
    (() '())
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
	(decode-options (subseq rest n) :debug debug))))
    ((list* 50 4 a b c d rest)
     (let ((req-ip (vector a b c d))) 
      (when debug (format t "request ip address=~a~%" req-ip))
       (cons (list :requested-ip req-ip)
	     (decode-options rest :debug debug))))
    ((list* 53 1 1 rest) ;; dhcp discover
     (when debug (format t "dhcp-message-type discover~%"))
     (decode-options rest :debug debug)
     )
    ((list* 53 1 3 rest) ;; dhcp request
     (when debug (format t "dhcp-message-type request~%"))
     (decode-options rest :debug debug)
     )
    ((list* 54 4 a b c d rest)
     ;; This is the 'id', or the IP address of the dhcp server.
     (let ((server (vector a b c d)))
       (when debug (format t "server-identifier: ~a ~%" server))
       (cons (list :server-id server) (decode-options rest :debug debug))))
    ((list* 55 n rest) 
     (when debug (format t "dhcp parameter requests~%"))
     (let ((code-list
	    (loop :for i below n
	       :for e in rest 
	       :collect e)))
       (cons (cons :client-params-request code-list) (decode-options (subseq rest n) :debug debug)))
     )
    ((list* 57 2 l1 l2 rest) ;; max size
     (let ((num (nums-and-txt:octets->num (list l1 l2))))
       (when debug (format t "dhcp max message size:~a~%" num))
       (cons (list :max-dhcp-message-size num) (decode-options rest :debug debug))))

    ((list* 60 n rest) ;; vendor class
     (let ((payload (subseq rest 0 n)))
       (when debug (format t "vendor class identifier:~a~%" (map 'string #'code-char payload)))
       (cons (list :vendor-class payload )
	     (decode-options (subseq rest n) :debug debug))))

    ((list* 61 rest) ;; client-identifier
     (trivia:match
	 rest
       ((list* n type rest)
	(let ((client-id (subseq rest 0 (- n 1))))
	  (when debug (format t "client-identifier ~a" client-id))
	  (cons
	   (list :client-identifier client-id)
	   (decode-options (subseq rest (- n 1)) :debug debug)))))
     )

    ((list* 83 n rest)
     (when debug (format t "rfc4174 - iSNS,n=~a,len(seq)=~a" n (length rest)))
     (let ((after (subseq rest n)))
       (cons (cons :iSNS (subseq rest 0 n))
	     (decode-options after :debug debug))
       ))
    ((list* 99 n rest)
     (let ((after (subseq rest n)))
       (cons (list :GEO (subseq rest 0 n))
	     (decode-options after :debug debug))))
    ((list* 119 n rest)
     (let ((after (subseq rest n)))
       (cons (list :domain-search
		   (subseq rest 0 n))
	     (decode-options after :debug debug))))
    ((list* 112 n rest)
     (let ((after (subseq rest n)))
       (cons (list :netinfo-address
		   (subseq rest 0 n))
	     (decode-options after :debug debug))))
    (otherwise
     (error "Unable to handle request: ~a" seq))
    )
  )
     
     
