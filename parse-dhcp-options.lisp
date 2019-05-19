(in-package :dhcp-server)

(defvar *dhcp-options-key-map*
  (dict :hostname 12)
  )


(defun encode-option (options-doc)
  ;; Based on flatten.
  ;; 53 - message type
  ;; 1     DHCPDISCOVER
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
    (:dhcp-discover (list 53 1 1))
    (:dhcp-offer (list 53 1 2))
    (:dhcp-request (list 53 1 3))
    (:dhcp-decline (list 53 1 4))
    (:dhcp-ack (list 53 1 5))
    (:dhcp-nak (list 53 1 6))
    (:dhcp-release (list 53 1 7))
    (:dhcp-inform (list 53 1 8))
    ((list :lease-time secs)
     (cons 51 (cons 4 (coerce (nums-and-txt:num->octets secs :length 4) 'list))))
    ((list :requested-ip-address (list a b c d))
     (list 50 4 a b c d))
    ((trivia:guard str (stringp str)) (cons (length str) (map 'list #'char-code str)))
    (:hostname (list 12))
    ((trivia:guard a (atom a)) (list a))
    (otherwise
     (append (encode-option (car options-doc))
	     (encode-option (cdr options-doc))))))

(defun parse-options (seq &key debug)
  ;; maybe rename to decde?
  (trivia:match
      seq
    (() '())
    ((list* 0 rest)
     ;; This is the Pad option
     (parse-options rest))
    ((list* 255 _)
     '())
    ((list* 12 n rest) ;; hostname option
     (let ((hn (map 'string #'code-char (subseq rest 0 n))))
       (when debug (format t "hostname=~a~%" hn))
       (parse-options (subseq rest n) :debug debug)))
    ((list* 50 4 a b c d rest)
     (let ((req-ip (vector a b c d)))
       (when debug (format t "request ip address=~a~%" req-ip))
       (parse-options rest :debug debug)))
    ((list* 53 1 1 rest) ;; dhcp discover
     (when debug (format t "dhcp-message-type discover~%"))
     (parse-options rest :debug debug)
     )
    ((list* 53 1 3 rest) ;; dhcp request
     (when debug (format t "dhcp-message-type request~%"))
     (parse-options rest :debug debug)
     )
    ((list* 54 4 a b c d rest)
     (let ((server (vector a b c d)))
       (when debug (format t "server-identifier: ~a ~%" server))
       (parse-options rest :debug debug)))
    ((list* 55 n rest) ;; dhcp discover
     (when debug (format t "dhcp discover requests~%"))
     (loop
	:for i below n
	:for (a b) on rest by #'cddr
	:collect (nums-and-txt:octets->num (vector a b)))
     (parse-options (subseq rest (* 2 n)) :debug debug)
     )
    ((list* 57 2 l1 l2 rest)
     (let ((num (nums-and-txt:octets->num (list l1 l2))))
       (when debug (format t "dhcp max message size:~a~%" num))
       (parse-options rest :debug debug)))
    ((list* 60 n rest) ;; vendor class
     (let ((payload (subseq rest 0 n)))
       (when debug (format t "vendor class identifier:~a~%" (map 'string #'code-char payload))))
     (parse-options (subseq rest n) :debug debug))

    ((list* 61 n rest) ;; client-identifier
     (let ((payload (subseq rest 0 n)))
       (trivia:match
	   payload
	 ((list* type clazz-info)
	  (when debug (format t "client identifier type=~a,~a~%" type clazz-info)))
	 (otherwise
	  (when debug (format t "error parsing client-identifier payload ~a" payload))))
       (parse-options (subseq rest n) :debug debug))
     )
     
    ((list* 83 n rest)
     (when debug (format t "rfc4174 - iSNS,n=~a,len(seq)=~a" n (length rest)))
     (let ((after (subseq rest n)))
       (parse-options after :debug debug))
     )
    (otherwise
     (error "Unable to handle request: ~a" seq))
    )
  )
     
     
