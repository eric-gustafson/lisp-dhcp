(in-package :dhcp-server)

(defun parse-options (seq &key debug)
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
    ((list* 53 1 3 rest) ;; dhcp discover
     (when debug (format t "dhcp-message-type discover~%"))
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
    ((list* 83 n rest)
     (when debug (format t "rfc4174 - iSNS,n=~a,len(seq)=~a" n (length rest)))
     (let ((after (subseq rest n)))
       (parse-options after :debug debug))
     )
    (otherwise
     (error "Unable to handle request: ~a" seq))
    )
  )
     
     
