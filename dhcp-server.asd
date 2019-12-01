;;;; dhcp-server.asd

(asdf:defsystem #:dhcp-server
  :description "DHCP client and server code"
  :author "gus"
  :license  "Specify license here"
  :version "0.0.2"
  :serial t
  :depends-on (
	       #:alexandria	       
	       #:flexi-streams
	       #:usocket
	       #:swank
	       #:closer-mop	       
	       #:uiop
	       #:lparallel   
	       #:cl-ppcre
	       #:trivia
	       #:trivia.ppcre
	       #:cl-interpol
	       #:daemon	       	       
	       #:serapeum
	       #:inferior-shell
	       #:numex
	       #:lsa
	       #:trivial-ssh
	       #:cl-syslog
               #:cl-ppcre
	       )
  :components ((:file "package")
	       (:file "dhcp-bootp-fields")
	       (:file "dhcp-options-table")
               (:file "dhcp-server")
	       (:file "parse-dhcp-options")
	       ))
