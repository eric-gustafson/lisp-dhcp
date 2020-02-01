(asdf:defsystem #:dhcptest
  :description "DHCP client and server unit testing code"
  :author "gus"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (
	       #:alexandria
	       #:serapeum
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
	       #:inferior-shell
	       #:numex
	       #:lsa
	       #:cl-syslog
               #:cl-ppcre
	       #:cl-async
	       #:dhcp
	       )
  :components ((:file "dhcptest-package")
	       (:file "dhcp-ut")
	       ))

