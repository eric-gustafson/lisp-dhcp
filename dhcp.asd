;;;; dhcp.asd

(asdf:defsystem #:dhcp
  :description "DHCP client and server code"
  :author "gus"
  :license  "Specify license here"
  :version "0.0.2"
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
	       ;;#:trivial-ssh
	       #:cl-syslog
               #:cl-ppcre
	       #:cl-async
	       )
  :components ((:file "dhcp-package")
	       (:file "parse-dhcp-options")
	       (:file "dhcp-bootp-fields")
	       (:file "dhcp-options-table")
	       (:file "dhcp-common")
	       (:file "dhcp-client")
               (:file "dhcp-server")
	       ))
