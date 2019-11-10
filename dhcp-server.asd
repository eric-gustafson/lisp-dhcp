;;;; dhcp-server.asd

(asdf:defsystem #:dhcp-server
  :description "Describe dhcp-server here"
  :author "Your Name <your.name@example.com>"
  :license  "Specify license here"
  :version "0.0.1"
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
	       #:hunchentoot
	       #:parenscript
	       #:postmodern
               #:cl-ppcre
               #:cl-who
	       #:snot
	       )
  :components ((:file "package")
	       (:file "dhcp-bootp-fields")
	       (:file "dhcp-options-table")
               (:file "dhcp-server")
	       (:file "parse-dhcp-options")
	       ))
