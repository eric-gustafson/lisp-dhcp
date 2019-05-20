;;;; dhcp-server.asd

(asdf:defsystem #:dhcp-server
  :description "Describe dhcp-server here"
  :author "Your Name <your.name@example.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (
	       #:flexi-streams
	       #:usocket
	       #:swank
	       #:alexandria
	       #:trivia
	       #:serapeum
	       #:nums-and-txt
	       )
  :components ((:file "package")
	       (:file "dhcp-clos")
	       (:file "dhcp-hydrate")
	       (:file "dhcp-dehydrate")
               (:file "dhcp-server")
	       (:file "parse-dhcp-options")
	       ))