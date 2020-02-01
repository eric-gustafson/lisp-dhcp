

(in-package #:dhcptest)

(fiasco:deftest server-socket-test ()
    (fiasco:is
     (eq (server-socket :port 1025)
	 (server-socket :port 1025))
     ))
