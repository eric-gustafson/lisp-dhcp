;;;; dhcp-server.lisp

(in-package #:dhcp-server)


(defvar *dhcp-dest-port* 67)

(defparameter *ns* 0)

(defun serve ()
  (if (> *ns* 0)
      nil
      t))

(defvar *last* nil)

(defun save-binary-packet-to-file (path buff)
  (with-open-file (bout path :direction :output :element-type '(unsigned-byte 8)  :if-exists :overwrite :if-does-not-exist :create)
    (write-sequence buff bout))
  )

(defun create-dhcpd-handler ()
  (labels ((run ()
	     (let* ((buff (make-array 1024 :element-type '(unsigned-byte 8)))
		    (socket (usocket:socket-connect nil
						    nil
						    :protocol :datagram
						    :element-type 'char
						    :local-port *dhcp-dest-port*)))
	       (unwind-protect
		    (loop while (serve) do
			 (multiple-value-bind (buff size client receive-port)
			     (usocket:socket-receive socket buff 1024)
			   (format t "Got one~%")
			   (setf *last* (copy-seq buff))
			   ))
		 (usocket:socket-close socket)))))
    (run)))

