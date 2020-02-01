

(in-package #:dhcp)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ->symbol (&rest stuff)
    (alexandria:ensure-symbol
     (string-upcase (with-output-to-string (port)
		      (loop :for x :in stuff :do
			 (princ x port))))
     )
    ))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ->keyword (&rest stuff)
    (alexandria:ensure-symbol
     (string-upcase (with-output-to-string (port)
		      (loop :for x :in stuff :do
			 (princ x port))))
     :keyword
     )
    )
  )

(defun sequence-type (obj)
  (etypecase
   obj
    (list 'list)
    (string 'string)
    (vector 'vector)
    ))



(defun ensure-length (seq n &key pad-value)
  "make sure that a sequence matches a specified length"
  (let ((l (length seq)))
    (cond
      ((= l n) seq)
      ((< l n)
       (let ((seqt (sequence-type seq))
	     (x (- n l)))
	 (concatenate seqt
		      seq
		      (make-sequence seqt x :initial-element (if (null pad-value)
								 (elt (make-sequence seqt 1) 0)
								 pad-value)))))
      (t
       (serapeum:take n seq)))))

(defparameter *dhcp-magic-cookie* '(99 130 83 99))

(defmacro clos-code (name)
  ;; Use the global dhcp symbol table, and create a CLOS class
  ;; for dhcp and bootp packets
  `(defclass ,(->symbol name)
       ()
     ,(mapcar #'(lambda(row)
		  (trivia:match
		      row
		    ((list field octets description type _)
		     (list (->symbol field)
                           :documentation description
                           :accessor (->symbol field)
                           :initarg (->keyword field)
			   :initform (if (equal type "int")
					 0
					 `(make-array ,octets :element-type `(unsigned-byte 8) :initial-element 0)
					 )
			   ))))
	      *dhcp-bootp-base-fields*)
     )
  )


(defmacro gen-serialize-code (name)
  (let (code
	(clazz-name name))
    (labels ((field-serialize-fn-name  (field)
	       (intern (string-upcase (format nil "~a-~a-stream-serialize" clazz-name field))))
	     (pf (field sexp)
	       (push `(defmethod ,(field-serialize-fn-name field) ((obj ,clazz-name) (out stream))
			(declare (optimize (speed 0) (safety 3)))
			;(format t "~a~%" (quote ,field))
			,sexp)
		     code)
	       ))
      ;; Generate a serialize function for each slo
      (loop :for row :in *dhcp-bootp-base-fields* :do
	   (trivia:match 
	       row
	     ((list field octets _ da-type _)
	      (let ((type (intern (string-upcase da-type) :keyword)))
		(pf field
		    (cond
		      ((eq type :mac)
		       `(let ((value (,(->symbol field) obj)))
			  (etypecase
			      value
			    (string (write-sequence (ensure-length value ,octets :pad-value #\nul) out))
			    (t
			     (write-sequence (ensure-length value ,octets :pad-value 0)  out)))))
		      ((eq type :rest)
		       `(write-sequence (,(->symbol field) obj) out))
		      ((eq type :string)
		       `(write-sequence (,(->symbol field) obj) out))
		      ((eq type :int)
		       ;; support a number, or a list/vector octet in the field of the
		       ;; object
		       `(let ((value (,(->symbol field) obj)))
			  (etypecase
			      value
			    (integer
			     (write-sequence (numex:num->octets value :length ,octets :endian :big) out))
			    (sequence
			     (unless (eq (length value) ,octets)
			       (error "~a: integer sequence size mismatch" ,field))
			     (write-sequence value out)))
			  )
		       )
		      (t
		       (error "Unexpected type ~a" row))
		      ))))))
      `(progn
	 ,@code	 
	 (defmethod stream-serialize ((obj ,name)  (out stream))
	   ,@(mapcar #'(lambda(row)
			 `(,(field-serialize-fn-name (car row)) obj out))
		     *dhcp-bootp-base-fields*)
	   )
	 )
      )
    )
  )

(defmacro gen-deserialize-code (name )
  ;; generate a dehydrate command given the symbol table
  (labels ((dehydrate-operation (st-row)
	     (trivia:match 
		st-row
	       ((list field octets descr da-type notes)
		(let ((type (intern (string-upcase da-type) :keyword)))
		  (cond
		    ((eq type :mac) ;; 
		     `(setf (,(->symbol field) obj)
			    (loop :for i :below ,octets :collect (read-byte input-stream))))
		    ((eq type :rest)
		     `(setf (,(->symbol field) obj) (loop
						       :for x = (read-byte  input-stream nil nil)
						       :while x :collect x
						       )))
		    ;; Strings have a fixed length
		    ;; Maybe we should handle fixed-length, pascal, and c with different
		    ;; keywords?
		    ((eq type :string)
		     `(setf (,(->symbol field) obj)
			    (loop :for i :below ,octets :collect (read-byte input-stream))))
		    ((eq type :int)
		     `(setf (,(->symbol field) obj) (numex:octets->num (numex:read-octets ,octets input-stream) :endian :big)))
		    (t
		     (error "Unexpected type ~a" st-row))
		    ))))))
     `(progn
        (defmethod stream-deserialize ((obj ,(->symbol name)) (input-stream  stream))
          ,@(mapcar #'dehydrate-operation  *dhcp-bootp-base-fields*))
	)
        )
  )

(clos-code dhcp)

(gen-serialize-code dhcp)

(gen-deserialize-code dhcp)

(defmethod deserialize-into-dhcp-from-buff! ((dhcpObj dhcp) (buff sequence))
  (flexi-streams:with-input-from-sequence (inport buff)
    (stream-deserialize dhcpObj inport))
  dhcpObj)

(defmethod mac ((dhcpObj dhcp))
  (let ((len (hlen dhcpObj)))
    (subseq (chaddr dhcpObj) 0 len)))



(defmethod obj->pdu ((dhcp-obj dhcp))
  (flexi-streams:with-output-to-sequence (opp :element-type '(unsigned-byte 8))
    (let ((options-obj (options dhcp-obj)))
      (cond
	((typep options-obj 'dhcp-options)
	 (unwind-protect
	      (progn
		(setf (options dhcp-obj) (encode-dhcp-options options-obj))
		(stream-serialize dhcp-obj opp))
	   ;; Back the way we found it
	   (setf (options dhcp-obj) options-obj)))
	(t
	 (stream-serialize dhcp-obj opp)))
      )
    )
  )
