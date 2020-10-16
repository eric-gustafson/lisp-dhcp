;; FILE: cnets.lisp
;;
;; Allocate IP addresses for a mesh network

(in-package #:dhcp)

(defvar *max-children-per-node*
  "The number of possible child nodes a mesh-AP mote may have.  This
  is the most we can divide the network addresses into"
  )

(defvar *cnet-node-table* (serapeum:vect))

(defclass cnet-node ()
  (
   (parent :accessor parent :initarg :parent :initform 0)
   (hops :accessor hops :initarg :hops :initform 0 :documentation "The
   number of hops away from the coordinator.  This is also used to
   calculate the cnet-netmask offset.")
   (addr :accessor addr :initarg :addr :initform nil)
   )
  )


(defun make-net-tree ()
  (let ((obj (make-instance 'cnet-node :addr #(10 0 0 0))))
    (vector-push-extend obj *cnet-node-table*)
    )
  )



