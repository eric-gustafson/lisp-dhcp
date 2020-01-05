

ldhcpd: lisp-dhcpd.ros
	ros -Q build $^

clean:
	- rm lisp-dhcpd


deploy:
	cd .. && rsync -av lisp-dhcp/ $(TARGET):~/secapp/lisp-dhcp/
