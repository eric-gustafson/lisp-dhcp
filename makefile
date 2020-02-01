
LISP_FILES=$(wildcard *.lisp)

ut: ut.ros $(LISP_FILES)
	ros -Q build $<

dhcp: dhcp.ros
	ros -Q build $^

clean:
	- rm dhcp
	- rm ut

