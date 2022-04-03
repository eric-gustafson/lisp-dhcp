LISP_FILES=$(wildcard *.lisp)

UT_LISP_FILES=$(wildcard ut/*.lisp)

dhcp: dhcp.ros
	ros -Q build $<

clean:
	- rm dhcp

