SUBPROJS=ut

LISP_FILES=$(wildcard *.lisp)

UT_LISP_FILES=$(wildcard ut/*.lisp)

dhcp: dhcp.ros ut/ut
	ros -Q build $<

ut/ut: $(UT_LISP_FILES)
	make -C ut

clean:
	- rm dhcp
	- rm ut

