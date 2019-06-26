
test_files=$(wildcard *.ros)
results=$(test_files:.ros=.results)

%.results:%.ros
	ros $^ | tee $@

all: $(results)
	echo "done;"

debug: $(test_files)
	echo $^

clean:
	rm *results
