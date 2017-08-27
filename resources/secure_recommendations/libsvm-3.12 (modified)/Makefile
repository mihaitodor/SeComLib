CXX ?= g++
CFLAGS = -Wall -Wconversion -O3 -fPIC
SHVER = 2
OS = $(shell uname)

all: svm-train svm-predict svm-scale

#+Michael
lib_static: svm.o
	ar rcs libsvm.a svm.o
#/+Michael

lib: svm.o
	if [ "$(OS)" = "Darwin" ]; then \
		SHARED_LIB_FLAG="-dynamiclib -W1,-install_name,libsvm.so.$(SHVER)"; \
	else \
		SHARED_LIB_FLAG="-shared -W1,-soname,libsvm.so.$(SHVER)"; \
	fi; \
	$(CXX) $${SHARED_LIB_FLAG} svm.o -o libsvm.so.$(SHVER)

#-Michael
#svm-predict: svm-predict.c svm.o
#	$(CXX) $(CFLAGS) svm-predict.c svm.o -o svm-predict -lm
#svm-train: svm-train.c svm.o
#	$(CXX) $(CFLAGS) svm-train.c svm.o -o svm-train -lm
#/-Michael
#+Michael: added eval.o
svm-predict: svm-predict.c svm.o eval.o
	$(CXX) $(CFLAGS) svm-predict.c svm.o eval.o -o svm-predict -lm
svm-train: svm-train.c svm.o eval.o
	$(CXX) $(CFLAGS) svm-train.c svm.o eval.o -o svm-train -lm
#/+Michael
svm-scale: svm-scale.c
	$(CXX) $(CFLAGS) svm-scale.c -o svm-scale
svm.o: svm.cpp svm.h
	$(CXX) $(CFLAGS) -c svm.cpp
	
#+Michael
eval.o: eval.cpp eval.h svm.h
	$(CXX) $(CFLAGS) -c eval.cpp -o eval.o
#/+Michael

#-Michael: added eval.o
#clean:
#	rm -f *~ svm.o svm-train svm-predict svm-scale libsvm.so.$(SHVER)
#/-Michael
#+Michael
clean:
	rm -f *~ svm.o eval.o svm-train svm-predict svm-scale libsvm.so.$(SHVER)
#/+Michael
