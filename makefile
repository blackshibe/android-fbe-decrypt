TARGETS := $(shell find src -iname '*.cpp') 
 
main:
	g++ $(TARGETS) -lscrypt -lcrypto -o main.o -fpermissive -Wdeprecated-declarations