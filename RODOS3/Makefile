all: RODOS3

RODOS3: main.o RODOS3.o hid-libusb.o usb.o
	gcc main.o RODOS3.o hid-libusb.o usb.o -o RODOS3 -lstdc++ -lusb-1.0 -lpthread

main.o: main.cpp
	gcc -c -std=c++11 -O2 main.cpp

RODOS3.o: RODOS3.cpp
	gcc -c -O2 RODOS3.cpp
	
hid-libusb.o: hid-libusb.c 
	gcc -I/usr/include/libusb-1.0 -I. -c -O2 hid-libusb.c

usb.o: usb.cpp
	gcc -c -O2 usb.cpp

clean:
	rm -f hid-libusb.o RODOS3.o main.o usb.o


