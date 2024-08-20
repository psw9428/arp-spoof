TEMPLATE = app
TARGET = arp-spoof
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	util.cpp \
	main.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	util.h \
	mac.h
