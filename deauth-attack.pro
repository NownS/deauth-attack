TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -lnet -lpthread
SOURCES += \
    mac.cpp \
    main.cpp

HEADERS += \
    mac.h \
    wireless.h
