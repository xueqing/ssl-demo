QT -= core gui

CONFIG += c++11

TARGET = GmSSLDemo
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

INCLUDEPATH += \
    $$PWD/../util \
    $$PWD/../AlgoProcLib \
    $$PWD/../include/openssl-1.0.0

unix
{
    CONFIG(debug, debug|release) {
        LIBS += -L$$PWD/../build/debug
        DESTDIR = $$PWD/../build/debug
    } else {
        LIBS += -L$$PWD/../build/release
        DESTDIR = $$PWD/../build/release
    }
}

unix{
    target.path = /usr/lib
    INSTALLS += target
}

LIBS += \
    -lAlgoProcLib \
    -lUtilityLib


LIBS += \
    -L$$PWD/../lib/openssl-1.0.0 \
    -lcrypto

SOURCES += \
    main.cpp \
    algoprocinterface.cpp

HEADERS += \
    algoprocinterface.h
