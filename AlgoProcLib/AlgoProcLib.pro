QT       -= core gui

TARGET = AlgoProcLib
TEMPLATE = lib

CONFIG += c++11

unix
{
    CONFIG(debug, debug|release) {
        DESTDIR = $$PWD/../build/debug
    } else {
        DESTDIR = $$PWD/../build/release
    }
}

unix{
    target.path = /usr/lib
    INSTALLS += target
}

INCLUDEPATH += \
    $$PWD/../util \
    $$PWD/../include/openssl-1.0.0/openssl \
    $$PWD/../include/openssl-1.0.0

SOURCES += \
    algoproclib.cpp \
    algoprocfactory.cpp \
    symmkeygenerator.cpp

HEADERS += \
    algoproclib.h \
    algoprocfactory.h \
    algoproc_common.h \
    symmkeygenerator.h
