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
    mybase64.c \
    algoproclib.cpp \
    algoprocfactory.cpp \
    algoprocinterface.cpp \
    symmkeygenerator.cpp \
    rsakeygenerator.cpp \
    rsacrypt.cpp \
    rsapubkeyencrypt.cpp \
    rsaprikeydecrypt.cpp \
    aesencrypt.cpp \
    aesdecrypt.cpp

HEADERS += \
    mybase64.h \
    algoproclib.h \
    algoprocfactory.h \
    algoproc_common.h \
    algoprocinterface.h \
    symmkeygenerator.h \
    rsakeygenerator.h \
    rsacrypt.h \
    rsapubkeyencrypt.h \
    rsaprikeydecrypt.h \
    aesencrypt.h \
    aesdecrypt.h
