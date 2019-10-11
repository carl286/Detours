##############################################################################
##
##  API Extention to Measure time slept.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib ws2_32.lib

##############################################################################

all: dirs \
    $(BIND)\likehack$(DETOURS_BITS).dll \
    $(BIND)\liketest.exe \
    \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\likehack$(DETOURS_BITS).bsc \
    $(OBJD)\liketest.bsc \
!ENDIF
    option

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\likehack.obj : likehack.cpp

$(OBJD)\likehack.res : likehack.rc

$(BIND)\likehack$(DETOURS_BITS).dll $(BIND)\likehack$(DETOURS_BITS).lib: \
        $(OBJD)\likehack.obj $(OBJD)\likehack.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\likehack.obj $(OBJD)\likehack.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        /export:TimedSleepEx \
        /export:HackGetAddrInfoW \
        /export:HackSocket \
        /export:HackWSASocketW \
        /export:HackBind \
        /export:HackConnect \
        /export:HackListen \
        /export:HackGetSockName \
        /export:HackGetAddrInfoW \
        /export:HackGetAddrInfoExW \
        /export:HackGetHostByName \
        /export:HackWSAConnect \
        /export:HackWSAConnectByList \
        /export:HackSendTo \
        /export:HackWSASendTo \
        /export:HackWSASend \
        /export:HackWSARecv \
        /export:HackSend \
        /export:HackRecv \
        $(LIBS)

$(OBJD)\likehack$(DETOURS_BITS).bsc : $(OBJD)\likehack.obj
    bscmake /v /n /o $@ $(OBJD)\likehack.sbr

$(OBJD)\liketest.obj : liketest.cpp

$(BIND)\liketest.exe : $(OBJD)\liketest.obj $(DEPS)
    cl $(CFLAGS) /Fe$@ /Fd$(@R).pdb $(OBJD)\liketest.obj \
        /link $(LINKFLAGS) $(LIBS) \
        /subsystem:console

$(OBJD)\liketest.bsc : $(OBJD)\liketest.obj
    bscmake /v /n /o $@ $(OBJD)\liketest.sbr

##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\likehack*.* 2>nul
    -del $(BIND)\liketest.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\likehack$(DETOURS_OPTION_BITS).dll:
$(OPTD)\likehack$(DETOURS_OPTION_BITS).pdb:

$(BIND)\likehack$(DETOURS_OPTION_BITS).dll : $(OPTD)\likehack$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\likehack$(DETOURS_OPTION_BITS).pdb : $(OPTD)\likehack$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\likehack$(DETOURS_OPTION_BITS).dll \
    $(BIND)\likehack$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

test: all
    @echo -------- Reseting test binaries to initial state. ---------------------
    $(BIND)\setdll.exe -r $(BIND)\liketest.exe
    @echo.
    @echo -------- Should not load likehack$(DETOURS_BITS).dll -----------------------------------
    $(BIND)\liketest.exe
    @echo.
    @echo -------- Adding likehack$(DETOURS_BITS).dll to liketest.exe ------------------------------
    $(BIND)\setdll.exe -d:$(BIND)\likehack$(DETOURS_BITS).dll $(BIND)\liketest.exe
    @echo.
    @echo -------- Should load likehack$(DETOURS_BITS).dll statically ----------------------------
    $(BIND)\liketest.exe
    @echo.
    @echo -------- Removing likehack$(DETOURS_BITS).dll from liketest.exe --------------------------
    $(BIND)\setdll.exe -r $(BIND)\liketest.exe
    @echo.
    @echo -------- Should not load likehack$(DETOURS_BITS).dll -----------------------------------
    $(BIND)\liketest.exe
    @echo.
    @echo -------- Should load likehack$(DETOURS_BITS).dll dynamically using withdll.exe----------
    $(BIND)\withdll.exe -d:$(BIND)\likehack$(DETOURS_BITS).dll $(BIND)\liketest.exe
    @echo.

debug: all
    windbg -o $(BIND)\withdll.exe -d:$(BIND)\likehack$(DETOURS_BITS).dll $(BIND)\liketest.exe


################################################################# End of File.
