LITEOSTOPDIR = /home/zhaozuoen/file/liteos/Hi3518E_SDK_V5.0.5.3/osdrv/opensource/liteos/liteos/
#LITEOSTOPDIR = /home/zhaozuoen/file/liteos/Hi1131C_V100R001C01B361/Software/Source/liteos
include $(LITEOSTOPDIR)/config.mk


ALLDIR = ../../
TOPDIR = ..
SRCDIR = $(TOPDIR)/src
LIBDIR = $(TOPDIR)/lib/

LITEOS_CFLAGS += -I$(TOPDIR)/include -I$(ALLDIR)/libqr.a/inc -I$(ALLDIR)/libqr.a/src

AFLAGS	+= -r

FILE = config

ifeq ($(FILE), $(wildcard $(FILE)))
include $(FILE)
else
$(error "please run xmconfig")
endif


LITEOS_CFLAGS += $(LibCFlags)

ifeq ($(DEBUG_ON),true)
	LITEOS_CFLAGS += -g
	CPPFLAGS += -g
	STRIP 	= @echo " no STRIP $@";
	LIB_TARGET := $(LIBDIR)libxmconnect$(LibExt)-d.a
else
	LITEOS_CFLAGS  += -Os 
	CPPFLAGS  += -Os
	STRIP 	= @echo " STRIP $@"; $(CROSS)strip
	LIB_TARGET= $(LIBDIR)libxmconnect$(LibExt).a
endif

LIB_OBJS =	$(SRCDIR)/xmconnect.o	$(SRCDIR)/xmnet.o $(SRCDIR)/xmcmd.o
	
	
TARGET	= $(LIB_TARGET)

all: clean $(TARGET)
	

$(LIB_TARGET): $(LIB_OBJS)
	
	
	$(RM) $@;
	$(AR) $(AFLAGS) $@ $^
	cp -rf $@ /home/zhaozuoen/file/liteos/Hi1131C_V100R001C01B361/Software/Source/wifi_project/out/hi3518ev200/lib
	cp -rf $@ /home/zhaozuoen/file/liteos/build/I_2016.3.07_IPC_V1.01.R01/_libs/LITEOS_HI3518EV200/V5.0.5.3
.c.o:
	$(CC)  $(LITEOS_CFLAGS) -c -o $@ $<

.cpp.o:
	$(GPP) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(LIB_OBJS);
	find ./ -type f \( -name '*.elf*' -o -name '*.gdb' \) | xargs rm -f
	rm -f /home/zhaozuoen/file/liteos/Hi1131C_V100R001C01B361/Software/Source/wifi_project/out/hi3518ev200/lib/libxmconnect_hi1131.a
