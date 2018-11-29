# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

TOPDIR = ..

INCLUDES := -I. -I$(TOPDIR)/include -I$(TOPDIR)/include/uapi
ALL_CFLAGS := $(INCLUDES)

FEATURE_REALLOCARRAY := $(shell $(TOPDIR)/scripts/check-reallocarray.sh)
ifneq ($(FEATURE_REALLOCARRAY),)
	ALL_CFLAGS += -DCOMPAT_NEED_REALLOCARRAY
endif

ifdef BUILD_SHARED
	ALL_CFLAGS += -fPIC -fvisibility=hidden
endif

CFLAGS ?= -g -O2 -Werror -Wall
ALL_CFLAGS += $(CFLAGS)

OBJDIR ?= .

OBJS := $(addprefix $(OBJDIR)/,bpf.o btf.o libbpf.o libbpf_errno.o netlink.o \
	nlattr.o str_error.o)

LIBS := $(OBJDIR)/libbpf.a
ifdef BUILD_SHARED
	LIBS += $(OBJDIR)/libbpf.so
endif

HEADERS := bpf.h libbpf.h btf.h
UAPI_HEADERS := $(addprefix $(TOPDIR)/include/uapi/linux/,bpf.h btf.h)

INSTALL = install

DESTDIR ?=

ifeq ($(shell uname -m),x86_64)
	LIBSUBDIR := lib64
else
	LIBSUBDIR := lib
endif

PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/$(LIBSUBDIR)
INCLUDEDIR ?= $(PREFIX)/include
UAPIDIR ?= $(PREFIX)/include

all: $(LIBS)

$(OBJDIR)/libbpf.a: $(OBJS)
	$(AR) rcs $@ $^

$(OBJDIR)/libbpf.so: $(OBJS)
	$(CC) -shared $(LDFLAGS) $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

define do_install
	if [ ! -d '$(DESTDIR)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR)$2';	\
	fi;						\
	$(INSTALL) $1 $(if $3,-m $3,) '$(DESTDIR)$2'
endef

install: all install_headers
	$(call do_install,$(LIBS),$(LIBDIR))

install_headers:
	$(call do_install,$(HEADERS),$(INCLUDEDIR)/bpf,644)

# UAPI headers can be installed by a different package so they're not installed
# in by install rule.
install_uapi_headers:
	$(call do_install,$(UAPI_HEADERS),$(UAPIDIR)/linux,644)

clean:
	rm -f *.o *.a *.so
