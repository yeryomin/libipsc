NAME    = libipsc
SOURCES = $(NAME).c priv.c
HEADERS = $(NAME).h priv.h
OBJECTS = $(SOURCES:.c=.o)
SHARED  = $(NAME).so
STATIC  = $(NAME).a
RANLIB ?= ranlib

LDFLAGS += -lssl -lcrypto

default: all
all: $(HEADERS) $(SOURCES) $(SHARED) $(STATIC)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(SHARED): $(HEADERS) $(SOURCES) $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -shared -o $@

$(STATIC): $(HEADERS) $(SOURCES) $(OBJECTS)
	$(AR) -rcv $@ $(OBJECTS)
	$(RANLIB) $(STATIC)

clean:
	rm -f *.o
	rm -f $(SHARED)
	rm -f $(STATIC)


.PHONY: default all $(SHARED) $(STATIC) clean
