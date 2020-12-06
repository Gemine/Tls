# ECC Examples Makefile
CC       = g++
LIB_PATH = /usr/local
CFLAGS   = -Wall -I$(LIB_PATH)/include
LIBS     = -L$(LIB_PATH)/lib -lm

# option variables
DYN_LIB         = -lwolfssl -pthread
STATIC_LIB      = $(LIB_PATH)/lib/libwolfssl.a
DEBUG_FLAGS     = -g -DDEBUG
DEBUG_INC_PATHS = -MD
OPTIMIZE        = -Os
OUTPUT_DIR		= ./build

# Options
#CFLAGS+=$(DEBUG_FLAGS)
CFLAGS+=$(OPTIMIZE)
#LIBS+=$(STATIC_LIB)
LIBS+=$(DYN_LIB)

# build targets
SRC=$(wildcard *.cpp)
TARGETS=$(patsubst %.cpp, %, $(SRC))

.PHONY: clean all

all: $(TARGETS)

debug: CFLAGS+=$(DEBUG_FLAGS)
debug: all

# build template
%: %.cpp
	$(CC) -o $(OUTPUT_DIR)/$@ $< $(CFLAGS) $(LIBS)

clean:
	rm  ./build/main
	rm -f ECC*.der
	rm -f ECC*.pem
run:
	./build/main