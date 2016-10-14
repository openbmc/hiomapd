CFLAGS	= -Wall -O2 -g

ifdef KERNEL_HEADERS
	CFLAGS += -I$(KERNEL_HEADERS)
endif

EXE =

all: $(EXE)

$(EXE): common.o

clean:
	rm -rf *.o $(EXE)
