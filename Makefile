CFLAGS	= -Wall -O2 -g

ifdef KERNEL_HEADERS
	CFLAGS += -I$(KERNEL_HEADERS)
endif

EXE = mboxd

all: $(EXE)

$(EXE): common.o

mboxd: CFLAGS += -DPREFIX="\"MBOXD\""

clean:
	rm -rf *.o $(EXE)
