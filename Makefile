CC:=gcc
CFLAGS:=-Wall -Wextra -Werror
LFLAGS:=

EXE:=win32_exe_ico_extract

SRC:=win32_exe_ico_extract.c
OBJ:=$(SRC:.c=.o)

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -fv $(EXE) $(OBJ)
