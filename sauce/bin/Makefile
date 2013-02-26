CC = gcc
CFLAGS += -Wall -Wextra -ggdb -O0
LDFLAGS += -Wl,-O0

all: suexec
	@sudo -p "Enter the password for %p to set owner and setuid bit: " -v
	sudo chown root $^
	sudo chmod u+s $^

suexec.o: suexec.c suexec.h

