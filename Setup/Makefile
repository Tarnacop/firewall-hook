CFLAGS = -D_POSIX_SOURCE -Wall -Werror -pedantic -std=c99 -D_GNU_SOURCE -pthread
GCC = gcc $(CFLAGS)

APPS = firewallSetup

all: $(APPS)

firewallSetup: firewallSetup.c
	$(GCC) -o firewallSetup firewallSetup.c

clean:
	rm -f $(APPS)