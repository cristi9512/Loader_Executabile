/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 *
 * Cristi Nica
 * 336 CA
 */

#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>


#include "exec_parser.h"
#include "utils.h"

static so_exec_t *exec;
static int pageSize;
static struct sigaction old_action;
char *p;
int fd;
void *rc;

/*
 * Functie ce verifica daca o adresa se afla in interiorul
 * segmentelor de memorie ale unui fisier executabil
 */
int address_in_segments(char *addr)
{
	int i;

	for (i = 0; i < exec->segments_no; i++) {
		char *aux = (char *)exec->segments[i].vaddr;

		if (aux <= addr &&
			addr <= aux + exec->segments[i].mem_size)
			return i;
		}
	return -1;
}

/*
 * Functie ce trateaza un eveniment de tip page-fault.
 * Va verifica semnalul care a generat apelarea handler-ului,
 * va obtine adresa la care page-fault-ul a fost produs si il
 * va trata.
 */

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	char *addr;
	int ok, permission, segmVaddr, segmOffset, fileSize;
	int memSize, page, segNr, auxOffset;
	void *auxAddr;

	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	addr = (char *) info->si_addr;

	if (info->si_code == SEGV_ACCERR) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}
	ok = address_in_segments(addr);

	if (ok != -1) {
		segNr = ok;
		segmVaddr = exec->segments[segNr].vaddr;
		page = ((int) addr - segmVaddr) / pageSize;

		permission = exec->segments[segNr].perm;
		memSize = exec->segments[segNr].mem_size;
		segmOffset = exec->segments[segNr].offset;
		fileSize = exec->segments[segNr].file_size;
		auxOffset = page * pageSize + segmOffset;
		auxAddr = (void *)  (page * pageSize) + segmVaddr;

		if (page * pageSize < fileSize  &&
			(page + 1) * pageSize < fileSize) {
			p = mmap(auxAddr, pageSize, permission,
				MAP_FIXED | MAP_PRIVATE, fd, auxOffset);
			DIE(p == (char *)-1, "mmap");
		} else if (page * pageSize < fileSize &&
			(page + 1) * pageSize >= fileSize) {

			p = mmap(auxAddr, pageSize, permission,
				MAP_FIXED | MAP_PRIVATE, fd, auxOffset);
			DIE(p == (char *)-1, "mmap");
			if ((page + 1) * pageSize < memSize)
				rc = memset((void *)segmVaddr + fileSize, 0,
				(page + 1) * pageSize - fileSize);
			else
				rc = memset((void *)segmVaddr + fileSize, 0,
				memSize - fileSize);
			DIE(rc < 0, "memset");

		} else{
			p = mmap((void *)segmVaddr + page * pageSize,
				pageSize, permission, MAP_FIXED |
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			DIE(p == (char *)-1, "mmap");
		}

	} else {
		old_action.sa_sigaction(signum, info, context);
		return;
	}
}

/*
 * Functie ce realizeaza declararea handler-ului care va trata
 * evenimentele de tip page-fault.
 */

int so_init_loader(void)
{
	struct sigaction action;
	int rez;

	pageSize = getpagesize();
	memset(&action, 0, sizeof(struct sigaction));
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = &segv_handler;
	rez = sigaction(SIGSEGV, &action, &old_action);
	DIE(rez == -1, "sigaction");
	return rez;
}

int so_execute(char *path, char *argv[])
{
	int aux;

	fd = open(path, O_RDONLY, 0644);
	DIE(fd < 0, "open file");
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	so_start_exec(exec, argv);
	aux = close(fd);
	DIE(aux == -1, "close file");
	return -1;
}
