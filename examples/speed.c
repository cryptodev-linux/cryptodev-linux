/*  cryptodev_test - simple benchmark tool for cryptodev
 *
 *    Copyright (C) 2010 by Phil Sutter <phil.sutter@viprinet.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "../cryptodev.h"
#include "../ncr.h"

static double udifftimeval(struct timeval start, struct timeval end)
{
	return (double)(end.tv_usec - start.tv_usec) +
	       (double)(end.tv_sec - start.tv_sec) * 1000 * 1000;
}

static int must_finish = 0;

static void alarm_handler(int signo)
{
        must_finish = 1;
}

static void value2human(double bytes, double time, double* data, double* speed,char* metric)
{
        if (bytes > 1000 && bytes < 1000*1000) {
                *data = ((double)bytes)/1000;
                *speed = *data/time;
                strcpy(metric, "Kb");
                return;
        } else if (bytes >= 1000*1000 && bytes < 1000*1000*1000) {
                *data = ((double)bytes)/(1000*1000);
                *speed = *data/time;
                strcpy(metric, "Mb");
                return;
        } else if (bytes >= 1000*1000*1000) {
                *data = ((double)bytes)/(1000*1000*1000);
                *speed = *data/time;
                strcpy(metric, "Gb");
                return;
        } else {
                *data = (double)bytes;
                *speed = *data/time;
                strcpy(metric, "bytes");
                return;
        }
}


int encrypt_data(int cipher, int fdc, int chunksize)
{
	struct crypt_op cop;
	char *buffer, iv[32];
	static int val = 23;
	struct timeval start, end;
	double total = 0;
	double secs, ddata, dspeed;
	struct session_op sess;
	char metric[16];
	char keybuf[16];
	int keylen;

	memset(keybuf, 0x42, 16);
	if (cipher == CRYPTO_NULL)
		keylen = 0;
	else keylen = 16;

	buffer = malloc(chunksize);
	memset(iv, 0x23, 32);

	printf("\tEncrypting in chunks of %d bytes: ", chunksize);
	fflush(stdout);

	memset(buffer, val++, chunksize);

	must_finish = 0;
	alarm(5);

	gettimeofday(&start, NULL);
	do {
		memset(&sess, 0, sizeof(sess));
		sess.cipher = cipher;
		sess.keylen = keylen;
		sess.key = (unsigned char *)keybuf;
		if (ioctl(fdc, CIOCGSESSION, &sess)) {
			perror("ioctl(CIOCGSESSION)");
			return 1;
		}

		memset(&cop, 0, sizeof(cop));
		cop.ses = sess.ses;
		cop.len = chunksize;
		cop.iv = (unsigned char *)iv;
		cop.op = COP_ENCRYPT;
		cop.flags = 0;
		cop.src = cop.dst = (unsigned char *)buffer;

		if (ioctl(fdc, CIOCCRYPT, &cop)) {
			perror("ioctl(CIOCCRYPT)");
			return 1;
		}
		
		ioctl(fdc, CIOCFSESSION, &sess.ses);

		total+=chunksize;
	} while(must_finish==0);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end)/ 1000000.0;
	
	value2human(total, secs, &ddata, &dspeed, metric);
	printf ("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
	printf ("%.2f %s/sec\n", dspeed, metric);

	return 0;
}


int encrypt_data_ncr_direct(int cfd, int algo, int chunksize)
{
	char *buffer, iv[32];
	static int val = 23;
	struct timeval start, end;
	double total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	ncr_key_t key;
	struct ncr_key_generate_st kgen;
	struct ncr_session_once_op_st nop;

	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	kgen.desc = key;
	kgen.params.algorithm = NCR_ALG_AES_CBC;
	kgen.params.keyflags = NCR_KEY_FLAG_EXPORTABLE;
	kgen.params.params.secret.bits = 128; /* 16  bytes */
	
	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}


	buffer = malloc(chunksize);
	memset(iv, 0x23, 32);

	printf("\tEncrypting in chunks of %d bytes: ", chunksize);
	fflush(stdout);

	memset(buffer, val++, chunksize);

	must_finish = 0;
	alarm(5);

	gettimeofday(&start, NULL);
	do {
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = algo;
		nop.init.key = key;
		nop.init.op = NCR_OP_ENCRYPT;
		nop.op.data.udata.input = buffer;
		nop.op.data.udata.input_size = chunksize;
		nop.op.data.udata.output = buffer;
		nop.op.data.udata.output_size = chunksize;
		nop.op.type = NCR_DIRECT_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		total+=chunksize;
	} while(must_finish==0);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end)/ 1000000.0;
	
	value2human(total, secs, &ddata, &dspeed, metric);
	printf ("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
	printf ("%.2f %s/sec\n", dspeed, metric);

	return 0;
}

int main(void)
{
	int fd, i, fdc = -1;

	signal(SIGALRM, alarm_handler);

	if ((fd = open("/dev/crypto", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}
	if (ioctl(fd, CRIOGET, &fdc)) {
		perror("ioctl(CRIOGET)");
		return 1;
	}

	fprintf(stderr, "Testing NULL cipher: \n");

	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data(CRYPTO_NULL, fdc, i))
			break;
	}

	fprintf(stderr, "\nTesting NCR-DIRECT with NULL cipher: \n");
	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data_ncr_direct(fdc, NCR_ALG_NULL, i))
			break;
	}

	fprintf(stderr, "\nTesting AES-128-CBC cipher: \n");

	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data(CRYPTO_AES_CBC, fdc, i))
			break;
	}

	fprintf(stderr, "\nTesting NCR-DIRECT with AES-128-CBC cipher: \n");
	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data_ncr_direct(fdc, NCR_ALG_AES_CBC, i))
			break;
	}


	close(fdc);
	close(fd);
	return 0;
}
