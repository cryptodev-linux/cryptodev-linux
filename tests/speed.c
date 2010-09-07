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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <linux/netlink.h>
#include "../ncr.h"
#include "utils.h"

#define ALG_AES_CBC "cbc(aes)"

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

static void value2human(double bytes, double time, double *data, double *speed,
			char *metric)
{
	if (bytes > 1000 && bytes < 1000 * 1000) {
		*data = ((double)bytes) / 1000;
		*speed = *data / time;
		strcpy(metric, "Kb");
		return;
	} else if (bytes >= 1000 * 1000 && bytes < 1000 * 1000 * 1000) {
		*data = ((double)bytes) / (1000 * 1000);
		*speed = *data / time;
		strcpy(metric, "Mb");
		return;
	} else if (bytes >= 1000 * 1000 * 1000) {
		*data = ((double)bytes) / (1000 * 1000 * 1000);
		*speed = *data / time;
		strcpy(metric, "Gb");
		return;
	} else {
		*data = (double)bytes;
		*speed = *data / time;
		strcpy(metric, "bytes");
		return;
	}
}

int encrypt_data_ncr_direct(int cfd, const char *algo, int chunksize)
{
	char *buffer, iv[32];
	static int val = 23;
	struct timeval start, end;
	double total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	ncr_key_t key;
	NCR_STRUCT(ncr_key_generate) kgen;
	NCR_STRUCT(ncr_session_once) op;
	struct nlattr *nla;
	size_t algo_size;

	algo_size = strlen(algo) + 1;
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	nla = NCR_INIT(kgen);
	kgen.f.key = key;
	ncr_put_string(&nla, NCR_ATTR_ALGORITHM, ALG_AES_CBC);
	ncr_put_u32(&nla, NCR_ATTR_SECRET_KEY_BITS, 128); /* 16 bytes */
	NCR_FINISH(kgen, nla);

	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE)");
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
		size_t output_size;

		nla = NCR_INIT(op);
		op.f.op = NCR_OP_ENCRYPT;
		ncr_put_u32(&nla, NCR_ATTR_KEY, key);
		ncr_put_session_input_data(&nla, NCR_ATTR_UPDATE_INPUT_DATA,
					   buffer, chunksize);
		ncr_put_session_output_buffer(&nla,
					      NCR_ATTR_UPDATE_OUTPUT_BUFFER,
					      buffer, chunksize, &output_size);
		ncr_put(&nla, NCR_ATTR_IV, NULL, 0);
		ncr_put(&nla, NCR_ATTR_ALGORITHM, algo, algo_size);
		NCR_FINISH(op, nla);

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &op)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		total += chunksize;
	} while (must_finish == 0);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end) / 1000000.0;

	value2human(total, secs, &ddata, &dspeed, metric);
	printf("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
	printf("%.2f %s/sec\n", dspeed, metric);

	return 0;
}

int main(void)
{
	int fd, i;

	signal(SIGALRM, alarm_handler);

	if ((fd = open("/dev/ncr", O_RDWR, 0)) < 0) {
		perror("open()");
		return 1;
	}

	fprintf(stderr, "\nTesting NCR-DIRECT with NULL cipher: \n");
	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data_ncr_direct(fd, "ecb(cipher_null)", i))
			break;
	}

	fprintf(stderr, "\nTesting NCR-DIRECT with AES-128-CBC cipher: \n");
	for (i = 256; i <= (64 * 1024); i *= 2) {
		if (encrypt_data_ncr_direct(fd, "cbc(aes)", i))
			break;
	}

	close(fd);
	return 0;
}
