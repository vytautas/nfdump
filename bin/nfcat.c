/*
 *  Copyright (c) 2013, Vytautas Krakauskas
 *  Copyright (c) 2013, Kaunas university of technology
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Kaunas university of technology nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
This is a crude utility to join multiple nfdump files as a one stream.
Please be aware that some data from file and stat headers will be lost
(e.g. source ident).
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "nffile.h"

// Set the block header
int ReadDataHeader(nffile_t *nffile);

int ReadDataHeader(nffile_t *nffile) {
	ssize_t rlen;
	ssize_t hsize = sizeof(data_block_header_t);

	rlen = read(nffile->fd, nffile->block_header, hsize);
	if (rlen < hsize) {
		if (0 == rlen) {
			// This is the end
			return 0;
		} else if (rlen < 0) {
			perror("Header read failed");
			return -1;
		} else {
			fprintf(stderr, "Short read (%ld of %ld)\n", rlen, hsize);
			return -1;
		}
	}
	return hsize;
} // end of ReadDataHeader


int main (void) {
	nffile_t *nffile_in, *nffile_out = NULL;
	ssize_t rlen, wlen, rpos, wpos, toread;
	ssize_t trash_len = sizeof(file_header_t)+sizeof(stat_record_t);
	char *trash_buf[trash_len];
	file_header_t *fh;
	char header_ok;

	// read from stdin
	if ((nffile_in = OpenFile(NULL, NULL)) == NULL) {
		perror("Unable to open input");
		return 1;
	}

	// write to stdout
	if ((nffile_out = OpenNewFile("-", NULL, FILE_IS_COMPRESSED(nffile_in), IP_ANONYMIZED(nffile_in), nffile_in->file_header->ident)) == NULL) {
		perror("Unable to open output");
		return 1;
	}

	while (1) {
		header_ok = 0;
		// Initial try to read the data header
		if ((rlen = ReadDataHeader(nffile_in)) <= 0) {
			return rlen;
		}
		do {
			// Check if it is a start of a new file
			fh = (file_header_t *) nffile_in->block_header;
			if (MAGIC == fh->magic && LAYOUT_VERSION_1 == fh->version) {
				// its a new file, skip the file_header_t and stat_record_t
				toread = trash_len-rlen;
				do {
					if ((rlen = read(nffile_in->fd, trash_buf, toread)) < 0) {
						perror("file/stat header read failed");
						return 1;
					}
					toread -= rlen;
				} while (toread > 0);

				// File/Stat headers skipped, read the data header
				if ((rlen = ReadDataHeader(nffile_in)) <= 0) {
					return rlen;
				}
			} else {
				header_ok = 1;
			}
		} while (!header_ok);

		// write the header
		if (write(nffile_out->fd, nffile_in->block_header, sizeof(data_block_header_t)) != rlen) {
			perror("Short write on header");
			return 1;
		}

		// read the data
		rpos = 0;
		do {
			toread = nffile_in->block_header->size - rpos;
			if ((rlen = read(nffile_in->fd, (void *)(nffile_in->buff_ptr + rpos), toread)) < 0) {
				perror("Data block read failed");
				return 1;
			} else if (0 == rlen) {
				if  (rpos > 0) {
					// Part of a block was read
					perror("Unfinished block!");
					return 1;
				} else {
					// This is the end
					return 0;
				}
			} else {
				rpos += rlen;
			}
		} while (rpos < nffile_in->block_header->size);

		// write the data
		wpos = 0;
		do {
			if ((wlen = write(nffile_out->fd, (void *)(nffile_in->buff_ptr + wpos), nffile_in->block_header->size - wpos)) < 0) {
				perror("Data block write failed");
				return 1;
			}
			wpos += wlen;
		} while (wpos < rlen);
	} // end of while(1)

	CloseFile(nffile_in);
	DisposeFile(nffile_in);

	CloseFile(nffile_out);
	DisposeFile(nffile_out);

	return 0;
}
