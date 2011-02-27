/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nffile.c 41 2009-12-31 14:46:28Z haag $
 *
 *  $LastChangedRevision: 41 $
 *	
 */

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "minilzo.h"
#include "nf_common.h"
#include "nffile.h"
#include "util.h"

/* global vars */

char 	*CurrentIdent;

/* local vars */
static file_header_t	FileHeader;
static stat_record_t	NetflowStat;

#define file_compressed (FileHeader.flags & FLAG_COMPRESSED)

// LZO params
#define LZO_BUFFSIZE  ((BUFFSIZE + BUFFSIZE / 16 + 64 + 3) + sizeof(data_block_header_t))
#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);
static void *lzo_buff;
static int lzo_initialized = 0;

#define ERR_SIZE 256
static char	error_string[ERR_SIZE];

static int LZO_initialize(void);

extern char *nf_error;

/* function prototypes */

static void ZeroStat(void);

/* function definitions */

static void ZeroStat() {

	FileHeader.NumBlocks 	= 0;
	strncpy(FileHeader.ident, IdentNone, IdentLen);

	NetflowStat.first_seen  = 0;
	NetflowStat.last_seen	= 0;
	NetflowStat.msec_first	= 0;
	NetflowStat.msec_last	= 0;

	CurrentIdent			= FileHeader.ident;

} // End of ZeroStat

void SumStatRecords(stat_record_t *s1, stat_record_t *s2) {

	s1->numflows			+= s2->numflows;
	s1->numbytes			+= s2->numbytes;
	s1->numpackets			+= s2->numpackets;
	s1->numflows_tcp		+= s2->numflows_tcp;
	s1->numflows_udp		+= s2->numflows_udp;
	s1->numflows_icmp		+= s2->numflows_icmp;
	s1->numflows_other		+= s2->numflows_other;
	s1->numbytes_tcp		+= s2->numbytes_tcp;
	s1->numbytes_udp		+= s2->numbytes_udp;
	s1->numbytes_icmp		+= s2->numbytes_icmp;
	s1->numbytes_other		+= s2->numbytes_other;
	s1->numpackets_tcp		+= s2->numpackets_tcp;
	s1->numpackets_udp		+= s2->numpackets_udp;
	s1->numpackets_icmp		+= s2->numpackets_icmp;
	s1->numpackets_other	+= s2->numpackets_other;
	s1->sequence_failure	+= s2->sequence_failure;

	if ( s2->first_seen < s1->first_seen ) {
		s1->first_seen = s2->first_seen;
		s1->msec_first = s2->msec_first;
	}
	if ( s2->first_seen == s1->first_seen && 
		 s2->msec_first < s1->msec_first ) 
			s1->msec_first = s2->msec_first;

	if ( s2->last_seen > s1->last_seen ) {
		s1->last_seen = s2->last_seen;
		s1->msec_last = s2->msec_last;
	}
	if ( s2->last_seen == s1->last_seen && 
		 s2->msec_last > s1->msec_last ) 
			s1->msec_last = s2->msec_last;

} // End of SumStatRecords


char *GetIdent(void) {

	return CurrentIdent;

} // End of GetIdent

int IsCompressed(void) {
	return file_compressed;
} // End of IsCompressed

int IsAnonymized(void) {
	return (FileHeader.flags & FLAG_ANONYMIZED);
} // End of IsCompressed

static int LZO_initialize(void) {

	if (lzo_init() != LZO_E_OK) {
			// this usually indicates a compiler bug - try recompiling 
			// without optimizations, and enable `-DLZO_DEBUG' for diagnostics
			snprintf(error_string, ERR_SIZE,"Compression lzo_init() failed.\n");
			return 0;
	} 
	lzo_buff = malloc(BUFFSIZE+ sizeof(data_block_header_t));
	if ( !lzo_buff ) {
		snprintf(error_string, ERR_SIZE, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		error_string[ERR_SIZE-1] = 0;
		return 0;
	}
	lzo_initialized = 1;

	return 1;

} // End of LZO_initialize


int OpenFile(char *filename, stat_record_t **stat_record, char **err){
struct stat stat_buf;
int fd, ret;

	*err = NULL;
	if ( stat_record ) 
		*stat_record = &NetflowStat;

	if ( filename == NULL ) {
		// stdin
		ZeroStat();
		fd = STDIN_FILENO;
	} else {
		// regular file
		if ( stat(filename, &stat_buf) ) {
			snprintf(error_string, ERR_SIZE, "Can't stat '%s': %s\n", filename, strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		if (!S_ISREG(stat_buf.st_mode) ) {
			snprintf(error_string, ERR_SIZE, "'%s' is not a file\n", filename);
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		// printf("Statfile %s\n",filename);
		fd =  open(filename, O_RDONLY);
		if ( fd < 0 ) {
			snprintf(error_string, ERR_SIZE, "Error open file: %s\n", strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return fd;
		}

	}

	ret = read(fd, (void *)&FileHeader, sizeof(FileHeader));
	if ( FileHeader.magic != MAGIC ) {
		snprintf(error_string, ERR_SIZE, "Open file '%s': bad magic: 0x%X\n", filename ? filename : "<stdin>", FileHeader.magic );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	if ( FileHeader.version != LAYOUT_VERSION_1 ) {
		snprintf(error_string, ERR_SIZE,"Open file %s: bad version: %u\n", filename, FileHeader.version );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	read(fd, (void *)&NetflowStat, sizeof(NetflowStat));

// for debugging:
/*
	printf("Magic: 0x%X\n", FileHeader.magic);
	printf("Version: %i\n", FileHeader.version);
	printf("Flags: %i\n", FileHeader.flags);
	printf("NumBlocks: %i\n", FileHeader.NumBlocks);
	printf("Ident: %s\n\n", FileHeader.ident);

	printf("Flows: %llu\n", NetflowStat.numflows);
	printf("Flows_tcp: %llu\n", NetflowStat.numflows_tcp);
	printf("Flows_udp: %llu\n", NetflowStat.numflows_udp);
	printf("Flows_icmp: %llu\n", NetflowStat.numflows_icmp);
	printf("Flows_other: %llu\n", NetflowStat.numflows_other);
	printf("Packets: %llu\n", NetflowStat.numpackets);
	printf("Packets_tcp: %llu\n", NetflowStat.numpackets_tcp);
	printf("Packets_udp: %llu\n", NetflowStat.numpackets_udp);
	printf("Packets_icmp: %llu\n", NetflowStat.numpackets_icmp);
	printf("Packets_other: %llu\n", NetflowStat.numpackets_other);
	printf("Bytes: %llu\n", NetflowStat.numbytes);
	printf("Bytes_tcp: %llu\n", NetflowStat.numbytes_tcp);
	printf("Bytes_udp: %llu\n", NetflowStat.numbytes_udp);
	printf("Bytes_icmp: %llu\n", NetflowStat.numbytes_icmp);
	printf("Bytes_other: %llu\n", NetflowStat.numbytes_other);
	printf("First: %u\n", NetflowStat.first_seen);
	printf("Last: %u\n", NetflowStat.last_seen);
	printf("msec_first: %u\n", NetflowStat.msec_first);
	printf("msec_last: %u\n", NetflowStat.msec_last);
*/
	CurrentIdent		= FileHeader.ident;

	if ( file_compressed && !lzo_initialized && !LZO_initialize() ) {
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
    }

	return fd;

} // End of OpenFile

int ChangeIdent(char *filename, char *Ident, char **err) {
struct stat stat_buf;
int fd, ret;

	*err = NULL;
	if ( filename == NULL ) 
		return 0;

	if ( stat(filename, &stat_buf) ) {
		snprintf(error_string, ERR_SIZE, "Can't stat '%s': %s\n", filename, strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}

	if (!S_ISREG(stat_buf.st_mode) ) {
		snprintf(error_string, ERR_SIZE, "'%s' is not a file\n", filename);
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}

	fd =  open(filename, O_RDWR);
	if ( fd < 0 ) {
		snprintf(error_string, ERR_SIZE, "Error open file: %s\n", strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return fd;
	}

	ret = read(fd, (void *)&FileHeader, sizeof(FileHeader));
	if ( FileHeader.magic != MAGIC ) {
		snprintf(error_string, ERR_SIZE, "Open file '%s': bad magic: 0x%X\n", filename, FileHeader.magic );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}
	if ( FileHeader.version != LAYOUT_VERSION_1 ) {
		snprintf(error_string, ERR_SIZE,"Open file %s: bad version: %u\n", filename, FileHeader.version );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}

	strncpy(FileHeader.ident, Ident, IdentLen);
	FileHeader.ident[IdentLen - 1] = 0;

	if ( lseek(fd, 0, SEEK_SET) < 0 ) {
		snprintf(error_string, ERR_SIZE,"lseek failed: '%s'\n" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}

	write(fd, (void *)&FileHeader, sizeof(file_header_t));
	if ( close(fd) < 0 ) {
		snprintf(error_string, ERR_SIZE,"close failed: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}
	
	return 0;

} // End of ChangeIdent


void PrintStat(stat_record_t *s) {

	if ( s == NULL )
		s = &NetflowStat;

	// format info: make compiler happy with conversion to (unsigned long long), 
	// which does not change the size of the parameter
	printf("Ident: %s\n", FileHeader.ident);
	printf("Flows: %llu\n", (unsigned long long)s->numflows);
	printf("Flows_tcp: %llu\n", (unsigned long long)s->numflows_tcp);
	printf("Flows_udp: %llu\n", (unsigned long long)s->numflows_udp);
	printf("Flows_icmp: %llu\n", (unsigned long long)s->numflows_icmp);
	printf("Flows_other: %llu\n", (unsigned long long)s->numflows_other);
	printf("Packets: %llu\n", (unsigned long long)s->numpackets);
	printf("Packets_tcp: %llu\n", (unsigned long long)s->numpackets_tcp);
	printf("Packets_udp: %llu\n", (unsigned long long)s->numpackets_udp);
	printf("Packets_icmp: %llu\n", (unsigned long long)s->numpackets_icmp);
	printf("Packets_other: %llu\n", (unsigned long long)s->numpackets_other);
	printf("Bytes: %llu\n", (unsigned long long)s->numbytes);
	printf("Bytes_tcp: %llu\n", (unsigned long long)s->numbytes_tcp);
	printf("Bytes_udp: %llu\n", (unsigned long long)s->numbytes_udp);
	printf("Bytes_icmp: %llu\n", (unsigned long long)s->numbytes_icmp);
	printf("Bytes_other: %llu\n", (unsigned long long)s->numbytes_other);
	printf("First: %u\n", s->first_seen);
	printf("Last: %u\n", s->last_seen);
	printf("msec_first: %u\n", s->msec_first);
	printf("msec_last: %u\n", s->msec_last);
	printf("Sequence failures: %u\n", s->sequence_failure);
} // End of PrintStat

static void InitFile(nffile_t *nffile) {

	// Init header
	nffile->file_header->magic 	   = MAGIC;
	nffile->file_header->version   = LAYOUT_VERSION_1;
	nffile->file_header->flags 	   = 0;
	nffile->file_header->NumBlocks = 0;

	// Init vars
	nffile->writeto		 = NULL;
	nffile->wfd			 = 0;

	// Init block header
	nffile->block_header->size 		 = 0;
	nffile->block_header->NumRecords = 0;
	nffile->block_header->id		 = DATA_BLOCK_TYPE_2;
	nffile->block_header->pad		 = 0;
	nffile->writeto = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));

} // End of InitFile

nffile_t *NewFile(void) {
nffile_t *nffile;

	// Create struct
	nffile = calloc(1, sizeof(nffile_t));
	if ( !nffile ) {
		snprintf(error_string, ERR_SIZE, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		error_string[ERR_SIZE-1] = 0;
		return NULL;
	}

	// Init file header
	nffile->file_header = calloc(1, sizeof(file_header_t));
	if ( !nffile->file_header ) {
		snprintf(error_string, ERR_SIZE, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		error_string[ERR_SIZE-1] = 0;
		return NULL;
	}

	// init output data buffer
	nffile->block_header = malloc(BUFFSIZE + sizeof(data_block_header_t));
	if ( !nffile->block_header ) {
		snprintf(error_string, ERR_SIZE, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		error_string[ERR_SIZE-1] = 0;
		return NULL;
	}

	return nffile;

} // End of NewFile

nffile_t *DisposeFile(nffile_t *nffile) {
	free(nffile->file_header);
	free(nffile->block_header);
	free(nffile);
	return NULL;
} // End of 

nffile_t *OpenNewFile(char *filename, nffile_t *nffile, int compressed, int anonymized, char **err) {
stat_record_t	stat_record;
size_t			len;
int 			flags;

	// Allocate new struct if not given
	if ( nffile == NULL ) {
		nffile = NewFile();
		if ( nffile == NULL ) {
			*err = error_string;
			return NULL;
		}
	}

	InitFile(nffile);

	flags = compressed ? FLAG_COMPRESSED : 0;
	if ( anonymized ) 
		SetFlag(flags, FLAG_ANONYMIZED);

	nffile->file_header->flags 	   = flags;

	if ( strcmp(filename, "-") == 0 ) { // output to stdout
		nffile->wfd = STDOUT_FILENO;
	} else {
		nffile->wfd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( nffile->wfd < 0 ) {
			snprintf(error_string, ERR_SIZE, "Failed to open file %s: '%s'" , filename, strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			return NULL;
		}
	}

	memset((void *)&stat_record, 0, sizeof(stat_record));

	if ( TestFlag(flags, FLAG_COMPRESSED) ) {
		if ( !lzo_initialized && !LZO_initialize() ) {
			snprintf(error_string, ERR_SIZE, "Failed to initialize compression");
			*err = error_string;
			close(nffile->wfd);
			return NULL;
		}
    }

	len = sizeof(file_header_t);
	if ( write(nffile->wfd, (void *)nffile->file_header, len) < len ) {
		snprintf(error_string, ERR_SIZE, "Failed to write file header: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(nffile->wfd);
		return NULL;
	}

	// write empty stat record - ist updated when file gets closed
	len = sizeof(stat_record_t);
	if ( write(nffile->wfd, (void *)&stat_record, len) < len ) {
		snprintf(error_string, ERR_SIZE, "Failed to write file header: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(nffile->wfd);
		return NULL;
	}

	return nffile;

} /* End of OpenNewFile */

void CloseUpdateFile(nffile_t *nffile, stat_record_t *stat_record, char *ident, char **err ) {
file_header_t	file_header;

	*err = NULL;
	if ( lseek(nffile->wfd, 0, SEEK_SET) < 0 ) {
		// lseek on stdout works if output redirected:
		// e.g. -w - > outfile
		// but fails on pipe e.g. -w - | ./nfdump .... 
		if ( nffile->wfd == STDOUT_FILENO ) {
			return;
		} else {
			snprintf(error_string, ERR_SIZE,"lseek failed: '%s'\n" , strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			close(nffile->wfd);
			return;
		}
	}

	strncpy(nffile->file_header->ident, ident ? ident : "unknown" , IdentLen);
	file_header.ident[IdentLen - 1] = 0;

	write(nffile->wfd, (void *)nffile->file_header, sizeof(file_header_t));
	write(nffile->wfd, (void *)stat_record, sizeof(stat_record_t));
	if ( close(nffile->wfd) < 0 ) {
		snprintf(error_string, ERR_SIZE,"close failed: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
	}
	
	return;

} /* End of CloseUpdateFile */

int ReadBlock(int rfd, data_block_header_t *block_header, void *read_buff, char **err) {
ssize_t ret, read_bytes, buff_bytes, request_size;
void 	*read_ptr, *buff;

		ret = read(rfd, block_header, sizeof(data_block_header_t));
		if ( ret == 0 )		// EOF
			return NF_EOF;
		
		if ( ret == -1 )	// ERROR
			return NF_ERROR;
		
		// block header read successfully
		read_bytes = ret;

		// Check for sane buffer size
		if ( block_header->size > BUFFSIZE ) {
			snprintf(error_string, ERR_SIZE, "Corrupt data file: Requested buffer size %u exceeds max. buffer size.\n", block_header->size);
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			// this is most likely a corrupt file
			return NF_CORRUPT;
		}

		buff = file_compressed ? lzo_buff : read_buff;

		ret = read(rfd, buff, block_header->size);
		if ( ret == block_header->size ) {
			lzo_uint new_len;
			// we have the whole record and are done for now
			if ( file_compressed ) {
				int r;
    			r = lzo1x_decompress(lzo_buff,block_header->size,read_buff,&new_len,NULL);
    			if (r != LZO_E_OK ) {
        			/* this should NEVER happen */
        			printf("internal error - decompression failed: %d\n", r);
        			return NF_CORRUPT;
    			}
				block_header->size = new_len;
				return read_bytes + new_len;
			} else
				return read_bytes + ret;

		} 
			
		if ( ret == 0 ) {
			// EOF not expected here - this should never happen, file may be corrupt
			snprintf(error_string, ERR_SIZE, "Corrupt data file: Unexpected EOF while reading data block.\n");
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			return NF_CORRUPT;
		}

		if ( ret == -1 )	// ERROR
			return NF_ERROR;

		// Ups! - ret is != block_header->size
		// this was a short read - most likely reading from the stdin pipe
		// loop until we have requested size

		buff_bytes 	 = ret;								// already in buffer
		request_size = block_header->size - buff_bytes;	// still to go for this amount of data

		read_ptr 	 = (void *)((pointer_addr_t)buff + buff_bytes);	
		do {

			ret = read(rfd, read_ptr, request_size);
			if ( ret < 0 ) 
				// -1: Error - not expected
				return NF_ERROR;

			if ( ret == 0 ) {
				//  0: EOF   - not expected
				snprintf(error_string, ERR_SIZE, "Corrupt data file: Unexpected EOF. Short read of data block.\n");
				error_string[ERR_SIZE-1] = 0;
				*err = error_string;
				return NF_CORRUPT;
			} 
			
			buff_bytes 	 += ret;
			request_size = block_header->size - buff_bytes;

			if ( request_size > 0 ) {
				// still a short read - continue in read loop
				read_ptr 	 = (void *)((pointer_addr_t)buff + buff_bytes);
			}
		} while ( request_size > 0 );

		if ( file_compressed ) {
			int r;
			lzo_uint new_len;
    		r = lzo1x_decompress(lzo_buff,block_header->size,read_buff,&new_len,NULL);
    		if (r != LZO_E_OK ) {
        		/* this should NEVER happen */
        		printf("internal error - decompression failed: %d\n", r);
        		return NF_CORRUPT;
    		}
			block_header->size = new_len;
			return read_bytes + new_len;

		} else {
			// finally - we are done for now
			return read_bytes + buff_bytes;
		}
	
		/* not reached */

} // End of ReadBlock

int WriteBlock(nffile_t *nffile) {
data_block_header_t *out_block_header;
int r;
unsigned char __LZO_MMODEL *in;
unsigned char __LZO_MMODEL *out;
lzo_uint in_len;
lzo_uint out_len;

	if ( !TestFlag(nffile->file_header->flags, FLAG_COMPRESSED) ) {
		return write(nffile->wfd, (void *)nffile->block_header, sizeof(data_block_header_t) + nffile->block_header->size);
	} 

	out_block_header = (data_block_header_t *)lzo_buff;
	*out_block_header = *(nffile->block_header);

	in  = (unsigned char __LZO_MMODEL *)((pointer_addr_t)nffile->block_header     + sizeof(data_block_header_t));	
	out = (unsigned char __LZO_MMODEL *)((pointer_addr_t)out_block_header + sizeof(data_block_header_t));	
	in_len = nffile->block_header->size;
	r = lzo1x_1_compress(in,in_len,out,&out_len,wrkmem);

	if (r != LZO_E_OK) {
		snprintf(error_string, ERR_SIZE,"compression failed: %d" , r);
		error_string[ERR_SIZE-1] = 0;
		return -2;
	}

	out_block_header->size = out_len;
	return write(nffile->wfd, (void *)out_block_header, sizeof(data_block_header_t) + out_block_header->size);

} // End of WriteBlock


inline void ExpandRecord_v1(common_record_t *input_record, master_record_t *output_record ) {
uint32_t	*u;
size_t		size;
void		*p = (void *)input_record;

	// Copy common data block
	size = sizeof(common_record_t) - sizeof(uint8_t[4]);
	memcpy((void *)output_record, p, size);
	p = (void *)input_record->data;

	if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		memcpy((void *)output_record->v6.srcaddr, p, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		u = (uint32_t *)p;
		output_record->v6.srcaddr[0] = 0;
		output_record->v6.srcaddr[1] = 0;
		output_record->v4.srcaddr 	 = u[0];

		output_record->v6.dstaddr[0] = 0;
		output_record->v6.dstaddr[1] = 0;
		output_record->v4.dstaddr 	 = u[1];
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// packet counter
	if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// byte counter
	if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

} // End of ExpandRecord_v1

void UnCompressFile(char * filename) {
int 			i, rfd, flags, compressed, anonymized;
ssize_t			ret;
nffile_t		*nffile;
stat_record_t 	*stat_ptr;
char			*string;
char 			outfile[MAXPATHLEN];
void			*buff_ptr;

	rfd = OpenFile(filename, &stat_ptr, &string);
	if ( rfd < 0 ) {
		fprintf(stderr, "%s\n", string);
		return;
	}
	
	// tmp filename for new output file
	snprintf(outfile, MAXPATHLEN, "%s-tmp", filename);
	outfile[MAXPATHLEN-1] = '\0';

	flags = FileHeader.flags;
	if ( file_compressed ) {
		printf("Uncompress file .. \n");
		compressed = 0;
	} else {
		printf("Compress file .. \n");
		compressed = 1;
	}
	anonymized = IsAnonymized();

	// allocate output file
	nffile = OpenNewFile(outfile, NULL, compressed, anonymized, &string);
	if ( !nffile ) {
		fprintf(stderr, "%s\n", string);
		close(rfd);
		return;
	}

	buff_ptr	 = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));

	for ( i=0; i < FileHeader.NumBlocks; i++ ) {
		ret = ReadBlock(rfd, nffile->block_header, buff_ptr, &string);
		if ( ret < 0 ) {
			fprintf(stderr, "Error while reading data block. Abort.\n");
			close(rfd);
			close(nffile->wfd);
			unlink(outfile);
			return;
		}
		if ( WriteBlock(nffile) <= 0 ) {
			fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
			close(rfd);
			close(nffile->wfd);
			unlink(outfile);
			return;
		}
	}

	close(rfd);
	CloseUpdateFile(nffile, stat_ptr, GetIdent(), &string );
	if ( string != NULL ) {
		fprintf(stderr, "%s\n", string);
		close(nffile->wfd);
		unlink(outfile);
	} else {
		close(nffile->wfd);
		unlink(filename);
		rename(outfile, filename);
	}
	DisposeFile(nffile);

} // End of UnCompressFile

void QueryFile(char *filename) {
int i, fd;
stat_record_t *stat_ptr;
data_block_header_t block_header;
char	*string;
uint32_t num_records, type1, type2;
ssize_t	ret;

	fd = OpenFile(filename, &stat_ptr, &string);
	if ( fd < 0 ) {
		fprintf(stderr, "%s\n", string);
		return;
	}

	num_records = 0;
	type1 = 0;
	type2 = 0;
	printf("File    : %s\n", filename);
	printf("Version : %u - %s\n", FileHeader.version, file_compressed ? "compressed" : "not compressed");
	printf("Blocks  : %u\n", FileHeader.NumBlocks);
	for ( i=0; i < FileHeader.NumBlocks; i++ ) {
		ret = read(fd, (void *)&block_header, sizeof(data_block_header_t));
		if ( ret < 0 ) {
			fprintf(stderr, "Error reading block %i: %s\n", i, strerror(errno));
			return;
		}
		num_records += block_header.NumRecords;
		switch ( block_header.id) {
			case DATA_BLOCK_TYPE_1:
				type1++;
				break;
			case DATA_BLOCK_TYPE_2:
				type2++;
				break;
			default:
				printf("block %i has unknown type %u\n", i, block_header.id);
		}

		if ( lseek(fd, block_header.size, SEEK_CUR) < 0 ) {
			fprintf(stderr, "Error seeking block %i: %s\n", i, strerror(errno));
			return;
		}
	}
	printf(" Type 1 : %u\n", type1);
	printf(" Type 2 : %u\n", type2);
	printf("Records : %u\n", num_records);

	close(fd);

} // End of QueryFile

#ifdef COMPAT15
/*
 * v1 -> v2 record conversion:
 * A netflow record in v1 block format has the same size as in v2 block format.
 * Therefore, the conversion rearranges the v1 layout into v2 layout
 *
 * old record size = new record size = 36bytes + x, where x is the sum of
 * IP address block (IPv4 or IPv6) + packet counter + byte counter ( 4/8 bytes) 
 *
 * v1											v2
 * 
 *  0 uint32_t    flags;						uint16_t	type; 	
 *												uint16_t	size;
 *
 *  1 uint16_t    size;							uint8_t		flags;		
 * 												uint8_t 	exporter_ref;
 *    uint16_t    exporter_ref; => 0			uint16_t	ext_map;
 *
 *  2 uint16_t    msec_first;					uint16_t	msec_first;
 *    uint16_t    msec_last;					uint16_t	msec_last;
 *
 *  3 uint32_t    first;						uint32_t	first;
 *  4 uint32_t    last;							uint32_t	last;
 *
 *  5 uint8_t     dir;							uint8_t		fwd_status;
 *    uint8_t     tcp_flags;					uint8_t		tcp_flags;
 *    uint8_t     prot;							uint8_t		prot;
 *    uint8_t     tos;							uint8_t		tos;
 *
 *  6 uint16_t    input;						uint16_t	srcport;
 *    uint16_t    output;						uint16_t	dstport;
 *
 *  7 uint16_t    srcport;						x bytes IP/pkts/bytes
 *    uint16_t    dstport;
 *
 *  8 uint16_t    srcas;
 *    uint16_t    dstas;
 *												uint16_t    input;
 *												uint16_t    output;
 *
 *												uint16_t    srcas;
 *	9 x bytes IP/pkts/byte						uint16_t    dstas;
 *
 *
 */

void Convert_v1_to_v2(void *mem) {
common_record_t    *v2 = (common_record_t *)mem;
common_record_v1_t *v1 = (common_record_v1_t *)mem;
uint32_t *index 	   = (uint32_t *)mem;
uint16_t tmp1, tmp2, srcas, dstas, *tmp3;
size_t cplen;

	// index 0
	tmp1 	 = v1->flags;
	v2->type = CommonRecordType;
	v2->size = v1->size;

	// index 1
	v2->flags 		 = tmp1;
	v2->exporter_ref = 0;
	v2->ext_map 	 = 0;

	// index 2, 3, 4 already in sync

	// index 5
	v2->fwd_status = 0;

	// index 6
	tmp1 = v1->input;
	tmp2 = v1->output;
	v2->srcport = v1->srcport;
	v2->dstport = v1->dstport;

	// save AS numbers
	srcas = v1->srcas;
	dstas = v1->dstas;

	cplen = 0;
	switch (v2->flags) {
		case 0:
			// IPv4 8 byte + 2 x 4 byte counter
			cplen = 16;
			break;
		case 1:
			// IPv6 32 byte + 2 x 4 byte counter
			cplen = 40;
			break;
		case 2:
			// IPv4 8 byte + 1 x 4 + 1 x 8 byte counter
			cplen = 20;
			break;
		case 3:
			// IPv6 32 byte + 1 x 4 + 1 x 8 byte counter
			cplen = 44;
			break;
		case 4:
			// IPv4 8 byte + 1 x 8 + 1 x 4 byte counter
			cplen = 20;
			break;
		case 5:
			// IPv6 32 byte + 1 x 8 + 1 x 4 byte counter
			cplen = 44;
			break;
		case 6:
			// IPv4 8 byte + 2 x 8 byte counter
			cplen = 24;
			break;
		case 7:
			// IPv6 32 byte + 2 x 8 byte counter
			cplen = 48;
			break;
		default:
			// this should never happen - catch it anyway
			cplen = 0;
	}
	// copy IP/pkts/bytes block
	memcpy((void *)&index[7], (void *)&index[9], cplen );

	// hook 16 bit array at the end of copied block
	tmp3 = (uint16_t *)&index[7+(cplen>>2)];
	// 2 byte I/O interfaces 
	tmp3[0] = tmp1;
	tmp3[1] = tmp2;
	// AS numbers
	tmp3[2] = srcas;
	tmp3[3] = dstas;

} // End of Convert_v1_to_v2
#endif

