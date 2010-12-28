
bin_PROGRAMS = nfcapd nfdump nfreplay nfexpire 
EXTRA_PROGRAMS = nftest nfgen nfreader

check_PROGRAMMS = test.sh
TESTS = nftest test.sh

if SFLOW
bin_PROGRAMS += sfcapd
endif

if NFPROFILE
bin_PROGRAMS += nfprofile
endif

if FT2NFDUMP
bin_PROGRAMS += ft2nfdump
endif

BUILT_SOURCES = grammar.h
AM_YFLAGS = -d

INCLUDES = $(DEPS_CFLAGS)
LDADD = $(DEPS_LIBS)

#Add extra debug info for gdb
AM_CFLAGS = -ggdb 

common =  nf_common.c nf_common.h panonymizer.c panonymizer.h rijndael.c \
	version.h rijndael.h
util = util.c util.h
filelzo = minilzo.c minilzo.h lzoconf.h lzodefs.h nffile.c nffile.h nfx.c nfx.h
nflist = flist.c flist.h fts_compat.c fts_compat.h
filter = grammar.y scanner.l nftree.c nftree.h ipconv.c ipconv.h rbtree.h
nfprof = nfprof.c nfprof.h
nfnet = nfnet.c nfnet.h
collector = collector.c collector.h
nfv9 = netflow_v9.c netflow_v9.h
nfv5v7 = netflow_v5_v7.c netflow_v5_v7.h
nfstatfile = nfstatfile.c nfstatfile.h
nflowcache = nflowcache.c nflowcache.h
bookkeeper = bookkeeper.c bookkeeper.h
expire= expire.c expire.h
launch = launch.c launch.h

nfdump_SOURCES = nfdump.c nfdump.h nfstat.c nfstat.h nfexport.c nfexport.h \
	$(common) $(nflowcache) $(util) $(filelzo) $(nflist) $(filter) $(nfprof)

nfreplay_SOURCES = nfreplay.c \
	$(common) $(util) $(filelzo) $(nflist) $(filter) $(nfprof) \
	$(nfnet) $(collector) $(nfv9) $(nfv5v7)

nfprofile_SOURCES = nfprofile.c profile.c profile.h \
	$(common) $(util) $(filelzo) $(nflist) $(filter) $(nfstatfile)
nfprofile_LDADD = -lrrd

nfcapd_SOURCES = nfcapd.c \
	$(common) $(util) $(filelzo) $(nflist) $(nfstatfile) $(launch) \
	$(nfnet) $(collector) $(nfv9) $(nfv5v7) $(bookkeeper) $(expire)

if READPCAP
nfcapd_CFLAGS = -DPCAP
nfcapd_SOURCES += pcap_reader.c pcap_reader.h
nfcapd_LDADD = -lpcap
endif

sfcapd_SOURCES = sfcapd.c sflow.c sflow.h sflow_proto.h \
	$(common) $(util) $(filelzo) $(nflist) $(nfstatfile) $(launch) \
	$(nfnet) $(collector) $(bookkeeper) $(expire)

if READPCAP
sfcapd_CFLAGS = -DPCAP
sfcapd_SOURCES += pcap_reader.c pcap_reader.h
sfcapd_LDADD = -lpcap
endif

nfreader_SOURCES = nfreader.c \
	$(util) $(filelzo) $(nflist)

nfgen_SOURCES = nfgen.c $(util) $(filelzo) $(nflist)

nfexpire_SOURCES = nfexpire.c \
	$(bookkeeper) $(expire) $(util) $(nfstatfile)
nfexpire_LDADD = @FTS_OBJ@

nftest_SOURCES = nftest.c $(common) $(filter) $(filelzo)
nftest_DEPENDENCIES = nfgen

if FT2NFDUMP
ft2nfdump_SOURCES = ft2nfdump.c $(common) $(filelzo) $(util)
ft2nfdump_CFLAGS = @FT_INCLUDES@
ft2nfdump_LDADD = -lft -lz
ft2nfdump_LDADD += @FT_LDFLAGS@
endif

EXTRA_DIST = inline.c collector_inline.c nffile_inline.c nfdump_inline.c heapsort_inline.c applybits_inline.c test.sh nfdump.test.out parse_csv.pl
	
CLEANFILES = lex.yy.c grammar.c grammar.h scanner.c scanner.h
