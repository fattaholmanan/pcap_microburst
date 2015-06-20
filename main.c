//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
//
// pcap microburst analysis 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>

#include "fTypes.h"

double TSC2Nano = 0;

//---------------------------------------------------------------------------------------------

typedef struct
{
	char* Path;				// path to the file
	char	Name[128];		// short name
	FILE*	F;				// bufferd io file handle
	int		fd;				// file handler of the mmap attached data
	u64		Length;			// exact file length
	u64		MapLength;		// 4KB aligned mmap length
	u8*		Map;			// raw mmap ptr

	u64		TimeScale;		// 1000ns for usec pcap, 1ns for nano pcap
	u64		ReadPos;		// current read pointer
	u64		PktCnt;			// number of packets processed

	u8*		PacketBuffer;	// temp read buffer
	bool	Finished;		// read completed

	u64		TS;				// last TS processed

} PCAPFile_t;

typedef struct
{
	u64		TS;				// timestamp of the packet		
	u16		Length;			// length of this packet
	u64		PktNo;			// packet number

} PacketSummary_t;

//---------------------------------------------------------------------------------------------
// tunables

static u64		s_TimeZoneOffset	= 0;			// local machines timezone offset
static u64		s_TimeBinNS			= 100e3;		// microburst time slot
static double	s_BurstThreshold	= 1e9;
static double	s_BurstDuration		= 0;			// length in time of burst rate

static bool		s_PCAPStdin			= false;		// read pcap from stdin
static bool		s_EnableStatus		= false;		// print regular status interval updates

//---------------------------------------------------------------------------------------------
// mmaps a pcap file in full
static PCAPFile_t* OpenPCAP(char* Path)
{
	PCAPFile_t* F = (PCAPFile_t*)malloc( sizeof(PCAPFile_t) );
	memset(F, 0, sizeof(PCAPFile_t));

	if (!s_PCAPStdin)
	{
		struct stat fstat;	
		if (stat(Path, &fstat) < 0)
		{
			fprintf(stderr, "failed to get file size [%s]\n", Path);
			return NULL;
		}
		F->Path		= Path;
		F->Length 	= fstat.st_size;

		F->F = fopen(Path, "r");
		if (F->F == NULL)
		{
			fprintf(stderr, "failed to open buffered file [%s]\n", Path);
			return NULL;
		}
	}
	else
	{
		F->F 		= stdin;
		F->Length 	= 1e16; 

		F->Path		= "stdin";
	}

	// note always map as read-only 
	PCAPHeader_t Header1;
	PCAPHeader_t* Header = NULL; 

	int ret = fread(&Header1, 1, sizeof(Header1), F->F);
	if (ret != sizeof(PCAPHeader_t))
	{
		fprintf(stderr, "failed to read header\n");
		return NULL;
	}

	Header = &Header1;
	F->PacketBuffer	= malloc(32*1024);

	switch (Header->Magic)
	{
	case PCAPHEADER_MAGIC_USEC: F->TimeScale = 1000; break;
	case PCAPHEADER_MAGIC_NANO: F->TimeScale = 1; break;
	default:
		fprintf(stderr, "invalid pcap header %08x\n", Header->Magic);
		return NULL;
	}
	F->ReadPos =  sizeof(PCAPHeader_t);

	return F;
}

//---------------------------------------------------------------------------------------------
// get the next packet
static PCAPPacket_t* ReadPCAP(PCAPFile_t* PCAP)
{
	int ret;
	PCAPPacket_t* Pkt = (PCAPPacket_t*)PCAP->PacketBuffer;
	ret = fread(Pkt, 1, sizeof(PCAPPacket_t), PCAP->F);
	if (ret != sizeof(PCAPPacket_t)) return NULL;

	if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length) return NULL; 

	ret = fread(Pkt+1, 1, Pkt->LengthCapture, PCAP->F);
	if (ret != Pkt->LengthCapture) return NULL;
	return Pkt;
}

//---------------------------------------------------------------------------------------------
// helpers for network formating 
static u64 PCAPTimeStamp(PCAPFile_t* F, PCAPPacket_t* Pkt)
{
	return s_TimeZoneOffset + Pkt->Sec * k1E9 + Pkt->NSec * F->TimeScale;
}
static fEther_t * PCAPETHHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	
	return E;
}

static IP4Header_t* PCAPIP4Header(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	return IP4;
}

static TCPHeader_t* PCAPTCPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);
	u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;

	return TCP;
}

static UDPHeader_t* PCAPUDPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	UDPHeader_t* UDP = (UDPHeader_t*)( ((u8*)IP4) + IPOffset);

	return UDP;
}

//---------------------------------------------------------------------------------------------

static void print_usage(void)
{
	printf("pcap_microburst: <pcap A>\n");
	printf("\n");
	printf("runs microburst analysis on the specified PCAP file\n"); 
	printf("\n");
	printf("Version: %s %s\n", __DATE__, __TIME__);
	printf("Contact: support at fmad.io\n"); 
	printf("\n");
	printf("Options:\n");
	printf("  --stdin                 | read file from stdin\n");
	printf("  --status                | print processing status updates\n");
	printf("  --burst-thresh <Gbps>   | threshold for burst starting in Gbps (default 1.0 Gbps)\n");
	printf("\n");
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* FileName = NULL;
	for (int i=1; i < argc; i++)
	{
		if (argv[i][0] != '-')
		{
			FileName = argv[i];
		}
		else
		{
			if (strcmp(argv[i], "--stdin") == 0)
			{
				fprintf(stderr, "reading pcap from stdin\n");
				s_PCAPStdin = true;	
			}
			else if (strcmp(argv[i], "--status") == 0)
			{
				fprintf(stderr, "output status information\n");
				s_EnableStatus = true;	
			}
			else if (strcmp(argv[i], "--burst-thresh") == 0)
			{
				double Threshold = atof(argv[i+1]);
				fprintf(stderr, "Set burst minimum threshold %f Gbps\n", Threshold);
				s_BurstThreshold = Threshold * 1e9;
				i++;
			}
			else if (strcmp(argv[i], "--timebin") == 0)
			{
				double TimeBin = atof(argv[i+1]);
				fprintf(stderr, "Bandwidth time bin to be %f ns\n", TimeBin);
				s_TimeBinNS = TimeBin;
				i++;
			}
			else
			{
				fprintf(stderr, "unknown option [%s]\n", argv[i]);
				return 0;
			}
		}
	}

	// need a file 
	if ((FileName == NULL) && (!s_PCAPStdin))
	{
		print_usage();
		return 0;
	}

	// get timezone offset

  	time_t t = time(NULL);
	struct tm lt = {0};

	localtime_r(&t, &lt);
	s_TimeZoneOffset = lt.tm_gmtoff * 1e9;
	
	// open pcap diff files

	PCAPFile_t* PCAPFile = OpenPCAP(FileName);
	if (!PCAPFile) return 0;


	// allocate ring for analysis 
	u64 PacketRingPut = 0;
	u64 PacketRingGet = 0;
	u64 PacketRingMax = 128*1024*1024;
	PacketSummary_t* PacketRing = (PacketSummary_t*)malloc( PacketRingMax * sizeof(PacketSummary_t) );
	memset(PacketRing, 0, PacketRingMax * sizeof(PacketSummary_t) );

	u64 WindowPktCnt 	= 0;
	u64 WindowByteCnt 	= 0;

	bool WindowInBurst 		= false;			// currnelty in a burst
	u64 WindowBurstStartTS 	= 0;				// time when the current burst started
	u64 WindowBurstBpsMax	= 0;				// max bps when bursting

	u64 WindowBurstBpsSum0	= 0;				// stats on how hard and long the burst was
	u64 WindowBurstBpsSum1	= 0;				// stats on how hard and long the burst was
	u64 WindowBurstBpsSum2	= 0;				// stats on how hard and long the burst was

	u64 WindowBurstBytes	= 0;				// number of bytes the burst ran for

	// get starting time 
	u64 PktCnt = 0;
	while (!feof(PCAPFile->F))
	{
		PCAPPacket_t* Pkt = ReadPCAP(PCAPFile); 
		if (!Pkt) break;

		u64 TS = PCAPTimeStamp(PCAPFile, Pkt);

		PacketSummary_t* PP = &PacketRing [ PacketRingPut ];

		PP->TS 		= TS;
		PP->Length 	= Pkt->LengthCapture;
		PP->PktNo	= PktCnt;

		// increate window stats

		WindowPktCnt++;
		WindowByteCnt += PP->Length;

		PacketRingPut = (PacketRingPut + 1) % PacketRingMax;

		// update tail ptr 
		while (true)
		{
			PacketSummary_t* PG = &PacketRing [ PacketRingGet ];

			s64 dTS = TS - PG->TS; 
			if (dTS < s_TimeBinNS)
			{
				// window not changed
				break;
			}

			// remove tail item from stats

			WindowPktCnt--;	
			WindowByteCnt -= PG->Length;

			// remove tail item

			PacketRingGet = (PacketRingGet + 1) % PacketRingMax; 
			if (PacketRingGet  == PacketRingPut)
			{
				break;
			}
		}

		// get new last packet in the window

		PacketSummary_t* PG = &PacketRing [ PacketRingGet ];

		// calcuate burst rate
		double dT = (PP->TS - PG->TS);

		// need to include time to receive the head packet 
		dT += PP->Length * (1e9 / 10e9) * 8.0; 

		double Bps = (8.0 * WindowByteCnt) * inverse(dT/ 1e9);	

		if (!WindowInBurst)
		{
			if (Bps > s_BurstThreshold)
			{
				WindowInBurst 		= true;
				WindowBurstStartTS 	= PP->TS;
				WindowBurstBpsMax	= Bps;

				WindowBurstBpsSum0	= 1;
				WindowBurstBpsSum1	= Bps;
				WindowBurstBpsSum2	= Bps*Bps;

				WindowBurstBytes	= PP->Length;	

				//printf("%s : BurstStart %.3f\n", FormatTS(PP->TS), Bps/1e9);
			}
		}
		else
		{
			if (Bps < s_BurstThreshold)
			{
				WindowInBurst = false;
				double dT = PP->TS - WindowBurstStartTS;

				if (
					(dT > s_BurstDuration) &&
					(WindowBurstBytes > 128*1024)
				){
					double BpsMean = WindowBurstBpsSum1	 / WindowBurstBpsSum0;
					s64 dByte = WindowBurstBytes; 

					printf("%s : Burst [Peek %10.3fGbps Mean: %10.3fGbps] Duration: %12.6f ms PacketCnt: %12lli Bytes:%8lliKB\n", 
							FormatTS(WindowBurstStartTS), 
							WindowBurstBpsMax/1e9, 
							BpsMean/1e9, 
							dT / 1e6,
							WindowBurstBpsSum0,
							WindowBurstBytes / 1024
						);
				}
			}
			else
			{
				WindowBurstBpsMax	= (WindowBurstBpsMax < Bps) ? Bps : WindowBurstBpsMax;

				WindowBurstBpsSum0	+= 1;
				WindowBurstBpsSum1	+= Bps;
				WindowBurstBpsSum2	+= Bps*Bps;

				WindowBurstBytes	+= PP->Length;	
			}
		}
		PktCnt++;
		
		if (PktCnt % (u64)100e6 == 0)
		{
			if (s_EnableStatus)
			{
				s64 PktCnt = PacketRingPut - PacketRingGet;
				fprintf(stderr, "%s : Stats %30s\n", FormatTS(TS), PCAPFile->Path);
			}
		}
	}
}

/* vim: set ts=4 sts=4 */
