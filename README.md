# pcap_microburst

![Alt text](http://fmad.io/analytics/logo_microburst.png "fmadio latency analyzer logo")

pcap_microbust is a simple **packet analyzer** tool used to extract microbust information from PCAP 


**Algo**

Command line options 

```

Options:
  --stdin                 | read file from stdin
  --status                | print processing status updates
  --burst-thresh <Gbps>   | threshold for burst starting in Gbps (default 1.0 Gbps)

```

### Examples


```
$ pcap_microburst  defcon22_hitcon.pcap
04:13:50.285.816.000 : Burst [Peek     10.000Gbps Mean:      9.938Gbps] Duration:   487.790000 ms PacketCnt:          271 Bytes:     227KB
05:12:21.843.350.000 : Burst [Peek     10.000Gbps Mean:     10.000Gbps] Duration:  5006.871000 ms PacketCnt:          704 Bytes:     135KB
08:05:08.951.163.000 : Burst [Peek     10.000Gbps Mean:     10.000Gbps] Duration:   201.977000 ms PacketCnt:          239 Bytes:     225KB

```

### Support 

This tool is part of the fmadio **10G sniffer appliance**, more information can be found at http://fmad.io 

Contact us for any bugs/patches/requests send a mail to: support at fmad.io 
