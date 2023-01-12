# massJARM
 
A threaded implemenation of [JARM](https://github.com/salesforce/jarm) tool.

# massJARM

To run a scan, provide a list of targets together with port in one file. The following examples are all supported:

* `massJARM.py -i <targetfile> -t <number of threads, default 4>`

The format of the input file should include IP/Domain and Port, separated by colon ":", one per line.

# JARM Process

The basic process involves:

* Create a list of probes for a given host and port using different TLS versions. 
* Open a connection to the host and port and send the probe. 
* Receive the response (up to 1484 bytes). Receiving more or less can change the hash.
* Parse the Server Hello from the received data.
* Calculate the JARM hash.
* Print out JARM in a CSV format

# Usage
```
usage: threat-queue.py [-h] [-i INPUT | -t THREADS]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Provide a list of IP addresses or domains to scan, one domain or IP address per line together with a port (e.g. 8.8.4.4:853).
  -t THREADS, --threads THREADS
                        Number of threads to use (default is 4)
```

# Performance Comparison

| Test | Number of threads | Time Taken | Test Command | 
| ------------- | ------------- | ------------- | ------------- |
| Original [JARM](https://github.com/salesforce/jarm) | 1 | 1049s | start_time=`date +%s` && python3 jarm.py -i alexa500withPort.txt  && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s | 
| massJARM (default 4 threads)| 4 | 253s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s| 
| massJARM | 10 | 103s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 10 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s |  
| massJARM | 20 | 99s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 20 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s | 

# 11M JARM

The folder [11MJARM](11MJARM/) contains 443/TCP JARM scan of most popular domains based on the datasets available at these links (as of 01/01/2023). Total of 11272827 domains were scanned using ```massJARM``` tool.

* [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html)
* [Majestic Top 1m most popular domains](https://majestic.com/reports/majestic-million)
* [DomCorp 10m most popular domains](https://www.domcop.com/top-10-million-domains)

The results are sorted into the following files:

* ```11m_domains_with_443_port.tar.bz2``` - Source file with all unique domains and port 443 added. 
* ```11m_domains_with_JARM_tcp_443_port_empty_removed.tar.bz2``` - Result file with all JARM responses that were not negative (i.e., ```00000000000000000000000000000000000000000000000000000000000000```).
* ```11m_domains_with_JARM_tcp_443_port_raw.tar.bz2``` - Raw result files with all, even empty, JARM responses.
* ```unique_jarm_fingerprints.txt``` - Collection of unique JARM fingerprints based on scan against ```11m_domains_with_443_port.tar.bz2``` source file.