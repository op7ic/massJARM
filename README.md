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
| Original [JARM](https://github.com/salesforce/jarm) | 1 | 1049s |```start_time=`date +%s` && python3 jarm.py -i alexa500withPort.txt  && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s``` | 
| massJARM (default 4 threads)| 4 | 253s |```start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s```| 
| massJARM | 10 | 103s |```start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 10 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s ```|  
| massJARM | 20 | 99s |```start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 20 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s ```| 

# Checking scanning results

A simple grep can be used to find all C2 that match some of the known [signatures](https://github.com/cedowens/C2-JARM):

```
cat result.xt | grep "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1\|07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823\|07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d\|2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb\|21d14d00000000021c21d14d21d21d1ee8ae98bf3ef941e91529a93ac62b8b\|29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38\|00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64\|2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261\|20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6\|2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883\|2ad000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46\|22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9"
```

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
