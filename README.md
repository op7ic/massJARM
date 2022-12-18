# massJARM
 
A threaded implemenation of [JARM](https://github.com/salesforce/jarm) tool to allow mass scaning.

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

| Test | Number of threads | Time Taken | Command | 
| ------------- | ------------- | ------------- |
| Original [JARM](https://github.com/salesforce/jarm) | 1 | 1049s | start_time=`date +%s` && python3 jarm.py -i alexa500withPort.txt  && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s | 
| MassJARM (default 4 threads)| 4 | 253s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s| 
| MassJARM | 10 | 103s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 10 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s |  
| MassJARM | 20 | 99s | start_time=`date +%s` && python3 massJARM.py -i alexa500withPort.txt -t 20 && end_time=`date +%s` && echo execution time was `expr $end_time - $start_time` s | 
