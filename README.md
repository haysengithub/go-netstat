### Usage:

```
Usage of ./go-netstat:
  -4    display only IPv4 sockets
  -6    display only IPv6 sockets
  -all
    	display both listening and non-listening sockets
  -help
    	display this help screen
  -lis
    	display only listening sockets
  -res
        lookup symbolic names for host addresses
  -tcp
    	display TCP sockets
  -udp
    	display UDP sockets
  -vt  
        Check ip and file md5 with virustotal  
  -vtkey string  
        Input the virustotal apikey (default "---")  
```
### Installation:

```
$ go get github.com/haysengithub/go-netstat  
```

go run main.go -vt -vtkey 1234556sfsfsds……  
