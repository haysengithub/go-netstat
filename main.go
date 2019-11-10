package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"io"
	"strings"
	"crypto/md5"
	"encoding/hex"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/williballenthin/govt"
)

var (
	udp       = flag.Bool("udp", false, "display UDP sockets")
	tcp       = flag.Bool("tcp", false, "display TCP sockets")
	listening = flag.Bool("lis", false, "display only listening sockets")
	all       = flag.Bool("all", false, "display both listening and non-listening sockets")
	resolve   = flag.Bool("res", false, "lookup symbolic names for host addresses")
	ipv4      = flag.Bool("4", false, "display only IPv4 sockets")
	ipv6      = flag.Bool("6", false, "display only IPv6 sockets")
	vt        =flag.Bool("vt", false, "Check ip and file md5 with virustotal")
	vtkey     = flag.String("vtkey","---","Input the virustotal apikey")
	help      = flag.Bool("help", false, "display this help screen")
)

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

type ip_table struct {
	IP   string
	ipReport *govt.IpReport
	detectedUrl *govt.DetectedUrl
	resolution *govt.IpResolution

}

type file_table struct{
	file string
	fileReport *govt.FileReport
	Md5       string 
	Sha1      string
	Sha256    string
	ScanDate  string
	Positives uint16
	Total     uint16
	AvName string
	FileScan *govt.FileScan 
	Permalink string
}

var ip_map map[string]*ip_table
var file_map map[string]*file_table
var govt_client *govt.Client

func init(){
	apikey:=*vtkey
	apiurl:="https://www.virustotal.com/vtapi/v2/"
	var err error
	govt_client, err = govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))

	check(err)

	ip_map = make(map[string]*ip_table)
	file_map = make(map[string]*file_table)
}

func md5V(str string) string  {
    file, inerr := os.Open(str)                                            
        if inerr == nil {                                                           
                md5h := md5.New()                                                   
                io.Copy(md5h, file)                                                 
				//fmt.Printf("%x", md5h.Sum([]byte(""))) //md5  
				return hex.EncodeToString(md5h.Sum(nil))                      
		}            
	defer file.Close()
	return ""
    
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func check_ip(ip string)*ip_table{
	
	if _, ok := ip_map[ip]; ok {
		return ip_map[ip]
	}else{

		r, err := govt_client.GetIpReport(ip)
		check(err)
		var temp_detectedUrl *govt.DetectedUrl
		var temp_resolution *govt.IpResolution
		if len(r.DetectedUrls) >0{
			var bad uint16
			bad =r.DetectedUrls[0].Positives
			temp_detectedUrl = &r.DetectedUrls[0]
			for i,v :=range(r.DetectedUrls){
				if v.Positives != 0{
					
					if v.Positives > bad{
						bad = v.Positives
						temp_detectedUrl = &r.DetectedUrls[i]
					}
				}
			}
		}
		if len(r.Resolutions) > 0{
			temp_resolution = &r.Resolutions[0]
		}
		ip_map[ip]=&ip_table{IP:ip,ipReport:r,detectedUrl:temp_detectedUrl,resolution:temp_resolution}
	}
	return ip_map[ip]
}


func check_file(file string)*file_table{

	var tem_file_table *file_table

	is_exits,_:=PathExists(file)

	if is_exits == true{
		md5:=md5V(file)//"c6b7544e4620fbe15316a49e937e7fd5 "//md5V(file)
		if _, ok := file_map[md5]; ok {
			return file_map[md5]
		}else{
			r, err := govt_client.GetFileReport(md5)
			check(err)
			scans := r.Scans
			if len(scans) >0{
				var fileScan govt.FileScan
				var AvName string
				if _,ok :=scans["Microsoft"]; ok{
					fileScan = scans["Microsoft"]
					AvName = "Microsoft"
				}else if  _,ok :=scans["Kaspersky"]; ok{
					fileScan = scans["Kaspersky"]
					AvName = "Kaspersky"
				}else if _,ok :=scans["ESET-NOD32"]; ok{
					fileScan = scans["ESET-NOD32"]
					AvName = "ESET-NOD32"
				}else if  _,ok :=scans["FireEye"]; ok{
					fileScan = scans["FireEye"]
					AvName = "FireEye"
				}
				file_map[md5]=&file_table{file:file,fileReport:r,
					Md5:r.Md5, 
					Sha1:r.Sha1,
					Sha256:r.Sha256,
					ScanDate:r.ScanDate,
					Positives:r.Positives,
					Total:r.Total,
					AvName:AvName,
					FileScan:&fileScan,
					Permalink:r.Permalink,
				}
				return file_map[md5]
			}
			
		}
	}
	
	return tem_file_table
}



func main() {
	//getvt("192.3.247.119")
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	var proto uint
	if *ipv4 {
		proto |= protoIPv4
	}
	if *ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	if os.Geteuid() != 0 {
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}
	fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

	if *udp {
		if proto&protoIPv4 == protoIPv4 {
			tabs, err := netstat.UDPSocks(netstat.NoopFilter)
			if err == nil {
				displaySockInfo("udp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := netstat.UDP6Socks(netstat.NoopFilter)
			if err == nil {
				displaySockInfo("udp6", tabs)
			}
		}
	} else {
		*tcp = true
	}

	if *tcp {
		var fn netstat.AcceptFn

		switch {
		case *all:
			fn = func(*netstat.SockTabEntry) bool { return true }
		case *listening:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen
			}
		default:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}

		if proto&protoIPv4 == protoIPv4 {
			tabs, err := netstat.TCPSocks(fn)
			if err == nil {
				displaySockInfo("tcp", tabs)
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := netstat.TCP6Socks(fn)
			if err == nil {
				displaySockInfo("tcp6", tabs)
			}
		}
	}
}

func displaySockInfo(proto string, s []netstat.SockTabEntry) {
	lookup := func(skaddr *netstat.SockAddr) (string,uint16) {
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		if *resolve {
			names, err := net.LookupAddr(addr)
			if err == nil && len(names) > 0 {
				addr = names[0]
			}
		}
		if len(addr) > IPv4Strlen {
			addr = addr[:IPv4Strlen]
		}
		//return fmt.Sprintf("%s:%d", addr, skaddr.Port)
		return addr,skaddr.Port
	}

	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		saddr,sport := lookup(e.LocalAddr)
		daddr,dport := lookup(e.RemoteAddr)
		s_ip_port := fmt.Sprintf("%s:%d", saddr,sport)
		d_ip_port := fmt.Sprintf("%s:%d",daddr,dport)
		fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, s_ip_port,d_ip_port, e.State, p)

		if *vt ==false{
			continue
		}
		ip_table := check_ip(daddr)
		if ip_table != nil{
			fmt.Println("--",ip_table.IP,ip_table.resolution,ip_table.detectedUrl)
		}


		pid_file :=strings.Split(p, "/")
		if len(pid_file) ==2{
			file_table:= check_file(pid_file[1])
			if file_table!= nil{
				fmt.Println("--",file_table.file,file_table.Md5,file_table.Positives,file_table.Total,file_table.AvName,file_table.FileScan)
			}
		}
		fmt.Println("")

	}
}

func check(e error) {
	//if e != nil {panic(e)}
	if e!=nil{
		fmt.Println(e)
	}
}

/*func getvt(ip string) {
	return
	apikey:="6b07e5931a26480af7a1d13a341775a4839f8d6140177c81015b48c5bbf77748"
	apiurl:="https://www.virustotal.com/vtapi/v2/"
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))

	check(err)

	r, err := c.GetIpReport(ip)

	check(err)

	//j, err := json.MarshalIndent(r, "", "    ")

	//check(err)

	//fmt.Printf("IP Report: ")

	//os.Stdout.Write(j)

	fmt.Println(r.Resolutions)
	fmt.Println(r.DetectedUrls)

}*/

