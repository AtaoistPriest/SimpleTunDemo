package net

import "C"
import (
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

//#include <stdio.h>
//#include <string.h>
//#include <unistd.h>
//#include <sys/ioctl.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <net/if.h>
//#include <net/route.h>
//int getMTU(const unsigned char * nic)
//{
//	int fd = socket(AF_INET, SOCK_DGRAM, 0);
//	struct ifreq ifr;
//	strncpy(ifr.ifr_name, nic, IFNAMSIZ - 1);
//	if (ioctl(fd, SIOCGIFMTU, &ifr)){
//	perror("ioctl");
//	return -1;
//	}
//	close(fd);
//	return ifr.ifr_mtu;
//}
//int setIfaceAddress(unsigned char *ifname, unsigned char *Ipaddr, unsigned char *mask)
//{
//  int fd, res = 0;
//  struct ifreq ifr;
//  struct sockaddr_in *sin;
//  struct rtentry  rt;
//  fd = socket(AF_INET, SOCK_DGRAM, 0);
//  memset(&ifr,0,sizeof(ifr));
//  strcpy(ifr.ifr_name,ifname);
//  //set nic up
//  ioctl(fd, SIOCGIFFLAGS, &ifr);
//  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
//  ioctl(fd, SIOCSIFFLAGS, &ifr);
//  sin = (struct sockaddr_in*)&ifr.ifr_addr;
//  sin->sin_family = AF_INET;
//  //ipaddr
//  inet_aton(Ipaddr,&(sin->sin_addr));
//  res = ioctl(fd,SIOCSIFADDR,&ifr);
//  if (res < 0) return -1;
//  //netmask
//  inet_aton(mask,&(sin->sin_addr));
//  res = ioctl(fd, SIOCSIFNETMASK, &ifr);
//  if (res < 0) return -2;
//  close(fd);
//	return res;
//}
import "C"
func GetMTU(ifaceStr string) int{
	ifaceName := []byte(ifaceStr)
	mtu := C.getMTU((*C.uchar)(&ifaceName[0]))
	return int(mtu)
}

func SetNicAddress(ifName string, address string, netmask string) int{
	res := C.setIfaceAddress((*C.uchar)(&[]byte(ifName)[0]), (*C.uchar)(&[]byte(address)[0]), (*C.uchar)(&[]byte(netmask)[0]))
	return int(res)
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *AfpacketHandle) SetBPFFilter(filter string, frame_size int) (err error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, frame_size, filter)
	if err != nil {
		return err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	if h.TPacket.SetBPF(bpfIns); err != nil {
		return err
	}
	return h.TPacket.SetBPF(bpfIns)
}


func CheckSum(data []byte) uint16 {
	cSum := uint32(0)
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		cSum += uint32(data[i]) << 8
		cSum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		cSum += uint32(data[length]) << 8
	}
	for cSum > 0xffff {
		cSum = (cSum >> 16) + (cSum & 0xffff)
	}
	return ^uint16(cSum)
}
/*
	主要用于计算IP和UDP的头部校验和，提供的Pkt参数需要确保数据的可靠性
*/
func CalPktCheckSum(pkt []byte){
	/* cal ip checksum */
	cs := CheckSum(pkt[14:34])
	pkt[24] = byte(cs >> 8)
	pkt[25] = byte(cs & 0xff)
	/* cal udp checksum */
	// pack the pseudo pkt
	pseHeadPkt := make([]byte, len(pkt) - 14 - 20 + 12)
	copy(pseHeadPkt[:4], pkt[26:30])
	copy(pseHeadPkt[4:8], pkt[30:34])
	pseHeadPkt[8] = 0
	pseHeadPkt[9] = 17
	pseHeadPkt[10] = 0
	pseHeadPkt[11] = 18
	// cal udp checksum
	copy(pseHeadPkt[12:], pkt[34:])
	ucs := CheckSum(pseHeadPkt)
	pkt[40] = byte(ucs >> 8)
	pkt[41] = byte(ucs & 0xff)
}
