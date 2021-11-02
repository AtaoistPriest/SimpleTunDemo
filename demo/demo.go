package main

import (
	"log"
	"SimpleTunDemo/tun"
	"time"
)

const OFFSET = 4

func main()  {
	buff := make([]byte, 1500)
	tunFd, err := tun.NewTun("tun0", "192.168.1.1", "255.255.255.0", 1420)
	if err != nil{
		log.Print("ERROR : ", err)
		return
	}
	log.Print("TUN { \n name : tun0 \n IP   : 192.168.1.1/24}")
	for true {
		length, _ := tunFd.Read(buff, OFFSET)
		log.Print(buff[OFFSET: length + OFFSET])
		time.Sleep(1 * time.Second)
	}
}

