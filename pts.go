package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

func addmass(str *string, str2 string) {
	*str += str2
	if strings.Contains(*str,"65535 ports/host]"){
		*str = ""
	}
	if str2 == "\r"{
		strl := strings.Split(*str,"\n")
		*str = strings.Join(strl[0:len(strl)-1],"\n")+"\n"
	}
}

func masscanProc(ips string,ports string,rate string,f bool) map[string][]string{
	source := ""
	if f{
		source = fmt.Sprintf("-Pn|-iL|%s|-p|%s|--rate=10000",ips,ports)
	}else {
		source = fmt.Sprintf("-Pn|%s|-p|%s|--rate=10000",ips,ports)
	}
	cmd := exec.Command(`masscan`,strings.Split(source,"|")...)
	fmt.Println("[*] masscan scanning",cmd.Args)
	stdout, err := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err != nil {
		return nil
	}
	if err = cmd.Start(); err != nil {
		fmt.Println(err.Error())
		return nil
	}
	output := ""
	var proc string

	var repro = regexp.MustCompile(`(?m)(\d+\.\d+%).*(found=\d+)`)
	var rescan = regexp.MustCompile(`(?m)open port (\d+)/tcp on (\d+\.\d+\.\d+\.\d+)`)
	result := make(map[string][]string)
	for {
		tmp := make([]byte, 1)
		_, err := stdout.Read(tmp)
		addmass(&output,string(tmp))
		proc += string(tmp)
		if string(tmp) == "\r" {
			psent := repro.FindAllStringSubmatch(proc,-1)
			if len(psent) > 0{
				fmt.Printf("masscan process %s %s\r" , psent[0][1],psent[0][2])
				if psent[0][1] == "100.00%"{
					break
				}
			}
			proc = ""
		}
		if err != nil {
			fmt.Println(err.Error())
			break
		}
	}
	for _, match := range rescan.FindAllStringSubmatch(output,-1) {
		result[match[2]] = append(result[match[2]], match[1])
	}
	return result
}

func nmapProc(ip string,ports []string,w *sync.WaitGroup,reschan chan map[string][]map[string]map[string]string){
	defer w.Done()
	cmd := exec.Command("nmap","-sV","-T4","-Pn",ip,fmt.Sprintf("-p%s",strings.Join(ports,",")),"-oG","-")
	fmt.Printf("[*] nmap scan host:[%s] port:[%s]\n",ip,strings.Join(ports,","))
	output, _ := cmd.Output()
	result := map[string][]map[string]map[string]string{}
	var rescan = regexp.MustCompile(`(?m)(\d+)/(\w+)/(\w+)//(.*?)//(.*?)/`)
	for _, match := range rescan.FindAllStringSubmatch(string(output),-1) {
		temp := map[string]map[string]string{match[1]:{"state":match[2],"service":match[4],"software":match[5]}}
		fmt.Printf("%6s:%6s [%6s] [%6s] [%6s]\n",ip,match[1],match[2],match[4],match[5])
		result[ip] = append(result[ip],temp)
	}
	reschan <- result
}

func splitArray(arr map[string][]string, num int) ([]map[string][]string) {
	max := len(arr)
	var segmens =make([]map[string][]string,0)
	if max < num {
		segmens = append(segmens, arr)
		return segmens
	}
	tmp :=map[string][]string{}
	for k,v := range arr{
		tmp[k] = v
		if (len(tmp) == num){
			segmens = append(segmens, tmp)
			tmp = map[string][]string{}
		}
	}
	if (len(tmp) < num){
		segmens = append(segmens, tmp)
	}
	return segmens
}

func Run(inputfile,outputfile,ports,singleinput string,thread int) {
	massres := make(map[string][]string)
	if len(inputfile) > 0{
		massres = masscanProc(inputfile,ports,"10000",true)
	}else {
		massres = masscanProc(singleinput,ports,"10000",false)
	}
	reschan := make(chan map[string][]map[string]map[string]string)
	res := splitArray(massres,thread)
	var w sync.WaitGroup
	go func() {
		for i := 0;i<len(res) ;i++  {
			for k,v := range res[i]{
				w.Add(1)
				go nmapProc(k,v,&w,reschan)
			}
			w.Wait()
		}
		close(reschan)
	}()
	os.Remove(outputfile)
	f,err := os.OpenFile(outputfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for ipinfo := range reschan{
		res,err := json.Marshal(ipinfo)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		f.Write(res)
	}
	fmt.Printf("结果保存 %s\n",f.Name())
}

