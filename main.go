package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
)
func usage() {
	_,filename,_,_ :=runtime.Caller(0)
	fmt.Fprintf(os.Stderr, fmt.Sprintf(`
Usage: %s [192.168.1.1] [-i 目标文件] [-o 输出文件] [-p 端口] [-t nmap进程数量]
Options:
`,path.Base(filename)))
	flag.PrintDefaults()
}

func main() {
	var resfile string
	flag.StringVar(&resfile,"o","result.json","保存扫描结果的文件位置")
	var thread int
	flag.IntVar(&thread,"t",4,"启动nmap进程数量")
	var ports string
	flag.StringVar(&ports,"p","1-65535","扫描的端口")
	var targetfile string
	flag.StringVar(&targetfile,"i","","扫描目标文件路径")
	flag.Parse()
	flag.Usage=usage
	if (len(targetfile) > 0){
		Run(targetfile,resfile,ports,"",thread)
	}else if len(os.Args) > 1 {
		if len(strings.Split(os.Args[1], ".")) == 4 {
			flag.CommandLine.Parse(os.Args[2:])
			Run("",resfile,ports,os.Args[1],thread)
		}
	}else {
		flag.Usage()
	}
}
