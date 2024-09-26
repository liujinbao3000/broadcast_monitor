package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

const defaultUpdateInterval = 5 * time.Second
const version = "2024-09-26" // 更新日期作为版本信息

func main() {
    interfaceDesc := flag.String("i", "", "指定网络接口的描述（如果有空格，请使用双引号包裹）")
    updateInterval := flag.Int("f", 5, "监控频率（秒）")
    showHelp := flag.Bool("h", false, "显示帮助信息")
    showVersion := flag.Bool("v", false, "显示版本信息")
    showList := flag.Bool("l", false, "显示所有网卡")

    flag.Parse()

    if *showHelp {
        fmt.Println("使用说明：")
        fmt.Println("-i [描述] : 指定网络接口的描述（如果有空格，请使用双引号包裹）")
        fmt.Println("-f [秒]   : 指定监控频率，默认为5秒")
        fmt.Println("-h        : 显示帮助信息")
        fmt.Println("-v        : 显示版本信息")
        fmt.Println("-l        : 显示所有网卡")
        return
    }

    if *showVersion {
        fmt.Printf("版本：%s\n", version)
        return
    }

    if *showList {
        interfaces, err := pcap.FindAllDevs()
        checkError(err)
        fmt.Println("可用的网络接口:")
        for _, iface := range interfaces {
            fmt.Printf("名称: %s, 描述: %s, IPv4: %s\n", iface.Name, iface.Description, getIPv4(iface))
        }
        return
    }

    interfaces, err := pcap.FindAllDevs()
    checkError(err)

    if *interfaceDesc == "" {
        fmt.Println("未指定网络接口描述。可用的网络接口:")
        for i, iface := range interfaces {
            fmt.Printf("%d. 名称: %s, 描述: %s, IPv4: %s\n", i+1, iface.Name, iface.Description, getIPv4(iface))
        }

        var choice int
        fmt.Print("请选择要监控的网络接口 (输入数字): ")
        _, err := fmt.Scan(&choice)
        if err != nil || choice < 1 || choice > len(interfaces) {
            log.Fatal("无效的选择")
        }
        *interfaceDesc = interfaces[choice-1].Description
    }

    var selectedInterface *pcap.Interface
    for _, iface := range interfaces {
        if strings.TrimSpace(iface.Description) == strings.TrimSpace(*interfaceDesc) {
            selectedInterface = &iface
            break
        }
    }

    if selectedInterface == nil {
        log.Fatalf("未找到描述为 '%s' 的网络接口", *interfaceDesc)
    }

    fmt.Printf("选定网络接口: %s - (%s)\n", selectedInterface.Description, getIPv4(*selectedInterface))

    handle, err := pcap.OpenLive(selectedInterface.Name, 1600, true, pcap.BlockForever)
    checkError(err)
    defer handle.Close()

    err = handle.SetBPFFilter("ether broadcast")
    checkError(err)

    broadcastCount := 0
    startTime := time.Now()
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    fmt.Printf("开始监控接口 %s 上的广播包...\n", selectedInterface.Name)
    fmt.Printf("统计信息每 %d 秒更新一次\n", *updateInterval)
    fmt.Println("按 Ctrl+C 可以退出程序")

    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
    stop := make(chan struct{})

    go func() {
        <-signalChan
        fmt.Println("\n正在退出程序...")
        close(stop)
    }()

    for {
        select {
        case packet := <-packetSource.Packets():
            broadcastCount++
            ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
            ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
            if !ok {
                log.Println("以太网层解析失败")
                continue
            }
            srcMAC := ethernetPacket.SrcMAC.String()

            ipLayer := packet.Layer(layers.LayerTypeIPv4)
            var srcIP string
            if ipLayer != nil {
                ip, ok := ipLayer.(*layers.IPv4)
                if ok {
                    srcIP = ip.SrcIP.String()
                } else {
                    srcIP = "未知"
                }
            } else {
                srcIP = "未知"
            }
            fmt.Printf("捕获到广播包 - 源MAC: %s, 源IP: %s\n", srcMAC, srcIP)

            if time.Since(startTime) >= time.Duration(*updateInterval)*time.Second {
                fmt.Printf("过去 %d 秒内捕获到 %d 个广播包\n", *updateInterval, broadcastCount)
                broadcastCount = 0
                startTime = time.Now()
            }
        case <-stop:
            return
        }
    }
}

func getIPv4(iface pcap.Interface) string {
    for _, addr := range iface.Addresses {
        if ipv4 := addr.IP.To4(); ipv4 != nil {
            return ipv4.String()
        }
    }
    return "无IPv4地址"
}

func checkError(err error) {
    if err != nil {
        log.Fatal(err)
    }
}
