package main

import (
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

const updateInterval = 5 * time.Second

func main() {
    // 获取所有网络接口
    interfaces, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }

    // 打印可用的网络接口
    fmt.Println("可用的网络接口:")
    for i, iface := range interfaces {
        ipv4 := getIPv4(iface)
        fmt.Printf("%d. %s - %s\n", i+1, iface.Description, ipv4)
    }

    // 让用户选择网络接口
    var choice int
    fmt.Print("请选择要监控的网络接口 (输入数字): ")
    _, err = fmt.Scan(&choice)
    if err != nil || choice < 1 || choice > len(interfaces) {
        log.Fatal("无效的选择")
    }

    interfaceName := interfaces[choice-1].Name

    // 打开网络接口
    handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // 设置过滤器,只捕获广播包
    err = handle.SetBPFFilter("ether broadcast")
    if err != nil {
        log.Fatal(err)
    }

    // 初始化计数器和时间
    broadcastCount := 0
    startTime := time.Now()

    // 创建数据包源
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    fmt.Printf("开始监控接口 %s 上的广播包...\n", interfaceName)
    fmt.Printf("统计信息每 %d 秒更新一次\n", int(updateInterval.Seconds()))
    fmt.Println("按 Ctrl+C 可以退出程序")

    // 设置信号处理
    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

    // 创建一个通道用于停止抓包
    stop := make(chan struct{})

    go func() {
        <-signalChan
        fmt.Println("\n正在退出程序...")
        close(stop)
    }()

    // 循环读取数据包
    for {
        select {
        case packet := <-packetSource.Packets():
            broadcastCount++
            
            // 解析以太网层
            ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
            if ethernetLayer != nil {
                ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
                srcMAC := ethernetPacket.SrcMAC

                // 解析IP层
                ipLayer := packet.Layer(layers.LayerTypeIPv4)
                if ipLayer != nil {
                    ip, _ := ipLayer.(*layers.IPv4)
                    srcIP := ip.SrcIP
                    fmt.Printf("捕获到广播包 - 源MAC: %s, 源IP: %s\n", srcMAC, srcIP)
                } else {
                    fmt.Printf("捕获到广播包 - 源MAC: %s, 源IP: 未知\n", srcMAC)
                }
            }
            
            // 每updateInterval打印一次统计信息
            if time.Since(startTime) >= updateInterval {
                fmt.Printf("过去 %d 秒内捕获到 %d 个广播包\n", int(updateInterval.Seconds()), broadcastCount)
                broadcastCount = 0
                startTime = time.Now()
            }
        case <-stop:
            return
        }
    }
}

// 获取接口的IPv4地址
func getIPv4(iface pcap.Interface) string {
    for _, addr := range iface.Addresses {
        if ipv4 := addr.IP.To4(); ipv4 != nil {
            return ipv4.String()
        }
    }
    return "无IPv4地址"
}
