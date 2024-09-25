package main

import (
    "bytes"
    "fmt"
    "os"
    "os/signal"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "net"
    "syscall"
)

func main() {
    // 获取所有网卡
    devices, err := pcap.FindAllDevs()
    if err != nil {
        fmt.Printf("Error finding devices: %v\n", err)
        return
    }

    // 列出所有网卡供用户选择
    fmt.Println("可用的网络接口：")
    for i, device := range devices {
        fmt.Printf("[%d] %s (%s)\n", i, device.Name, device.Description)
    }

    // 选择网卡
    var choice int
    fmt.Print("请选择要监控的网卡编号：")
    _, err = fmt.Scan(&choice)
    if err != nil || choice < 0 || choice >= len(devices) {
        fmt.Println("无效的选择")
        return
    }
    device := devices[choice].Name
    fmt.Printf("监控网卡: %s\n", device)

    // 打开网卡进行监听
    handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
    if err != nil {
        fmt.Printf("Error opening device %s: %v\n", device, err)
        return
    }
    defer handle.Close()

    // 设置信号监听，捕捉Ctrl+C来安全退出
    sigChan := make(chan os.Signal, 1)
    done := make(chan bool)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := packetSource.Packets()

    // 启动广播包统计
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()

        broadcastPackets := 0
        for {
            select {
            case packet := <-packets:
                if packet == nil {
                    return // 安全退出goroutine
                }
                // 判断是否是广播包
                ethLayer := packet.Layer(layers.LayerTypeEthernet)
                if ethLayer != nil {
                    eth, _ := ethLayer.(*layers.Ethernet)
                    if eth != nil && bytes.Equal(eth.DstMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
                        broadcastPackets++
                    }
                }
            case <-ticker.C:
                fmt.Printf("每秒广播包数量: %d\n", broadcastPackets)
                broadcastPackets = 0
            case <-done:
                return // 退出 goroutine
            }
        }
    }()

    // 等待信号中断
    <-sigChan
    fmt.Println("程序正在退出...")
    close(done) // 通知 goroutine 停止
    time.Sleep(1 * time.Second) // 确保 goroutine 有足够时间退出
    fmt.Println("程序已退出")
}
