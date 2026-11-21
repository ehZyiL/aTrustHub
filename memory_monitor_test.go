package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	hubproxy "github.com/ehZyiL/connect-hub/internal/proxy"
)

// TestMemoryMonitoringSimulation 模拟端到端并发数据转发并对内存指标进行全生命周期监测。
func TestMemoryMonitoringSimulation(t *testing.T) {
	var m0, m1, m2 runtime.MemStats

	// 1. 初始状态监测
	runtime.GC()
	runtime.ReadMemStats(&m0)
	rss0 := residentBytes()

	// 启动本地回环 Echo 服务模拟网关
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 Echo 监听失败: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// 启动 SOCKS5 代理服务器并配置直连 dialer
	server := hubproxy.New(hubproxy.Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, echoListener.Addr().String())
		},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动 SOCKS 代理失败: %v", err)
	}
	defer server.Close()

	// 2. 模拟并发高吞吐传输（20 条并发，每条传输 512KB 数据，总计 10MB 数据转发）
	concurrency := 20
	chunkSize := 32 * 1024
	repeat := 16 // 32KB * 16 = 512KB per connection
	payload := make([]byte, chunkSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	done := make(chan bool, concurrency)
	start := time.Now()

	for i := 0; i < concurrency; i++ {
		go func() {
			defer func() { done <- true }()
			conn, err := net.Dial("tcp", server.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()

			// SOCKS5 握手
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			_, _ = io.ReadFull(conn, resp)

			// CONNECT 请求
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90})
			reply := make([]byte, 10)
			_, _ = io.ReadFull(conn, reply)

			// 读写数据流
			readBuf := make([]byte, chunkSize)
			for r := 0; r < repeat; r++ {
				if _, err := conn.Write(payload); err != nil {
					return
				}
				if _, err := io.ReadFull(conn, readBuf); err != nil {
					return
				}
			}
		}()
	}

	for i := 0; i < concurrency; i++ {
		<-done
	}
	duration := time.Since(start)

	// 3. 采样高负载活跃期内存
	runtime.ReadMemStats(&m1)
	rss1 := residentBytes()

	// 4. 模拟空闲静默期并触发修剪工作集
	a := testApp(t)
	a.trimMemory()

	// 采样修剪后静默期内存
	runtime.ReadMemStats(&m2)
	rss2 := residentBytes()

	// 输出格式化监测报告
	fmt.Println("\n================= 运行内存监测实测报告 =================")
	fmt.Printf("模拟并发传输耗时: %v (20 并发，累计转发 10MB 数据)\n", duration)
	fmt.Println("-------------------------------------------------------")
	fmt.Printf("%-18s | %-12s | %-12s | %-12s\n", "指标维度", "1. 初始空闲", "2. 高并发峰值", "3. 静默修剪后")
	fmt.Println("-------------------------------------------------------")
	fmt.Printf("%-18s | %-10.2f MB | %-10.2f MB | %-10.2f MB\n", "HeapAlloc (活跃堆)",
		float64(m0.Alloc)/(1<<20), float64(m1.Alloc)/(1<<20), float64(m2.Alloc)/(1<<20))
	fmt.Printf("%-18s | %-10.2f MB | %-10.2f MB | %-10.2f MB\n", "HeapInuse (堆占用)",
		float64(m0.HeapInuse)/(1<<20), float64(m1.HeapInuse)/(1<<20), float64(m2.HeapInuse)/(1<<20))
	fmt.Printf("%-18s | %-10.2f MB | %-10.2f MB | %-10.2f MB\n", "Sys (系统申请虚拟内存)",
		float64(m0.Sys)/(1<<20), float64(m1.Sys)/(1<<20), float64(m2.Sys)/(1<<20))
	if rss0 > 0 {
		fmt.Printf("%-18s | %-10.2f MB | %-10.2f MB | %-10.2f MB\n", "RSS / WorkingSet (物理常驻)",
			float64(rss0)/(1<<20), float64(rss1)/(1<<20), float64(rss2)/(1<<20))
	}
	fmt.Printf("%-18s | %-10d 次 | %-10d 次 | %-10d 次\n", "GC 周期触发次数",
		m0.NumGC, m1.NumGC, m2.NumGC)
	fmt.Println("=======================================================")
}
