package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

// 云端后台 API 地址
const (
	// !! 警告：请将这里替换为你的真实后台服务器 API 地址
	backendURL = ""
)

// CloudConfig 定义了从云端获取的配置结构
type CloudConfig struct {
	ProcessList     []string `json:"process_list"`
	Announcement    string   `json:"announcement"`
	TotalExecutions uint64   `json:"total_executions"`
	OnlineUsers     int      `json:"online_users"`
}

// App 结构体
type App struct {
	ctx            context.Context
	fileLogger     *log.Logger
	logFile        *os.File
	logPath        string
	executionCount uint64 // 本地执行计数器

	// 云端控制相关
	clientID        string       // 客户端唯一ID
	targetProcesses []string     // 从云端获取的目标进程列表
	cloudConfig     CloudConfig  // 存储云端配置
	httpClient      *http.Client // HTTP 客户端
}

// NewApp 创建一个新的 App 应用结构体
func NewApp() *App {
	return &App{
		// 默认的进程列表，作为获取失败时的后备
		targetProcesses: []string{"SGuard64.exe", "SGuardSvc64.exe"},
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // 10秒超时
		},
	}
}

// checkAdmin 检查是否拥有管理员权限
func (a *App) checkAdmin() bool {
	// 尝试打开物理磁盘设备，这通常需要管理员权限
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// startup 在 Wails 启动时调用
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// 1. 初始化本地文件日志
	err := a.initLogger()
	if err != nil {
		// 如果日志文件都创建失败，先尝试打印到控制台，UI 此时可能还未这就绪
		fmt.Printf("!!! 警告：本地日志文件创建失败: %v\n", err)
	}

	// 2. [新增] 管理员权限检查
	if !a.checkAdmin() {
		a.Logf("❌ 错误：未检测到管理员权限！程序可能无法正常工作。")
		// 弹出原生警告框
		wailsRuntime.MessageDialog(ctx, wailsRuntime.MessageDialogOptions{
			Type:          wailsRuntime.ErrorDialog,
			Title:         "权限不足",
			Message:       "本程序需要管理员权限才能绑定 CPU 核心。\n\n请关闭程序，右键选择「以管理员身份运行」。",
			Buttons:       []string{"确定"},
			DefaultButton: "确定",
		})
	} else {
		a.Logf("✅ 已获取管理员权限。")
	}

	// 3. 异步初始化云端功能
	go a.initClientID()
	go a.fetchCloudConfig() // 尝试获取云端配置

	// 4. 启动主程序循环
	go a.runLoop()
}

// shutdown 在 Wails 关闭时调用
func (a *App) shutdown(ctx context.Context) {
	a.Logf("程序正在关闭...")
	if a.logFile != nil {
		a.fileLogger.Println("Logger shutting down.")
		a.logFile.Close()
	}
}

// initClientID 初始化客户端唯一ID
func (a *App) initClientID() {
	// 尝试获取唯一的机器 ID
	info, err := host.InfoWithContext(a.ctx)
	if err != nil {
		a.Logf("!!! 警告：获取客户端ID失败: %v", err)
		a.clientID = "unknown-client"
		return
	}
	a.clientID = info.HostID
	if a.clientID == "" {
		a.clientID = "unknown-host-id"
	}
	a.fileLogger.Printf("Client ID set to: %s", a.clientID)
}

// fetchCloudConfig 从云端获取配置
func (a *App) fetchCloudConfig() {
	a.Logf("... 正在连接云端获取配置 ...")
	req, err := http.NewRequestWithContext(a.ctx, "GET", backendURL+"/config", nil)
	if err != nil {
		a.Logf("!!! 警告：创建云端请求失败: %v", err)
		return
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.Logf("!!! 警告：连接云端失败: %v", err)
		a.Logf("... 将使用默认配置运行 ...")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.Logf("!!! 警告：云端服务器返回状态: %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.Logf("!!! 警告：读取云端响应失败: %v", err)
		return
	}

	var config CloudConfig
	if err := json.Unmarshal(body, &config); err != nil {
		a.Logf("!!! 警告：解析云端配置失败: %v", err)
		return
	}

	a.cloudConfig = config // 存储公告
	if len(config.ProcessList) > 0 {
		a.targetProcesses = config.ProcessList // 替换进程列表
		a.Logf("✅ 云端配置同步成功！")
		a.Logf("... 目标进程列表已更新: %v", a.targetProcesses)
	} else {
		a.Logf("... 云端未提供进程列表，使用默认配置 ...")
	}
	//启动时统计一次使用
	wailsRuntime.EventsEmit(a.ctx, "stats-update", config.OnlineUsers, config.TotalExecutions)
}

// sendHeartbeat 发送心跳到后台
func (a *App) sendHeartbeat() {
	if a.clientID == "" {
		return // 还未获取到ID
	}

	data := map[string]string{"client_id": a.clientID}
	jsonData, err := json.Marshal(data)
	if err != nil {
		a.fileLogger.Printf("Heartbeat marshal error: %v", err) // 心跳失败只记录到文件
		return
	}

	req, err := http.NewRequestWithContext(a.ctx, "POST", backendURL+"/heartbeat", bytes.NewBuffer(jsonData))
	if err != nil {
		a.fileLogger.Printf("Heartbeat request create error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.fileLogger.Printf("Heartbeat send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		a.fileLogger.Println("Heartbeat sent successfully.")
	} else {
		a.fileLogger.Printf("Heartbeat server response: %s", resp.Status)
	}
}

// fetchServerStats 循环获取最新的统计数据
func (a *App) fetchServerStats() {
	if a.ctx.Err() != nil {
		return // 检查上下文是否已取消
	}
	req, err := http.NewRequestWithContext(a.ctx, "GET", backendURL+"/config", nil)
	if err != nil {
		a.fileLogger.Printf("Stats fetch request error: %v", err)
		return
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.fileLogger.Printf("Stats fetch send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.fileLogger.Printf("Stats fetch server error: %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.fileLogger.Printf("Stats fetch read body error: %v", err)
		return
	}

	var stats CloudConfig
	if err := json.Unmarshal(body, &stats); err != nil {
		a.fileLogger.Printf("解析云端统计失败: %v", err)
		return
	}

	// 向前端发送最新统计数据
	wailsRuntime.EventsEmit(a.ctx, "stats-update", stats.OnlineUsers, stats.TotalExecutions)
}

// runLoop 是程序的主循环
func (a *App) runLoop() {
	// 等待前端 "ready" 事件
	wailsRuntime.EventsOnce(a.ctx, "frontend:ready", func(_ ...interface{}) {
		// 向前端发送日志保存位置
		if a.logPath != "" {
			wailsRuntime.EventsEmit(a.ctx, "logpath", a.logPath)
		}

		// 记录系统信息
		a.logSystemInfo()

		a.Logf("欢迎使用 Fuck your ACE！")
		a.Logf("请务必保持本窗口开启。")

		// 显示云端公告
		time.Sleep(1 * time.Second)
		if a.cloudConfig.Announcement != "" {
			a.Logf("--- 云端公告 ---")
			a.Logf(a.cloudConfig.Announcement)
			a.Logf("----------------")
		}

		// 启动一个独立的goroutine来定期刷新统计数据
		go func() {
			statsTicker := time.NewTicker(15 * time.Second)
			defer statsTicker.Stop()

			for {
				select {
				case <-a.ctx.Done(): // 程序退出
					return
				case <-statsTicker.C:
					a.fetchServerStats() // 定期获取统计
				}
			}
		}()

		// 开始无限循环
		for {
			a.RunBindingProcess()
			// 每次循环发送心跳（这将自动增加服务器的总执行次数）
			go a.sendHeartbeat()
			a.runCountdown() // 执行60秒倒计时
		}
	})
}

// runCountdown 执行60秒倒计时，并每秒向前端发送进度
func (a *App) runCountdown() {
	// a.Logf("... 60秒后将开始下一次执行 ...") // [降噪] 移除这行，因为它没太大意义
	for i := 1; i <= 60; i++ {
		// 向前端发送 (当前秒数, 总执行次数)
		wailsRuntime.EventsEmit(a.ctx, "progress-update", i, a.executionCount)
		time.Sleep(1 * time.Second)
	}
}

// initLogger 初始化本地文件日志记录器
func (a *App) initLogger() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("无法获取用户配置目录: %v", err)
	}
	logDir := filepath.Join(configDir, "FuckYourACE")
	logPath := filepath.Join(logDir, "app.log")
	a.logPath = logPath

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("无法创建日志目录 '%s': %v", logDir, err)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("无法打开日志文件 '%s': %v", logPath, err)
	}

	a.logFile = file
	a.fileLogger = log.New(a.logFile, "[FuckYourACE] ", log.LstdFlags)
	a.fileLogger.Println("----------------------------------")
	a.fileLogger.Println("Logger initialized. Application starting.")
	a.fileLogger.Printf("Log file location: %s", logPath)
	return nil
}

// logSystemInfo 记录详细的系统信息
func (a *App) logSystemInfo() {
	if a.fileLogger == nil {
		a.Logf("文件日志记录器未初始化。") // 也在UI上显示
		return
	}
	// [降噪] 系统信息只记录到文件，不再占用UI版面，除非是第一行
	a.fileLogger.Println("--- 开始记录系统信息 ---")
	if hostInfo, err := host.Info(); err == nil {
		a.fileLogger.Printf("操作系统: %s (版本: %s)", hostInfo.Platform, hostInfo.PlatformVersion)
		a.fileLogger.Printf("系统架构: %s", hostInfo.KernelArch)
	}
	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		cpuModel := strings.TrimSpace(cpuInfo[0].ModelName)
		a.fileLogger.Printf("CPU 型号: %s", cpuModel)
		a.fileLogger.Printf("物理核心: %d, 逻辑核心: %d", cpuInfo[0].Cores, runtime.NumCPU())
	}
	if memInfo, err := mem.VirtualMemory(); err == nil {
		totalGB := float64(memInfo.Total) / (1024 * 1024 * 1024)
		a.fileLogger.Printf("总内存: %.2f GB", totalGB)
	}
	a.fileLogger.Println("--- 系统信息记录完毕 ---")
}

// Logf 会将日志同时写入文件和发送到 UI 界面
func (a *App) Logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	// 写入本地日志文件
	if a.fileLogger != nil {
		a.fileLogger.Println(strings.TrimSpace(msg))
	}

	// 发送到 UI 界面
	wailsRuntime.EventsEmit(a.ctx, "log-stream", msg)

	// 暂停 100 毫秒，实现 "逐行打印" 效果
	time.Sleep(100 * time.Millisecond)
}

// [新增] logVerbose 用于处理“啰嗦”的日志
// 如果是第一次运行，或者 forceUI 为 true，则显示在 UI 上。
// 否则只写入文件，保持 UI 清爽。
func (a *App) logVerbose(forceUI bool, format string, args ...interface{}) {
	// 如果是第一次执行，或者强制显示（比如出错了），则调用 Logf (UI + File)
	if a.executionCount <= 1 || forceUI {
		a.Logf(format, args...)
		return
	}

	// 否则只写入本地文件
	if a.fileLogger != nil {
		msg := fmt.Sprintf(format, args...)
		a.fileLogger.Println(strings.TrimSpace(msg))
	}
}

// RunBindingProcess 执行核心绑定流程
func (a *App) RunBindingProcess() {
	// 原子增加执行次数
	atomic.AddUint64(&a.executionCount, 1)

	// 向前端发送 "执行开始" 事件
	wailsRuntime.EventsEmit(a.ctx, "execution-start", a.executionCount)

	// [降噪] 后续的成功信息使用 logVerbose，forceUI=false
	a.logVerbose(false, "----------------------------------")
	a.logVerbose(false, "--- 第 %d 次执行 ---", a.executionCount)
	a.logVerbose(false, "开始执行绑定流程...")

	var targetCore int

	cores, err := getEfficientCores()
	if err != nil {
		// [降噪] 即使出错，如果是备用方案也只提示一次详细信息
		// 但如果是严重错误，我们可能希望显示。这里保留详细信息，因为这很重要。
		a.logVerbose(true, "⚠️ %v，将启用备用方案。", err)
		totalCores := runtime.NumCPU()
		if totalCores <= 0 {
			totalCores = 1
		}
		targetCore = totalCores - 1 // 绑定到最后一个逻辑核心
		a.logVerbose(false, "✅ 启用备用方案：绑定到最后一个逻辑核心 (CPU %d)", targetCore)
	} else {
		targetCore = cores[0] // 绑定到第一个能效核
		a.logVerbose(false, "✅ 识别到能效核：%v", cores)
		a.logVerbose(false, "✅ 采用最佳方案：绑定到第一个能效核 (CPU %d)", targetCore)
	}

	pids, err := a.getTargetPIDs()
	if err != nil {
		// [注意] 找不到目标进程通常不是错误（没开游戏），所以不需要红色报警，但可以显示在UI
		// 这里选择：如果是第一次，显示。后续如果不显示，用户可能以为程序死了。
		// 折中方案：如果找不到进程，且是后续运行，只在文件里记录，UI 上保持安静。
		a.logVerbose(false, "❌ 获取目标进程失败（可能未运行）：%v", err)
		return
	}

	if len(pids) == 0 {
		targetProcsStr := strings.Join(a.targetProcesses, " / ")
		a.logVerbose(false, "ℹ️ 未找到目标进程 (%s)", targetProcsStr)
	} else {
		// 找到了进程！这是一个重要事件。
		// 如果是第 2+ 次运行，我们依然希望能看到它起作用了，但不要刷屏。
		// 策略：如果绑定成功，且是第 2+ 次，只输出一行简洁日志。

		if a.executionCount > 1 {
			// [降噪] 简洁模式
			a.Logf("✅ [第%d次] 成功捕获并处理 PID: %v", a.executionCount, pids)
		} else {
			// 详细模式
			a.Logf("✅ 找到目标进程 PID：%v", pids)
		}

		successCount := 0
		for _, pid := range pids {
			if err := bindToEfficientCore(pid, targetCore); err != nil {
				// 错误始终显示
				a.Logf("❌ PID=%d 绑定失败：%v", pid, err)
			} else {
				// 成功信息降噪
				a.logVerbose(false, "✅ PID=%d 已绑定到核心 %d，并设为最低优先级", pid, targetCore)
				successCount++
			}
		}
		a.logVerbose(false, "...绑定完成 (成功 %d / 总共 %d)", successCount, len(pids))
	}
	a.logVerbose(false, "----------------------------------")
}

// --- Windows API 动态加载 (保持不变) ---
var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetLogicalProcessorInformationEx = modkernel32.NewProc("GetLogicalProcessorInformationEx")
	procSetProcessAffinityMask           = modkernel32.NewProc("SetProcessAffinityMask")
)

// --- Windows API 帮助函数 (保持不变) ---

func _getLogicalProcessorInformationEx(relationship LOGICAL_PROCESSOR_RELATIONSHIP, buffer *byte, length *uint32) (err error) {
	ret, _, err := procGetLogicalProcessorInformationEx.Call(
		uintptr(relationship),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(length)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func _setProcessAffinityMask(handle windows.Handle, mask uintptr) (err error) {
	ret, _, err := procSetProcessAffinityMask.Call(
		uintptr(handle),
		mask,
	)
	if ret == 0 {
		return err
	}
	return nil
}

// --- Windows API 常量和结构体 (保持不变) ---
type LOGICAL_PROCESSOR_RELATIONSHIP uint32

const (
	RelationProcessorCore LOGICAL_PROCESSOR_RELATIONSHIP = 0
)
const (
	ProcessorEfficientCore byte = 4
)

type GROUP_AFFINITY struct {
	Mask     uintptr
	Group    uint16
	Reserved [3]uint16
}
type PROCESSOR_RELATIONSHIP struct {
	Flags      byte     // 包含核心类型（P-core 或 E-core）
	Reserved   [21]byte // 保留字段
	GroupCount uint16   // 组掩码的数量
	GroupMask  [1]GROUP_AFFINITY
}
type SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX struct {
	Relationship LOGICAL_PROCESSOR_RELATIONSHIP
	Size         uint32
	Processor    PROCESSOR_RELATIONSHIP
}

// getEfficientCores 查找能效核 (E-Cores) (保持不变)
func getEfficientCores() ([]int, error) {
	var bufferSize uint32 = 0

	err := _getLogicalProcessorInformationEx(RelationProcessorCore, nil, &bufferSize)
	if err != nil && err.(windows.Errno) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("无法获取 CPU 信息 (GetLogicalProcessorInformationEx 第一次调用失败): %v", err)
	}

	buffer := make([]byte, bufferSize)
	err = _getLogicalProcessorInformationEx(RelationProcessorCore, &buffer[0], &bufferSize)
	if err != nil {
		return nil, fmt.Errorf("读取 CPU 信息失败：%v", err)
	}

	var efficientCores []int
	var offset uintptr = 0

	for offset < uintptr(bufferSize) {
		lpi := (*SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(unsafe.Pointer(&buffer[offset]))

		if lpi.Relationship == RelationProcessorCore {
			procRel := lpi.Processor

			if (procRel.Flags & ProcessorEfficientCore) != 0 {
				for i := 0; i < int(procRel.GroupCount); i++ {
					groupMask := (*GROUP_AFFINITY)(unsafe.Pointer(
						uintptr(unsafe.Pointer(&procRel.GroupMask[0])) +
							uintptr(i)*unsafe.Sizeof(GROUP_AFFINITY{}),
					))

					mask := groupMask.Mask
					group := groupMask.Group

					for j := 0; j < 64; j++ {
						if (mask & (1 << j)) != 0 {
							cpuIndex := (int(group) * 64) + j
							efficientCores = append(efficientCores, cpuIndex)
						}
					}
				}
				if len(efficientCores) > 0 {
					break
				}
			}
		}

		if lpi.Size == 0 {
			break
		}
		offset += uintptr(lpi.Size)
	}

	if len(efficientCores) == 0 {
		return nil, fmt.Errorf("未识别到能效核 (E-Cores)")
	}
	return efficientCores, nil
}

// getTargetPIDs 查找目标进程的 PID 列表 (保持不变)
func (a *App) getTargetPIDs() ([]int, error) {
	targetMap := make(map[string]bool)
	for _, proc := range a.targetProcesses {
		targetMap[proc] = true
	}

	if len(targetMap) == 0 {
		return nil, fmt.Errorf("目标进程列表为空")
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("创建进程快照失败：%v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("获取进程列表失败：%v", err)
	}

	var pids []int
	for {
		procName := windows.UTF16ToString(entry.ExeFile[:])

		if _, found := targetMap[procName]; found {
			pids = append(pids, int(entry.ProcessID))
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("遍历进程列表失败：%v", err)
		}
	}

	return pids, nil
}

// bindToEfficientCore 将指定 PID 绑定到核心并设置优先级 (保持不变)
func bindToEfficientCore(pid int, core int) error {
	// 使用最小权限，避免杀毒软件误报
	handle, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("打开进程失败（PID: %d）：%v", pid, err)
	}
	defer windows.CloseHandle(handle)

	// 创建一个 CPU 亲和性掩码，只包含目标核心
	affinityMask := uintptr(1 << core)
	err = _setProcessAffinityMask(handle, affinityMask)
	if err != nil {
		return fmt.Errorf("绑定 CPU 核 %d 失败（PID: %d）：%v", core, pid, err)
	}

	// 设置进程优先级为最低
	err = windows.SetPriorityClass(handle, windows.IDLE_PRIORITY_CLASS)
	if err != nil {
		return fmt.Errorf("设置进程优先级失败（PID: %d）：%v", pid, err)
	}

	return nil
}
