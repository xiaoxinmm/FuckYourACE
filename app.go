package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

// App 负责管理本地逻辑。移除云端和日志依赖后结构大幅精简。
type App struct {
	ctx                     context.Context
	targetProcesses         []string
	executionCount          uint64
	efficientCores          []int
	coresChecked            bool
	selectedCore            int
	selectedCoreSet         bool
}

type ProcessBindingResult struct {
	PID     int    `json:"pid"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type BindingStatus struct {
	Level           string                 `json:"level"`
	Execution       uint64                 `json:"execution"`
	TargetCore      int                    `json:"target_core"`
	CoreMode        string                 `json:"core_mode"`
	EfficientCores  []int                  `json:"efficient_cores,omitempty"`
	TargetProcesses []string               `json:"target_processes"`
	FoundPIDs       []int                  `json:"found_pids,omitempty"`
	SuccessCount    int                    `json:"success_count"`
	TotalCount      int                    `json:"total_count"`
	Message         string                 `json:"message"`
	Processes       []ProcessBindingResult `json:"processes"`
}

var statusPriority = map[string]int{
	"info":    0,
	"success": 1,
	"warn":    2,
	"error":   3,
}

func newBindingStatus(execution uint64, targets []string) *BindingStatus {
	return &BindingStatus{
		Level:           "info",
		Message:         fmt.Sprintf("正在执行第 %d 次绑定流程", execution),
		Execution:       execution,
		TargetProcesses: append([]string(nil), targets...),
	}
}

func (s *BindingStatus) updateLevel(level string) {
	if statusPriority[level] > statusPriority[s.Level] {
		s.Level = level
	}
}

func (s *BindingStatus) addProcessResult(pid int, success bool, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.Processes = append(s.Processes, ProcessBindingResult{
		PID:     pid,
		Success: success,
		Message: msg,
	})
	if success {
		s.updateLevel("success")
	} else {
		s.updateLevel("error")
	}
}

func (s *BindingStatus) emit(app *App) {
	if app.ctx == nil {
		return
	}
	wailsRuntime.EventsEmit(app.ctx, "binding-status", s)
}

// NewApp 创建一个新的 App 应用结构体
func NewApp() *App {
	return &App{
		targetProcesses: []string{"SGuard64.exe", "SGuardSvc64.exe"},
	}
}

// startup 在 Wails 启动时调用
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.initDebugPrivilege()
	go a.runLoop()
}

// shutdown 在 Wails 关闭时调用
func (a *App) shutdown(ctx context.Context) {
	// 保持轻量，无需额外清理
}

func (a *App) initDebugPrivilege() {
	if err := enableDebugPrivilege(); err != nil {
		return
	}
}

// runLoop 是程序的主循环
func (a *App) runLoop() {
	wailsRuntime.EventsOnce(a.ctx, "frontend:ready", func(_ ...interface{}) {

		for {
			if a.ctx.Err() != nil {
				return
			}
			a.RunBindingProcess()
			if a.ctx.Err() != nil {
				return
			}
			a.runCountdown()
		}
	})
}

// runCountdown 执行60秒倒计时，并每秒向前端发送进度
func (a *App) runCountdown() {
	const waitSeconds = 60

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for i := 1; i <= waitSeconds; i++ {
		if a.ctx.Err() != nil {
			return
		}
		<-ticker.C
		wailsRuntime.EventsEmit(a.ctx, "progress-update", i, a.executionCount)
	}
}

// RunBindingProcess 执行核心绑定流程
func (a *App) RunBindingProcess() {
	// 原子增加执行次数
	atomic.AddUint64(&a.executionCount, 1)

	status := newBindingStatus(a.executionCount, a.targetProcesses)

	// 向前端发送 "执行开始" 事件，并附带当前次数
	wailsRuntime.EventsEmit(a.ctx, "execution-start", a.executionCount)
	targetCore := a.ensureTargetCore(status)
	status.TargetCore = targetCore

	pids, err := a.getTargetPIDs()
	if err != nil {
		status.Message = fmt.Sprintf("获取目标进程失败：%v", err)
		status.updateLevel("error")
		status.emit(a)
		return
	}

	if len(pids) == 0 {
		targetProcsStr := strings.Join(a.targetProcesses, " / ")
		status.Message = fmt.Sprintf("未找到目标进程：%s", targetProcsStr)
		status.updateLevel("warn")
		status.emit(a)
		return
	}

	status.FoundPIDs = append([]int(nil), pids...)
	status.Message = fmt.Sprintf("找到目标进程 PID：%v", pids)
	status.updateLevel("success")
	successCount := 0
	for _, pid := range pids {
		if err := bindToEfficientCore(pid, targetCore); err != nil {
			status.addProcessResult(pid, false, "绑定失败：%v", err)
		} else {
			status.addProcessResult(pid, true, "已绑定到核心 %d，并设为最低优先级", targetCore)
			successCount++
		}
	}
	status.SuccessCount = successCount
	status.TotalCount = len(pids)
	if successCount == len(pids) {
		status.Message = fmt.Sprintf("本轮绑定成功：%d/%d", successCount, len(pids))
		status.updateLevel("success")
	} else if successCount == 0 {
		status.Message = fmt.Sprintf("本轮绑定失败：0/%d", len(pids))
		status.updateLevel("error")
	} else {
		status.Message = fmt.Sprintf("本轮绑定完成：成功 %d / 总共 %d", successCount, len(pids))
		status.updateLevel("warn")
	}
	status.emit(a)
}

func (a *App) ensureTargetCore(status *BindingStatus) int {
	if a.selectedCoreSet {
		status.CoreMode = "reuse"
		if len(a.efficientCores) > 0 {
			status.EfficientCores = append([]int(nil), a.efficientCores...)
		}
		return a.selectedCore
	}

	if !a.coresChecked {
		cores, err := getEfficientCores()
		a.coresChecked = true
		if err == nil && len(cores) > 0 {
			a.efficientCores = cores
			a.selectedCore = cores[0]
			a.selectedCoreSet = true
			status.CoreMode = "efficient"
			status.EfficientCores = append([]int(nil), cores...)
			return a.selectedCore
		}
		if err != nil {
			status.Message = fmt.Sprintf("%v，将启用备用方案。", err)
		}
	}

	totalCores := runtime.NumCPU()
	if totalCores <= 0 {
		totalCores = 1
	}
	a.selectedCore = totalCores - 1
	a.selectedCoreSet = true
	status.CoreMode = "fallback"
	return a.selectedCore
}

func enableDebugPrivilege() error {
	process := windows.CurrentProcess()
	var token windows.Token
	err := windows.OpenProcessToken(process, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	namePtr, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}

	var tp windows.Tokenprivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}

	if lastErr := windows.GetLastError(); lastErr == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("AdjustTokenPrivileges: SeDebugPrivilege 未授予 (需要管理员权限)")
	}

	return nil
}

// --- Windows API 动态加载 ---
var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetLogicalProcessorInformationEx = modkernel32.NewProc("GetLogicalProcessorInformationEx")
	procSetProcessAffinityMask           = modkernel32.NewProc("SetProcessAffinityMask")
)

// --- Windows API 帮助函数 ---

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

// --- Windows API 常量和结构体 ---
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

// getEfficientCores 查找能效核 (E-Cores)
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

// getTargetPIDs 查找目标进程的 PID 列表
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

// bindToEfficientCore 将指定 PID 绑定到核心并设置优先级
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
