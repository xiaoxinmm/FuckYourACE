// Copyright (C) 2025 Russell Li (xiaoxinmm)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"io"
	"log" // 保留 log 包，用于初始的 fatalf
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus" // 新增：导入 logrus
)

// CloudConfig 定义了从云端下发的配置
type CloudConfig struct {
	ProcessList     []string `json:"process_list"`
	Announcement    string   `json:"announcement"`
	TotalExecutions uint64   `json:"total_executions"`
	OnlineUsers     int      `json:"online_users"`
}

// HeartbeatRequest 是客户端发送心跳的结构
type HeartbeatRequest struct {
	ClientID string `json:"client_id"`
}

// StatsData 定义了 stats.json 的结构
type StatsData struct {
	TotalExecutions uint64 `json:"total_executions"`
}

// --- 全局变量 ---
var (
	// 新增：创建 logrus 实例
	logger = logrus.New()

	currentConfig CloudConfig
	configMutex   sync.RWMutex

	activeClients = make(map[string]time.Time)
	clientMutex   sync.RWMutex

	totalExecutions uint64

	configFilePath = "config.json"
	statsFilePath  = "stats.json"
	logFilePath    = "fya_backend.log"
)

// --- 配置文件加载 ---
func loadConfig() {
	// 修复：使用 logger 实例
	logger.Info("... 正在加载 config.json ...")

	defaultConfig := CloudConfig{
		ProcessList:  []string{"SGuard64.exe", "SGuardSvc64.exe"},
		Announcement: "🔥 公告：连接服务器成功，但后台配置文件加载失败。",
	}

	file, err := os.ReadFile(configFilePath)
	if err != nil {
		// 修复：使用带 Error 字段的结构化日志
		logger.WithField("error", err).Warnf("!!! 警告：config.json 加载失败。将使用内置的默认配置。")
		configMutex.Lock()
		currentConfig = defaultConfig
		configMutex.Unlock()
		return
	}

	var configFromFile CloudConfig
	err = json.Unmarshal(file, &configFromFile)
	if err != nil {
		logger.WithField("error", err).Errorf("!!! 致命错误：无法解析 config.json。将使用内置的默认配置。")
		configMutex.Lock()
		currentConfig = defaultConfig
		configMutex.Unlock()
		return
	}

	configMutex.Lock()
	currentConfig.ProcessList = configFromFile.ProcessList
	currentConfig.Announcement = configFromFile.Announcement
	configMutex.Unlock()

	logger.Info("✅ config.json 加载成功。")
	logger.Infof("... 公告: %s", currentConfig.Announcement)
	logger.Infof("... 进程列表: %v", currentConfig.ProcessList)
}

// --- 统计数据加载 ---
func loadStats() {
	logger.Info("... 正在加载 stats.json ...")
	file, err := os.ReadFile(statsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("ℹ️  stats.json 未找到，将从 0 开始计数。")
			return
		}
		logger.WithField("error", err).Warn("!!! 警告：无法读取 stats.json")
		return
	}

	var statsData StatsData
	err = json.Unmarshal(file, &statsData)
	if err != nil {
		logger.WithField("error", err).Warn("!!! 警告：无法解析 stats.json")
		return
	}

	atomic.StoreUint64(&totalExecutions, statsData.TotalExecutions)
	logger.Infof("✅ stats.json 加载成功，当前累计执行次数: %d", statsData.TotalExecutions)
}

// --- 统计数据保存 ---
func saveStats() {
	currentExecutions := atomic.LoadUint64(&totalExecutions)
	statsData := StatsData{
		TotalExecutions: currentExecutions,
	}

	data, err := json.Marshal(statsData)
	if err != nil {
		logger.WithField("error", err).Error("!!! 致命错误：无法序列化 stats.json")
		return
	}

	err = os.WriteFile(statsFilePath, data, 0644)
	if err != nil {
		logger.WithField("error", err).Error("!!! 致命错误：无法写入 stats.json")
		return
	}
	logger.Infof("... 统计数据已保存到 %s (累计: %d)", statsFilePath, currentExecutions)
}

// --- 后台任务 Goroutines ---

func startStatsSaver() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		saveStats()
	}
}

func cleanupExpiredClients() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		clientMutex.Lock()
		cutoff := time.Now().Add(-5 * time.Minute)
		var expiredCount int
		for id, lastSeen := range activeClients {
			if lastSeen.Before(cutoff) {
				delete(activeClients, id)
				expiredCount++
			}
		}
		clientMutex.Unlock()

		// 修复：使用结构化日志
		logger.WithFields(logrus.Fields{
			"type":          "cleanup",
			"expired_count": expiredCount,
			"active_count":  len(activeClients),
		}).Info("后台清理任务完成")
	}
}

// --- 新增：Gin 的 Logrus 中间件 ---
func ginLogrusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		c.Next() // 处理请求
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		// 记录结构化日志
		logger.WithFields(logrus.Fields{
			"type":        "request", // 标记为 Gin 请求日志
			"status_code": c.Writer.Status(),
			"client_ip":   c.ClientIP(),
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"latency":     latency.String(),
			"user_agent":  c.Request.UserAgent(),
			"errors":      c.Errors.ByType(gin.ErrorTypePrivate).String(),
		}).Info("Gin request handled")
	}
}

// --- 后台主程序 ---

func main() {
	// --- 1. 设置日志 ---
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// 此时 logger 未必初始化，使用标准 log 致命退出
		log.Fatalf("无法打开日志文件: %v", err)
	}

	// 设置 logrus
	logger.SetFormatter(&logrus.JSONFormatter{}) // 核心：设置为 JSON 格式
	logger.SetLevel(logrus.InfoLevel)            // 设置日志级别

	// 设置多路输出：同时写入文件和标准输出（终端）
	mw := io.MultiWriter(os.Stdout, logFile)
	logger.SetOutput(mw)

	// 替换标准库 log 的输出（以防万一有旧代码调用）
	log.SetOutput(mw)
	log.SetFlags(0)
	log.SetPrefix("") // 标准库 log 不再需要前缀

	logger.Info("----------------------------------")
	logger.Info("--- 后台服务器启动 (Logger已初始化) ---")

	// --- 2. 加载配置和统计 ---
	loadStats()
	loadConfig()

	// --- 3. 启动后台任务 ---
	go cleanupExpiredClients()
	go startStatsSaver()

	// --- 4. 设置 Gin ---
	gin.SetMode(gin.ReleaseMode)
	// 修复：使用 gin.New() 而不是 gin.Default() 来移除默认 logger
	router := gin.New()
	router.Use(gin.Recovery())        // 使用 Recovery 中间件
	router.Use(ginLogrusMiddleware()) // 使用我们自定义的 Logrus 中间件
	router.Use(cors.Default())        // 允许跨域

	// --- 5. 设置 API 路由 ---
	api := router.Group("/api")
	{
		api.GET("/config", getConfigHandler)
		api.POST("/heartbeat", heartbeatHandler)
		api.GET("/stats", statsHandler)
		api.GET("/reload-config", reloadConfigHandler)
	}

	// 启动服务器
	logger.Info("后台服务器启动于 0.0.0.0:8080")
	if err := router.Run(":8080"); err != nil {
		logger.Fatalf("无法启动服务器: %v", err)
	}
}

// --- Gin 处理器 ---

// getConfigHandler 向客户端发送当前配置和统计
func getConfigHandler(c *gin.Context) {
	clientMutex.RLock()
	onlineCount := getActiveClientCount(1 * time.Minute)
	clientMutex.RUnlock()

	totalRuns := atomic.LoadUint64(&totalExecutions)

	configMutex.RLock()
	config := currentConfig
	configMutex.RUnlock()

	config.OnlineUsers = onlineCount
	config.TotalExecutions = totalRuns

	c.JSON(http.StatusOK, config)
}

// heartbeatHandler 接收心跳，更新活跃时间，并增加总执行次数
func heartbeatHandler(c *gin.Context) {
	var req HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}
	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "需要 client_id"})
		return
	}
	clientMutex.Lock()
	activeClients[req.ClientID] = time.Now()
	clientMutex.Unlock()

	atomic.AddUint64(&totalExecutions, 1)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// statsHandler (给管理员) 返回当前的活跃用户数和总执行次数
func statsHandler(c *gin.Context) {
	clientMutex.RLock()
	count := getActiveClientCount(1 * time.Minute)
	clientMutex.RUnlock()
	totalRuns := atomic.LoadUint64(&totalExecutions)

	c.JSON(http.StatusOK, gin.H{
		"active_users_1min": count,
		"total_executions":  totalRuns,
		"total_tracked":     len(activeClients),
	})
}

// reloadConfigHandler 重新加载 config.json
func reloadConfigHandler(c *gin.Context) {
	loadConfig()
	logger.Info("--- 配置文件已通过 API 热重载 ---")
	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"message":      "配置已重新加载",
		"announcement": currentConfig.Announcement,
		"process_list": currentConfig.ProcessList,
	})
}

// --- 辅助函数 ---

// getActiveClientCount 计算在指定时间范围内有多少活跃客户端
func getActiveClientCount(duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)
	for _, lastSeen := range activeClients {
		if lastSeen.After(cutoff) {
			count++
		}
	}
	return count
}
