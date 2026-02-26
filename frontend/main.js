/*
 * Copyright (C) 2025 Russell Li (xiaoxinmm)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// 导入 CSS 文件
import './style.css';

// 导入 Wails 运行时
import { EventsOn, EventsEmit } from './wailsjs/runtime';

// --- 1. 获取所有 DOM 元素 ---
const logContainer = document.getElementById('log-container');
const progressBarInner = document.querySelector('.progress-bar-inner');
const progressBarText = document.querySelector('.progress-bar-text');
const onlineUsersEl = document.getElementById('online-users');
const totalRunsEl = document.getElementById('total-runs');
const logPathEl = document.getElementById('log-path-display');

/**
 * 统一的日志添加函数
 * @param {string} msg - 要显示的消息
 * @param {string} [className='info'] - 'info', 'warn', 'error', 'success', 'highlight', 'system'
 */
function addLog(msg, className = 'info') {
    if (!logContainer) return;

    // 检查是否应该保持在底部
    const isScrolledToBottom = logContainer.scrollHeight - logContainer.clientHeight <= logContainer.scrollTop + 5;

    // 创建新的日志行
    const logLine = document.createElement('div');
    logLine.className = 'log-line';
    logLine.classList.add(className); // 添加分类 class
    logLine.textContent = msg;
    logContainer.appendChild(logLine);

    // 如果之前就在底部，则自动滚动
    if (isScrolledToBottom) {
        logContainer.scrollTop = logContainer.scrollHeight;
    }
}

// --- 2. 监听 Go 后台事件 ---

/**
 * 监听 'log-stream'
 * 接收 Go 后台的 Logf() 日志并显示在界面上
 */
EventsOn('log-stream', (msg) => {
    // 根据关键字自动分类
    let className = 'info';
    if (msg.includes('!!! 警告') || msg.includes('⚠️')) {
        className = 'warn';
    } else if (msg.includes('❌') || msg.includes('失败')) {
        className = 'error';
    } else if (msg.includes('✅') || msg.includes('成功')) {
        className = 'success';
    } else if (msg.includes('--- 云端公告 ---') || msg.includes('欢迎使用') || msg.includes('--- 第')) {
        className = 'highlight';
    } else if (msg.includes('--- 开始记录系统信息 ---') || msg.includes('操作系统:') || msg.includes('CPU 型号:') || msg.includes('总内存:') || msg.includes('系统架构:')) {
        className = 'system'; // 为 systemInfo 日志使用 'system' 类
    }

    addLog(msg, className);
});

/**
 * 监听 'progress-update'
 * 更新进度条和倒计时
 */
EventsOn('progress-update', (currentSecond, executionCount) => {
    const percent = (currentSecond / 60) * 100;
    if (progressBarInner) {
        progressBarInner.style.width = `${percent}%`;
    }
    if (progressBarText) {
        progressBarText.textContent = `... ${60 - currentSecond}s 后下次执行 (已执行 ${executionCount} 次) ...`;
    }
});

/**
 * 监听 'execution-start'
 * 重置进度条并显示执行中
 */
EventsOn('execution-start', (executionCount) => {
    if (progressBarInner) {
        progressBarInner.style.width = '0%';
    }
    if (progressBarText) {
        progressBarText.textContent = `... 正在执行第 ${executionCount} 次 ...`;
    }
});

/**
 * 监听 'logpath' 事件
 * 将日志路径更新到页脚
 */
EventsOn('logpath', (path) => {
    if (logPathEl) {
        logPathEl.textContent = `Log: ${path}`;
    }
    console.log(`Log file location: ${path}`);
});


/**
 * 监听 'stats-update'
 * 接收 Go 后台发送的统计数据
 */
EventsOn("stats-update", (onlineCount, totalRuns) => {
    if (onlineUsersEl) {
        onlineUsersEl.textContent = (onlineCount !== null && onlineCount !== undefined)
            ? onlineCount.toLocaleString()
            : '...';
    }
    if (totalRunsEl) {
        totalRunsEl.textContent = (totalRuns !== null && totalRuns !== undefined)
            ? totalRuns.toLocaleString()
            : '...';
    }
});


/**
 * 监听 DOMContentLoaded 事件
 * 告诉 Go 后台 "前端已就绪"
 */
document.addEventListener('DOMContentLoaded', () => {
    EventsEmit('frontend:ready');
});