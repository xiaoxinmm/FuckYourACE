// 导入 CSS 文件
import './style.css';

// 导入 Wails 运行时
import { EventsOn, EventsEmit } from './wailsjs/runtime';

// --- 1. 获取所有 DOM 元素 ---
const progressBarInner = document.querySelector('.progress-bar-inner');
const progressBarText = document.querySelector('.progress-bar-text');
const bindingCard = document.getElementById('binding-card');
const bindingExecutionEl = document.getElementById('binding-execution');
const bindingLevelEl = document.getElementById('binding-level');
const bindingMessageEl = document.getElementById('binding-message');
const bindingCoreModeEl = document.getElementById('binding-core-mode');
const bindingTargetCoreEl = document.getElementById('binding-target-core');
const bindingEfficientCoresEl = document.getElementById('binding-efficient-cores');
const bindingTargetProcessesEl = document.getElementById('binding-target-processes');
const bindingFoundPIDsEl = document.getElementById('binding-found-pids');
const bindingResultSummaryEl = document.getElementById('binding-result-summary');
const bindingProcessesEl = document.getElementById('binding-processes');

function renderBindingStatus(data) {
    if (!bindingCard) {
        return;
    }
    bindingCard.classList.remove('hidden');

    if (bindingExecutionEl) {
        bindingExecutionEl.textContent = `第 ${data.execution ?? 0} 次执行`;
    }
    if (bindingLevelEl) {
        bindingLevelEl.textContent = (data.level || 'info').toUpperCase();
        bindingLevelEl.className = `binding-badge ${data.level || 'info'}`;
    }
    if (bindingMessageEl) {
        bindingMessageEl.textContent = data.message || '-';
    }
    if (bindingCoreModeEl) {
        bindingCoreModeEl.textContent = formatCoreMode(data.core_mode);
    }
    if (bindingTargetCoreEl) {
        bindingTargetCoreEl.textContent = data.target_core !== undefined ? data.target_core : '-';
    }
    if (bindingEfficientCoresEl) {
        bindingEfficientCoresEl.textContent = Array.isArray(data.efficient_cores) && data.efficient_cores.length
            ? data.efficient_cores.join(', ')
            : '无';
    }
    if (bindingTargetProcessesEl) {
        bindingTargetProcessesEl.textContent = Array.isArray(data.target_processes) && data.target_processes.length
            ? data.target_processes.join(' / ')
            : '未配置';
    }
    if (bindingFoundPIDsEl) {
        bindingFoundPIDsEl.textContent = Array.isArray(data.found_pids) && data.found_pids.length
            ? data.found_pids.join(', ')
            : '未发现';
    }
    if (bindingResultSummaryEl) {
        const successes = data.success_count ?? 0;
        const total = data.total_count ?? 0;
        const percentage = total > 0 ? Math.round((successes / total) * 100) : 0;
        bindingResultSummaryEl.textContent = total > 0
            ? `${successes} / ${total} (${percentage}%)`
            : '0 / 0';
    }

    if (bindingProcessesEl) {
        bindingProcessesEl.innerHTML = '';
        if (Array.isArray(data.processes) && data.processes.length) {
            data.processes.forEach((entry) => {
                const row = document.createElement('div');
                row.className = `process-row ${entry.success ? 'success' : 'error'}`;

                const pid = document.createElement('div');
                pid.className = 'process-pid';
                pid.textContent = `PID ${entry.pid}`;

                const message = document.createElement('div');
                message.className = 'process-message';
                message.textContent = entry.message;

                row.appendChild(pid);
                row.appendChild(message);
                bindingProcessesEl.appendChild(row);
            });
        } else {
            const empty = document.createElement('div');
            empty.className = 'binding-empty';
            empty.textContent = '未执行绑定或未返回结果。';
            bindingProcessesEl.appendChild(empty);
        }
    }
}

function formatCoreMode(mode) {
    switch (mode) {
        case 'efficient':
            return '能效核优先';
        case 'fallback':
            return '备用方案';
        case 'reuse':
            return '沿用上次选择';
        default:
            return '-';
    }
}

// --- 2. 监听 Go 后台事件 ---

EventsOn('binding-status', (payload) => {
    renderBindingStatus(payload || {});
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
 * 监听 DOMContentLoaded 事件
 * 告诉 Go 后台 "前端已就绪"
 */
document.addEventListener('DOMContentLoaded', () => {
    EventsEmit('frontend:ready');
});