/**
 * HTTP请求内容高亮显示脚本
 */
document.addEventListener('DOMContentLoaded', function() {
    // 获取HTTP请求展示容器
    const httpRequestElements = document.querySelectorAll('.http-request-display code');
    
    // 如果找到HTTP请求元素，进行处理
    if (httpRequestElements.length > 0) {
        httpRequestElements.forEach(function(element) {
            highlightHttpRequest(element);
        });
    }
    
    /**
     * 高亮显示HTTP请求内容
     * @param {HTMLElement} element - 包含HTTP请求内容的元素
     */
    function highlightHttpRequest(element) {
        const content = element.textContent;
        
        // 如果内容为空，不进行处理
        if (!content || content.trim() === '') {
            return;
        }
        
        // 分割HTTP请求的行
        const lines = content.split('\n');
        let highlightedContent = '';
        
        // 处理第一行（请求行）
        if (lines.length > 0) {
            const firstLine = lines[0];
            
            // 匹配HTTP请求方法、路径和协议版本
            const requestLineMatch = firstLine.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+([^\s]+)\s+(HTTP\/[\d\.]+)$/);
            
            if (requestLineMatch) {
                const [_, method, path, protocol] = requestLineMatch;
                
                // 高亮SQL注入和XSS攻击模式
                let highlightedPath = path;
                
                // 检测SQL注入
                if (path.includes("'") || path.includes("UNION") || path.includes("SELECT")) {
                    highlightedPath = highlightAttackPattern(path, /('+|\s+UNION\s+|\s+SELECT\s+|--)/gi);
                }
                
                // 检测XSS
                if (path.includes("<script>") || path.includes("alert(") || path.includes("onerror=")) {
                    highlightedPath = highlightAttackPattern(path, /(<script>|alert\(|on\w+\s*=)/gi);
                }
                
                highlightedContent += `<span class="http-method">${method}</span> <span class="http-path">${highlightedPath}</span> <span class="http-protocol">${protocol}</span>\n`;
            } else {
                highlightedContent += firstLine + '\n';
            }
        }
        
        // 处理头部
        let inHeaders = true;
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            
            // 空行表示头部的结束
            if (line.trim() === '') {
                inHeaders = false;
                highlightedContent += line + '\n';
                continue;
            }
            
            if (inHeaders) {
                // 匹配头部字段
                const headerMatch = line.match(/^([^:]+):\s*(.*)$/);
                if (headerMatch) {
                    const [_, name, value] = headerMatch;
                    highlightedContent += `<span class="http-header-name">${name}</span>: <span class="http-header-value">${value}</span>\n`;
                } else {
                    highlightedContent += line + '\n';
                }
            } else {
                // 请求体内容
                // 检测攻击模式
                let highlightedLine = line;
                
                // 检测SQL注入
                if (line.includes("'") || line.includes("UNION") || line.includes("SELECT")) {
                    highlightedLine = highlightAttackPattern(line, /('+|\s+UNION\s+|\s+SELECT\s+|--)/gi);
                }
                
                // 检测XSS
                if (line.includes("<script>") || line.includes("alert(") || line.includes("onerror=")) {
                    highlightedLine = highlightAttackPattern(line, /(<script>|alert\(|on\w+\s*=)/gi);
                }
                
                highlightedContent += highlightedLine + '\n';
            }
        }
        
        // 设置高亮后的内容
        element.innerHTML = highlightedContent;
    }
    
    /**
     * 高亮显示攻击模式
     * @param {string} text - 要处理的文本
     * @param {RegExp} pattern - 攻击模式正则表达式
     * @returns {string} 高亮后的文本
     */
    function highlightAttackPattern(text, pattern) {
        return text.replace(pattern, match => `<span class="attack-highlight">${match}</span>`);
    }
}); 