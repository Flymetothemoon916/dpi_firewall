def _process_packet(self, packet):
    """处理单个数据包"""
    try:
        with transaction.atomic():  # 添加事务保护
            # 解析数据包
            parsed_packet = self._parse_packet(packet)
            if not parsed_packet:
                return
            
            # 获取数据包方向
            direction = self._get_packet_direction(parsed_packet)
            
            # 更新统计信息
            with self.lock:  # 添加锁保护
                if direction == 'inbound':
                    self.stats['inbound_packets'] += 1
                    self.stats['inbound_bytes'] += len(packet)
                else:
                    self.stats['outbound_packets'] += 1
                    self.stats['outbound_bytes'] += len(packet)
            
            # 应用规则检查
            action, rule = self._apply_rules(parsed_packet)
            
            # 记录日志
            self._log_packet(
                src_ip=parsed_packet['src_ip'],
                dst_ip=parsed_packet['dst_ip'],
                src_port=parsed_packet['src_port'],
                dst_port=parsed_packet['dst_port'],
                protocol=parsed_packet['protocol'],
                packet=packet,
                direction=direction,
                action=action,
                rule=rule
            )
            
            # 如果被阻止，更新阻止计数
            if action == 'blocked':
                with self.lock:
                    self.stats['blocked_packets'] += 1
            
    except Exception as e:
        logger.error(f"处理数据包失败: {str(e)}") 