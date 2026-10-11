/** get_storage_usage 返回的本地存储占用统计（除 logLines 外均为字节数）。 */
export interface StorageUsage {
  /** 内存日志缓冲的行数 */
  logLines: number;
  /** 日志缓冲占用（内存） */
  logsBytes: number;
  /** 缓存占用（引擎二进制与隧道配置，可自动恢复） */
  cacheBytes: number;
  /** 应用数据占用（配置与秘密库） */
  dataBytes: number;
  /** 合计 */
  totalBytes: number;
}
