# ZoomEye 指纹采集进度文档

## 项目目标

从 `patterns_table.csv` 中读取 HTTP Server 头的正则匹配规则，通过 ZoomEye 搜索引擎批量采集匹配的真实设备 HTTP 响应数据，保存为结构化 CSV 供后续分析使用。

## 文件说明

| 文件 | 说明 |
|---|---|
| `patterns_table.csv` | 输入：453 行，含 449 条有效 pattern，每行两列：`description`（名称）、`pattern`（正则） |
| `fingerprints.csv` | 输出：10,109 条数据，列为 `name`、`pattern`、`response_content` |
| `batch_fingerprints.py` | 批量采集脚本 |
| `progress.json` | 断点续传进度记录（已全部完成，可删除） |

## 采集方法

1. **ZoomEye 查询构建**：从正则中提取字面量前缀，构造 `http.header.server=` 或 `http.header.server==` 查询
   - 纯精确匹配（`^foo$`，无特殊字符）→ `==`（精确）
   - 含可选/变长部分 → `=`（包含，宽泛）

2. **正则过滤**：对每条返回记录提取 `Server:` 头的值，用原始正则做 `re.fullmatch`，只保留真正匹配的记录，排除 ZoomEye 宽泛查询带来的误匹配

3. **分页**：每个 pattern 最多拉取 5 页（500 条候选），直到筛出 100 条匹配或候选耗尽

4. **断点续传**：每完成一条 pattern 写入 `progress.json`，中断后可直接重跑

## 采集结果

- 449 条 pattern 全部处理完毕
- 108 条 pattern 有匹配数据，341 条在 ZoomEye 中无收录
- 有数据的 pattern 平均 93.6 条记录，多数达到上限 100 条

## 使用的工具

- ZoomEye MCP（`mcp-zoomeye-org`），API 端点：`https://api.zoomeye.org/v2/search`
- Python 标准库：`re`、`csv`、`json`
- 第三方库：`requests`
