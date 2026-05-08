# 基于 ZoomEye 网络空间搜索引擎的 HTTP 指纹数据集构建方法

## 摘要

本节介绍一种面向 HTTP 响应头指纹识别任务的大规模标注数据集的自动化构建方法。该方法以公开的指纹规则库作为先验知识，结合网络空间搜索引擎 ZoomEye 的海量实网数据，通过查询语句自动推导、候选结果正则后过滤、多头部类型并行采集等手段，构建出覆盖 Server、Set-Cookie、WWW-Authenticate、X-Powered-By 四类 HTTP 响应头的指纹样本数据集，共计 **22,087 条**指令微调格式样本，为后续大语言模型（LLM）在网络指纹识别任务上的微调训练提供了高质量的数据基础。

---

## 1. 研究背景与动机

### 1.1 HTTP 指纹识别的重要性

HTTP 指纹识别（HTTP Fingerprinting）是网络资产探测与安全评估的核心能力之一。攻防双方均依赖对目标服务器软件类型、版本及框架的准确识别来制定相应策略。传统指纹识别方法依赖人工编写的正则规则库（如 Metasploit 的 `http.rb`、Nmap 的 `nmap-service-probes`），维护成本高且泛化能力有限。将大语言模型应用于该任务，有望实现对未见指纹的泛化推断，但其前提是构建足够规模、覆盖足够广泛的高质量标注数据集。

### 1.2 数据获取的挑战

直接人工标注 HTTP 响应头数据面临两大挑战：

1. **规模瓶颈**：互联网上可访问的目标设备数量庞大，人工采集效率极低；
2. **标签缺失**：原始 HTTP 响应数据本身不携带"该响应属于哪种软件产品"的标签信息，需要额外的匹配验证步骤。

本方法通过"先验规则引导 + 搜索引擎采集 + 正则后过滤"的三阶段流程，同时解决了上述两个问题。

---

## 2. 数据集构建方法

整体流程如图 1 所示，分为四个阶段：指纹规则解析、查询语句推导、网络空间数据采集、正则后过滤与格式化。

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  指纹规则库       │───▶│  查询语句推导     │───▶│  ZoomEye 采集    │───▶│  正则后过滤       │
│  (XML 格式)      │    │  (宽泛检索词)     │    │  (API 分页拉取)  │    │  + 格式化输出    │
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

**图 1** 数据集构建总体流程

### 2.1 指纹规则库解析

**数据来源**：采用 Metasploit Framework 中的 HTTP 指纹规则库作为先验知识来源，该库以 XML 格式定义，包含四类 HTTP 响应头的指纹规则文件：

| 文件 | 匹配头部 | 规则数量 |
|------|---------|---------|
| `http_servers.xml` | `Server` | 449 条 |
| `http_cookies.xml` | `Set-Cookie` | 84 条 |
| `http_wwwauth.xml` | `WWW-Authenticate` | 79 条 |
| `http_xpoweredby.xml` | `X-Powered-By` | 1 条 |

每条规则包含三类信息：正则表达式模式（`pattern`）、人工描述（`description`）以及若干匹配样例（`example`）。这三类信息共同用于后续查询语句的推导。

**XML 规则示例**：

```xml
<fingerprint pattern="^(?:Basic|Digest) realm=&quot;Transmission&quot;$">
  <description>Transmission</description>
  <example>Basic realm="Transmission"</example>
  <param pos="0" name="service.product" value="Transmission"/>
</fingerprint>
```

### 2.2 ZoomEye 查询语句自动推导

这是本方法的核心创新之一。给定一条指纹规则的正则表达式，需要自动推导出一个能从 ZoomEye 召回大量候选样本的宽泛检索语句。

**关键发现**：经过系统性实验验证，ZoomEye v2 API 支持对完整 HTTP 响应头块进行全文检索，正确的查询格式为：

```
http.header="<Header-Name>: <搜索词>"
```

而非字段专用查询（如 `http.header.set-cookie="..."` 或 `http.header.www-authenticate="..."`），后者在 ZoomEye v2 中索引数据为空，无法返回有效结果。表 1 展示了两种格式的实际检索量对比：

**表 1** ZoomEye 查询格式对比

| 查询语句 | 返回结果数 |
|---------|---------|
| `http.header.set-cookie="PHPSESSID"` | 0 |
| `http.header="Set-Cookie: PHPSESSID"` | 12,859,699 |
| `http.header.www-authenticate="Transmission"` | 0 |
| `http.header="WWW-Authenticate: Basic realm=Transmission"` | 959,358 |
| `http.header.x-powered-by="PHP"` | 0 |
| `http.header="X-Powered-By: PHP"` | 45,717,222 |

**查询词的自动推导策略**：

对于一条指纹规则，按如下优先级逐步退化，直到得到一个有效的搜索词：

1. **字面量前缀提取**：从正则表达式中提取锚点之后、第一个元字符之前的连续字面量子串。例如，`^PHPSESSID=` 提取出前缀 `PHPSESSID`。提取时将 ZoomEye 查询分隔符 `"` 也视为停止符，避免生成包含内嵌引号的非法查询语句。

2. **样例值提取**：若正则前缀为空或过于宽泛（如 `Basic realm`、`Digest realm`），则解析规则中的 `example` 字段。对于 `WWW-Authenticate` 类型的规则，提取 `realm=` 后的值并以 `Basic realm=<value>` 的形式拼接；对于 `Set-Cookie` 类型，提取 cookie 名称（第一个 `=` 之前的部分）；对于 `X-Powered-By` 类型，提取框架名称前缀。

3. **正则内反向解析**：若无样例，尝试从正则本身中匹配 `realm=<literal>` 模式提取 realm 值。

4. **描述词回退**：以上均失败时，取 `description` 字段中最后一个有意义的词作为检索词。

最终查询语句的构造方式为：

```
http.header="<标准化头部名称>: <推导出的搜索词>"
```

**示例**（`WWW-Authenticate` 类型）：

| 规则描述 | 正则模式 | 最终查询语句 |
|---------|---------|------------|
| Transmission | `^(?:Basic\|Digest) realm="Transmission"$` | `http.header="WWW-Authenticate: Basic realm=Transmission"` |
| TP-LINK Routers | `(?i)^(?:Basic\|Digest).*realm="TP-LINK (.*Router.*)"` | `http.header="WWW-Authenticate: Basic realm=TP-LINK Wireless N Router WR841N"` |
| PHP | `^PHP/([0-9.]+)$` | `http.header="X-Powered-By: PHP/"` |

### 2.3 ZoomEye 分页采集

对于每条指纹规则推导出的查询语句，通过 ZoomEye REST API（`POST /v2/search`）进行分页检索，采集策略如下：

- **查询编码**：将查询字符串 Base64 编码后作为 `qbase64` 参数提交，避免特殊字符转义问题；
- **检索字段**：仅请求 `header` 字段，降低传输开销；
- **分页策略**：每页 100 条，每条规则最多拉取 5 页（共 500 条候选），满足采集上限（100 条有效记录）后提前终止；
- **速率控制**：相邻规则间隔 1.5 秒，同一规则相邻页间隔 0.5 秒，防止触发 API 频率限制；
- **断点续传**：每条规则处理完毕后立即写入进度文件（`*_progress.json`），程序中断后可从断点恢复，无需重新采集。

### 2.4 正则后过滤

ZoomEye 全文检索属于宽泛匹配，返回结果中可能包含不满足原始指纹规则的记录（例如，搜索 `Basic realm=Transmission` 可能返回 realm 中包含该词的任意结果）。因此，对每条采集到的原始 HTTP 响应头执行以下过滤步骤：

1. **目标头部提取**：从完整响应头块中逐行扫描，提取所有与目标头部名称匹配的行值（大小写不敏感），支持一个响应中存在多个同名头部（如多条 `Set-Cookie`）；

2. **正则验证**：对提取出的每个头部值执行 `re.match(pattern, value, re.IGNORECASE)`，仅当至少有一个值通过验证时，才将该响应记录纳入数据集；

3. **匹配语义说明**：对于 `Set-Cookie` 类规则，其正则为前缀匹配模式（不含 `$` 锚点），使用 `re.match` 而非 `re.fullmatch`，正确反映"cookie 名称以指定前缀开头"的语义；对于 `WWW-Authenticate` 和 `X-Powered-By` 类规则，正则通常含 `$` 锚点，`re.match` 等价于全串匹配。

---

## 3. 数据集统计

### 3.1 原始采集规模

**表 2** 各头部类型采集结果统计

| 头部类型 | 规则总数 | 有效规则数 | 原始样本数（CSV）| 覆盖率 |
|---------|---------|----------|--------------|-------|
| `Server` | 449 | 108 | 10,109 | 24.1% |
| `Set-Cookie` | 84 | 73 | 6,211 | 86.9% |
| `WWW-Authenticate` | 79 | 67 | 5,667 | 84.8% |
| `X-Powered-By` | 1 | 1 | 100 | 100% |
| **合计** | **613** | **249** | **22,087** | **40.6%** |

> **覆盖率**定义为：在 ZoomEye 中检索到有效样本的规则数 / 该类型规则总数。`Set-Cookie` 与 `WWW-Authenticate` 覆盖率显著高于 `Server` 类型，原因在于认证头部与 Cookie 名称往往具有更强的字面量特征，检索词的区分度更高。

### 3.2 指令微调数据集格式

所有原始样本均转换为统一的指令微调（Instruction Fine-tuning）格式，与主流 LLM 对话训练数据规范保持一致：

```json
{
  "instruction": "将后续文本中的资产信息提取出正则表达式形式的指纹\n\n### 输入：\nHTTP/1.1 401 Unauthorized\nServer: Transmission\nWWW-Authenticate: Basic realm=\"Transmission\"\nContent-Type: text/html; charset=ISO-8859-1",
  "response": "^(?:Basic|Digest) realm=\"Transmission\"$"
}
```

- `instruction`：包含任务描述与原始 HTTP 响应头（含所有响应行），引导模型从完整上下文中提取目标头部的指纹特征；
- `response`：对应的正则表达式模式，作为训练的黄金标准输出。

### 3.3 最终数据集组织

**表 3** 发布数据集文件列表

| 文件 | 描述 | 样本数 |
|------|------|-------|
| `data/jsonl/all_http_fingerprints.jsonl` | 四类头部合并（**推荐**） | 22,087 |
| `data/jsonl/server_fingerprints.jsonl` | 仅 `Server` 头部 | 10,109 |
| `data/jsonl/cookies_fingerprints.jsonl` | 仅 `Set-Cookie` 头部 | 6,211 |
| `data/jsonl/wwwauth_fingerprints.jsonl` | 仅 `WWW-Authenticate` 头部 | 5,667 |
| `data/jsonl/xpoweredby_fingerprints.jsonl` | 仅 `X-Powered-By` 头部 | 100 |

---

## 4. 方法创新点总结

### 创新点一：先验规则引导的自动化标注流水线

本方法将现有人工维护的指纹规则库（XML 格式的正则规则）转化为自动化数据采集的"弱监督标注器"。规则库中的每条正则表达式同时充当两个角色：（1）作为查询词推导的知识来源，生成 ZoomEye 检索语句；（2）作为样本质量验证的过滤器，对采集到的候选样本执行正则验证。这种"规则即标注"的设计消除了人工逐条标注的需求，将规则数与数据规模的关系从 1:1 扩展到了平均 1:88.7。

### 创新点二：网络空间搜索引擎查询格式的系统性验证

本方法通过实验揭示了 ZoomEye v2 API 在 HTTP 头部检索上的有效查询格式。现有研究通常假设搜索引擎提供字段级专用查询接口（如 Shodan 的 `http.headers.set-cookie:`），但实验表明 ZoomEye 对 `Set-Cookie`、`WWW-Authenticate`、`X-Powered-By` 等头部的字段专用索引实际上为空，必须使用全文检索接口 `http.header="<Header-Name>: <value>"` 才能召回有效数据。这一发现具有普遍的工程参考价值。

### 创新点三：多级退化的查询词推导策略

为应对正则表达式复杂度各异的指纹规则（从纯字面量 `^Transmission$` 到含多层分组与量词的复杂模式），本方法设计了四级退化的查询词推导策略：字面量前缀提取 → 样例值解析 → 正则内语义提取 → 描述词回退。该策略在 249 条有效规则中实现了 100% 的查询语句生成覆盖，且无一条查询因语法错误返回 HTTP 400。

### 创新点四：多头部类型的联合采集与统一表示

现有公开 HTTP 指纹数据集通常仅关注 `Server` 头部，忽略了 `Set-Cookie`、`WWW-Authenticate`、`X-Powered-By` 等同样携带丰富软件特征的响应头。本数据集在统一的指令微调格式下整合了四类头部的指纹样本，使模型能够从完整的 HTTP 响应头块中联合学习多维度的指纹特征，提升对复杂场景（如隐藏 Server 头但暴露 Cookie 命名规律的服务）的识别能力。
