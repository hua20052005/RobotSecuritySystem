# PAPB 流程校验 —— 数据与逻辑说明

> 面向答辩 / 评审的说明文档。PAPB（Process-Aware Process Behavior，流程感知行为校验）模块用于
> 检测机器狗的**动作序列**是否符合正常运行流程，识别缺失、错序、非法分支、危险衔接等异常。

---

## 一、一句话定位

> PAPB 不分析原始流量信号，而是对上游识别出的**动作标签序列**（如 `stand → walk_slow → run_fast → …`）
> 做**流程合法性校验**：把它和已学习的「正常流程知识」逐项比对，给出
> **正常 / 容错正常 / 未知待审 / 异常** 四种判定，并解释异常发生在哪一步、为什么。

输入：一串动作标签（文本或 JSON）
输出：判定状态 + 流程图解释 + 逐项违规说明 + 可导出报告

---

## 二、PAPB 学习的数据（知识库）

PAPB 的「模型」是一个知识文件 [`papb_trained_model.json`](./papb_trained_model.json)，其内容**全部来自
`database_know/` 真实知识库**，不是随机/合成数据。共五类：

| 数据 | 字段 | 规模 | 作用 | 来源 |
|---|---|---|---|---|
| **正常流程模板** | `normal_templates` | 18 条 | 定义"合法完整流程"，主判定依据 | `normal_sequences.json` + `action_map.json` |
| **动作重复上限** | `max_repeats` | 13 个动作 | 限制单动作连续重复次数 | 从模板统计 |
| **关键动作** | `critical_actions` | `stand` | 缺失即异常的不可省动作 | 从模板统计 |
| **转移概率矩阵** | `transition_matrix` | 13 个动作 | 每步动作衔接的真实概率 | `transition_matrix.json` |
| **禁止转移规则** | `forbidden_transitions` | 4 条 | 明令禁止的危险衔接（硬约束） | `knowledge_base.json` |
| **风险阈值** | `transition_risk_threshold` | 0.15 | 转移风险判定阈值 | `recommended_detection_logic` |

### 2.1 动作字典（13 个动作）

来自 [`database_know/action_map.json`](./database_know/action_map.json)：

```
0 lie_down(趴下)   1 stand(站立)     2 walk_slow(慢走)   3 walk_mid(中速走)
4 run_fast(快跑)   5 backward(后退)  6 side_jump(侧跳)   7 forward_jump(前跳)
8 backflip(后空翻) 9 moonwalk(太空步) 10 dance2(舞蹈)    11 hello(打招呼)
12 twist_body(扭身)
```

### 2.2 正常流程模板（节选，共 18 条）

```
1.  lie_down → stand                                                （唤醒）
2.  stand → walk_slow → walk_slow → walk_mid → walk_slow → stand    （基础巡逻）
3.  stand → walk_slow → walk_mid → run_fast → walk_mid → walk_slow → stand （加速巡逻）
5.  stand → hello → twist_body → hello → stand                      （交互演示）
6.  stand → moonwalk → twist_body → dance2 → moonwalk → stand       （舞蹈表演）
9.  stand → twist_body → backflip → stand                           （特技）
18. lie_down → stand → walk_slow → … → backflip → stand → lie_down  （综合长流程）
```

### 2.3 禁止转移规则（4 条硬约束）

| 禁止衔接 | 含义 | 置信分 |
|---|---|---|
| `run_fast → lie_down` | 高速奔跑后直接趴下（机械冲击/失稳） | 0.99 |
| `lie_down → backflip` | 趴卧姿态直接后空翻（不可能/危险） | 0.98 |
| `forward_jump → run_fast` | 前跳落地未恢复就奔跑（失稳） | 0.95 |
| `backflip → backflip` | 连续后空翻（超出稳定能力） | 0.97 |

---

## 三、整体检测流程

```
┌─────────────────────────────────────────────────────────────────┐
│  输入：动作标签序列  例如 stand, walk_slow, run_fast, lie_down      │
└───────────────────────────────┬─────────────────────────────────┘
                                │  解析（支持逗号/箭头/换行/JSON）
                                ▼
        ┌───────────────────────────────────────────────┐
        │            四道关卡并行校验                       │
        ├───────────────────────────────────────────────┤
        │ ① 模板对齐关  —— 编辑距离对齐 18 条正常模板        │
        │ ② 硬/软违规关 —— 关键动作缺失、终止后多动作        │
        │ ③ 重复 & 任务图关 —— 重复超限、转移是否在任务图     │
        │ ④ 转移概率关  —— 马尔可夫风险评分 + 禁止规则硬判定   │
        └───────────────────────────────┬───────────────┘
                                        ▼
                ┌───────────────────────────────────┐
                │         综合判定 4 种状态            │
                │  NORMAL / NORMAL_WITH_TOLERANCE     │
                │  UNKNOWN_VALIDITY / ANOMALY         │
                └───────────────┬───────────────────┘
                                ▼
        ┌───────────────────────────────────────────────┐
        │ 输出：状态 + 流程图高亮 + 逐项违规 + 转移风险表    │
        │ 副作用：UNKNOWN 入待审池；结果存历史；可导出报告   │
        └───────────────────────────────────────────────┘
```

---

## 四、四道关卡详解

### 关卡 ① 模板对齐关（核心）

把输入序列与 18 条正常模板逐一做**编辑距离（Levenshtein）对齐**，找出最接近的模板，
并标出每个位置是 `match`（匹配）/ `substitute`（替换错误）/ `missing`（缺失）/ `extra`（多余）。

- `max_edit_distance = 1`：允许最多 1 处编辑偏差（容错）
- `is_exact`：编辑距离 = 0 → 完全命中某条模板
- 同时给出 Top-3 最接近模板（候选匹配），方便定位"它想做哪条流程"

### 关卡 ② 硬/软违规关

对关卡①找出的偏差区分严重程度：

- **硬违规（直接异常）**：
  - 缺失/错置了 `critical_actions`（关键动作 `stand`）
  - 在终止动作之后还出现多余动作
- **软违规（可容忍）**：涉及 `noncritical_actions`（非关键动作）的轻微偏差
- **容错正常**：编辑距离在容忍范围内，且所有偏差都是软违规 → `NORMAL_WITH_TOLERANCE`

### 关卡 ③ 重复 & 任务图关

- **重复校验**：按 `max_repeats` 检查单动作连续重复是否超限（如 `backflip` 连续 > 1 次 → 异常）
- **任务图合规**：把 18 条模板压成一张**有向转移图（邻接表）**，检查每个 `前→后` 衔接是否在图中出现过。
  这是判定 `UNKNOWN_VALIDITY` 的依据：没命中完整模板，但所有衔接都"见过" → 可能是合理新流程，转人工确认。

### 关卡 ④ 转移概率关（马尔可夫，本版本新接入）

基于真实 `transition_matrix` 和 `forbidden_transitions`，对每个相邻动作对 `a → b`：

- **禁止转移 → 硬判定异常**：命中 4 条禁止规则之一，直接 `ANOMALY`，并给出规则名与置信分
- **转移风险评分**：`risk = 1 − P(b | a)`，按转移概率分级，仅用于**解释展示**，不单独否决：

  | 概率 P(b\|a) | 等级 | 含义 |
  |---|---|---|
  | ≥ 0.25 | 正常 | 高频正常衔接 |
  | 0.10 ~ 0.25 | 偏低 | 较少见但合理 |
  | < 0.10 | 罕见 | 低频，值得关注 |
  | = 0（源动作有统计） | 未见过 | 正常数据从未出现 |
  | 命中禁止规则 | 禁止 | 硬约束违规 |

> 设计要点：`risk = 1 − p` 的绝对值对正常衔接也偏高（正常转移概率本就 < 0.85），
> 因此**只把"明令禁止"作为硬判定**，普通低概率仅作风险提示，避免误杀正常序列。

---

## 五、四种判定状态

| 状态 | 中文 | 触发条件 | 典型场景 |
|---|---|---|---|
| `NORMAL` | 正常 | 完全命中某条正常模板（编辑距离 0） | 标准巡逻流程 |
| `NORMAL_WITH_TOLERANCE` | 容错正常 | 在容忍范围内，偏差仅涉及非关键动作/轻微误差 | 少了一个无关紧要的动作 |
| `UNKNOWN_VALIDITY` | 未知待审 | 没命中完整模板，但无硬违规、无重复超限，且所有衔接在任务图中合法 | 可能是没学过的新合理流程 → 转人工 |
| `ANOMALY` | 异常 | 关键动作缺失 / 错误分支 / 终止后多动作 / 重复超限 / **禁止转移** | 危险或非法动作流程 |

---

## 六、典型用例（实测结果）

| 输入序列 | 判定 | 说明 |
|---|---|---|
| `stand → walk_slow → walk_mid → walk_slow → stand` | UNKNOWN_VALIDITY | 衔接都合法但非完整模板，转审核 |
| 完整模板精确匹配 | NORMAL | 四关全过 |
| `stand → walk_slow → run_fast → lie_down` | **ANOMALY** | 命中禁止规则 `run_fast→lie_down` |
| `stand → backflip → backflip` | **ANOMALY** | 命中禁止规则 `连续 backflip` |
| `stand → run_fast` | ANOMALY | `run_fast` 是 stand 的未见过转移 + 非完整流程 |

---

## 七、闭环学习机制（人工审核 → 模型更新）

PAPB 不是静态模型，支持**持续学习**：

```
检测出 UNKNOWN_VALIDITY
        │
        ▼
   自动进入待审核池  ──►  人工审核
                          ├─ 确认正常 → 加入训练序列 → 重新训练，下次即识别为 NORMAL
                          └─ 标记异常 → 记录为反例
```

- 新的正常流程可由人工"加入训练数据"后**重新训练**，模型自动重学模板、重复上限、关键动作。
- 重新训练时，转移矩阵、禁止规则、风险阈值等字段会被**完整保留**（序列化往返已验证）。

---

## 八、后端接口（FastAPI）

模块路径 [`backend/papb_api.py`](../../backend/papb_api.py)，前缀 `/api/papb`：

| 方法 | 路径 | 功能 |
|---|---|---|
| POST | `/detect` | 检测一条动作序列，返回完整判定 + 流程图 + 转移风险 |
| GET | `/summary` | 模型概览（模板数、训练序列数、待审数等） |
| GET | `/model` | 模型详情（模板、关键动作、重复上限等） |
| POST | `/training-sequences` | 追加正常训练序列 |
| POST | `/retrain` | 重新训练模型 |
| GET | `/review/pending` | 待审核池 |
| POST | `/review/{id}` | 提交审核结果（确认正常 / 标记异常） |

`/detect` 返回的关键字段：`status`、`violations`（逐项违规）、`template_match`（最佳模板对齐 +
四关明细）、`transition_check`（转移风险表）、`candidate_matches`（Top-3 候选模板）、`expected_next`（建议下一步）。

---

## 九、数据溯源总表

| 学习内容 | 来源文件 |
|---|---|
| 正常模板、重复上限、关键动作 | `database_know/normal_sequences.json`、`action_map.json` |
| 转移概率矩阵 | `database_know/transition_matrix.json` |
| 禁止规则、风险阈值 | `database_know/knowledge_base.json` |
| 当前生效模型 | `motion/motion/papb_trained_model.json` |
| 校验逻辑实现 | `motion/motion/papb_validator.py` |

---

## 十、答辩话术（30 秒版）

> PAPB 是流程层的安全校验：它学习机器狗的正常动作流程知识——18 条正常流程模板、动作转移概率矩阵、
> 以及 4 条硬性安全禁令，全部来自真实知识库。检测时通过**四道关卡**——模板编辑距离对齐、关键动作与
> 终止合规、重复与任务图合法性、马尔可夫转移概率校验——综合判定为正常、容错正常、待审或异常。
> 对于明令禁止的危险衔接（如急停后趴下、连续后空翻）直接判异常；对未学过但合理的新流程转人工审核，
> 审核通过后可重新训练纳入模型，形成检测—审核—学习的闭环。

> 说明：模型中保留了「嵌入向量校验」的可选接口，但当前输入为纯动作标签、无逐动作信号特征，
> 故第④关采用**马尔可夫转移概率校验**落地，既贴合知识库真实数据，也适配标签级输入。
