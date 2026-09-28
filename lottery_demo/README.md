# 链证摇号：公平可验证摇号原型

这是根据《基于默克尔树与区块链的公平可验证摇号系统》方案实现的可运行教学原型。它覆盖：

- 摇号批次和不可变规则哈希；
- 参与者报名、随机盐、SM3数据承诺和JSON回执；
- `REGISTRATION → CLOSED → FROZEN → RANDOM_READY → DRAWN` 状态机；
- 按唯一摇号编号排序的SM3默克尔树、空叶子补齐和成员证明；
- 冻结名单后产生的Ed25519签名演示随机信标；
- `SM3(seed || 唯一摇号编号)`独立评分、公开排序和中签结果；
- 可审计的追加式哈希链账本；
- 全局前序哈希与批次业务前序哈希组成的多区块证据链；
- 从创世块到审计块的区块浏览器、JSON导出和篡改检测；
- 参与者验证、完整批次审计和机器可读JSON审计接口。
- 128名参与者、12800轮摇号的可复现概率实验与逐人CSV统计。

## 1. 快速运行

需要 Python 3.10 或更高版本，并且系统 OpenSSL 支持 SM3（多数现代Python发行版已支持）。

### Windows PowerShell

```powershell
cd lottery_demo
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python seed_demo.py
python app.py
```

### macOS / Linux

```bash
cd lottery_demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python seed_demo.py
python app.py
```

浏览器打开：<http://127.0.0.1:5000>

区块浏览器：<http://127.0.0.1:5000/chain>

交付包已经附带生成好的128人示例链，可直接运行：

```bash
python view_multiblock_demo.py
```

然后访问 <http://127.0.0.1:5000/chain>，即可查看263个区块及其前序哈希。

`seed_demo.py` 会在空数据库中生成一个已经完成摇号的6人示例。也可以跳过它，从网页手工创建批次。

### 生成128人多区块证据链

```bash
python seed_multiblock_demo.py
```

该脚本会形成：创世块、规则块、128个报名块、128个审核块、关闭块、
冻结块、随机信标块、结果块和审计块，共263个首尾相连的区块。结果保存在：

```text
multiblock_output/multiblock_chain.sqlite3
multiblock_output/chain_export.json
```

如果需要重新生成，请指定新的输出目录，避免覆盖已有证据链：

```bash
python seed_multiblock_demo.py --output multiblock_output_2
```

### 直接运行128人概率实验

Windows可双击 `run_probability_test.bat`，macOS/Linux运行：

```bash
chmod +x run_probability_test.sh
./run_probability_test.sh
```

也可以直接执行：

```bash
python probability_simulation.py --participants 128 --runs 12800 --winners 1
```

默认每轮抽取1人。每个人的理论中签概率为 `1/128 = 0.78125%`，
12800轮中的理论中签次数为100次。程序会生成逐人统计CSV、实验汇总JSON和
128人公开承诺数据。固定参数重复执行时，逐人中签次数和复现摘要完全一致。

## 2. 手工演示顺序

1. 创建批次并设置中签人数、预定信标轮次。
2. 登记至少与中签人数相等的参与者。
3. 对所有参与者点击“通过”或“拒绝”。
4. 点击“关闭报名”，批次进入 `CLOSED`。
5. 确保没有待审核记录，再点击“冻结名单”。
6. 点击“产生演示信标”。名单冻结后才允许产生随机数。
7. 点击“执行摇号”。
8. 打开“公开审计”或任一参与者的“验证”页面。

## 3. 核心公式

数据承诺：

```text
Ci = SM3(0x10 || "DATA-V1" || batchID || Encode(Di) || salti)
```

真实叶子、空叶子和内部节点：

```text
Li     = SM3(0x00 || batchID || LotteryNoi || Ci)
Emptyj = SM3(0x02 || batchID || j)
Parent = SM3(0x01 || Left || Right)
```

最终种子和个人随机分值：

```text
S      = SM3(0x20 || "LOTTERY-SEED-V1" || batchID || Root || round || B || RuleHash)
Scorei = SM3(0x30 || "LOTTERY-SCORE-V1" || batchID || S || LotteryNoi)
```

所有可变长度字段都使用4字节大端长度前缀，避免字符串直接拼接产生歧义。

## 4. 项目结构

```text
lottery_demo/
├── app.py                 Flask应用和完整业务流程
├── crypto_utils.py        SM3、承诺、默克尔树、种子与分值
├── beacon.py              可公开验证的本地签名演示信标
├── database.py            SQLite模式与连接
├── ledger.py              追加式哈希链账本
├── seed_demo.py           一键生成演示数据
├── seed_multiblock_demo.py 生成128人、263区块的完整证据链
├── view_multiblock_demo.py  直接查看附带的多区块示例链
├── probability_simulation.py  128人、12800轮概率实验
├── run_probability_test.bat   Windows一键实验
├── run_probability_test.sh    macOS/Linux一键实验
├── templates/             中文Web界面
├── static/style.css       界面样式
└── tests/test_core.py     核心算法和端到端测试
```

## 5. 测试

```bash
python -m unittest discover -s tests -v
```

测试包括：

- SM3标准测试向量；
- 默克尔成员证明及篡改检测；
- 从创建批次到公开审计的完整Web流程。
- 概率实验统计恒等式和相同主种子的完全可复现性。
- 全局区块链接、批次业务链接及区块体篡改检测。

## 6. 多区块链结构

V2区块哈希覆盖以下字段：

```text
BlockHash = SM3(
  height || previous_hash || batch_id || stage || tx_type ||
  data_hash || state_hash || business_previous_hash || timestamp
)
```

- `previous_hash`：指向全局上一个区块，保证所有批次交易的唯一顺序；
- `business_previous_hash`：指向同一摇号批次的上一个区块；
- `data_hash`：当前区块体的SM3摘要；
- `state_hash`：当前批次公开状态快照的SM3摘要。

修改任何历史区块后，当前区块摘要或后续区块前序哈希都会验证失败。

概率实验输出位于 `output/`：

- `participant_probabilities.csv`：128人的中签次数、实验概率、理论概率、偏差和Z分数；
- `simulation_summary.json`：实验参数、默克尔根、规则哈希、统计量和复现摘要；
- `participants_128.json`：128人的摇号编号、数据承诺和默克尔叶子哈希。

## 7. 数据位置

- SQLite数据库：`instance/lottery.sqlite3`
- 本地演示信标私钥：`instance/demo_beacon_ed25519.key`
- 冻结后的脱敏名单：`data/manifests/`

这些运行数据不会包含在交付包的初始版本中。报名真实资料只保存在本地SQLite，公开名单只包含摇号编号、承诺值和叶子哈希。

## 8. 安全边界

本项目是一个教学和竞赛原型，不应直接用于真实购房、购车等高价值摇号：

- `ledger_blocks` 是SQLite上的哈希链账本，用于展示链上数据结构和篡改检测，不是真正部署的联盟链。
- 本地随机信标使用单个Ed25519私钥签名，只能证明输出真实性和完整性，不具备门限随机信标的抗单点操纵性质。
- 原型没有登录、权限隔离、硬件密钥、网络节点共识、密钥轮换和监管接口。
- 它能验证登记数据和算法计算的一致性，不能单独证明线下资格审核真实或一人只有一个现实身份。

生产化时建议：

1. 将哈希链账本适配到Hyperledger Fabric等多机构联盟链；
2. 将演示信标替换为预先指定轮次并完成签名验证的公开门限随机信标；
3. 为主管、审核、公证和审计机构配置独立身份与背书策略；
4. 将个人原始资料放入受控私有数据库或私有数据集合；
5. 进行密码合规、隐私影响、并发性能和第三方安全测评。
