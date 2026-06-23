"""云镜推理引擎 — 自学习引擎 v0.2

升级：从单步假设记录 → 海纳百川的案例库

核心新增能力：
1. **案例库(Case Base)** — 存储完整攻击链，支持按目标特征检索
2. **链模板(Chain Templates)** — 从多案例提炼通用攻击模式
3. **跨环境迁移(Cross-Env Transfer)** — 同种攻击模式在不同环境的成功率差异
4. **相似度检索** — 遇到新目标时，自动查找最相似的过往案例

设计理念：
- 河流湖泊终将汇入大海 — 每次渗透、每步推理、每个成功和失败，都是养分
- 从积累到质变 — 案例库累积到一定规模后，引擎将能自主组合攻击链
- 模型无关 — 数据独立于任何 LLM，可跨模型复用
"""
from __future__ import annotations
import json
import os
import time
import uuid
import logging
from collections import defaultdict
from typing import Optional, Any

from .models import AttackHypothesis, TargetPerception, HypothesisStatus

logger = logging.getLogger(__name__)

# ============================================================
# 常量
# ============================================================

# 通用攻击链类型 — 从实战中提炼
CHAIN_TYPES = {
    "web->container->host": "从 Web 打进容器 → 容器逃逸 → 宿主机控制",
    "web->rce->host": "从 Web RCE 直接到宿主机控制",
    "http->ssh->windows": "从 HTTP 文件泄露 → SSH 密钥 → Windows 主机控制",
    "ssh->sudo->pivot": "从 SSH 登录 → sudo 提权 → 跳板横向移动",
    "ssh->vmctrl->firewall": "从 SSH 到宿主机 → VM 控制 → 防火墙磁盘篡改",
    "ztna->postgres->creds": "从 ZTNA 探测 → PostgreSQL → 凭据获取",
    "container->escape->host": "容器逃逸 → 宿主机控制",
    "cred-reuse->lateral": "密码复用 → 内网横向移动",
    "browser-export->all": "浏览器密码导出 → 全平台凭据获取",
}

# 跨环境迁移的最低数据量阈值
MIN_TRANSFER_TRIALS = 2


class LearningEngine:
    """自学习引擎 v0.2 — 海纳百川版"""

    def __init__(self, storage_path: str = ""):
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(__file__), "learning_data.json"
        )
        self._data = self._load_or_init()
        logger.info(f"[自学习v2] 初始化: storage={self._storage_path}, "
                    f"实验={self._data['meta']['total_experiments']}, "
                    f"案例={self._data['meta'].get('total_chains', 0)}")

    # ============================================================
    # 数据持久化
    # ============================================================

    def _load_or_init(self) -> dict:
        """加载或初始化学习数据"""
        if os.path.exists(self._storage_path):
            try:
                with open(self._storage_path) as f:
                    data = json.load(f)
                    # 迁移旧数据到 v0.2 格式
                    if "case_base" not in data:
                        data = self._migrate_v01(data)
                    # 确保经验库字段存在（兼容旧数据）
                    if "experiences" not in data:
                        data["experiences"] = []
                    if "experience_index" not in data:
                        data["experience_index"] = {
                            "by_pattern": {},
                            "by_target_type": {},
                            "by_signal": {},
                            "by_result": {"success": [], "fail": []}
                        }
                    if "total_experiences" not in data.get("meta", {}):
                        if "meta" not in data:
                            data["meta"] = {}
                        data["meta"]["total_experiences"] = 0
                    return data
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"[自学习v2] 数据损坏，重新初始化: {e}")

        return self._fresh_data()

    @staticmethod
    def _fresh_data() -> dict:
        """返回全新数据结构"""
        now = time.time()
        return {
            # ---- 原有统计维度 ----
            "pattern_stats": {},
            "pattern_weights": {},
            "env_adaptation": {},
            "confidence_calibration": {},

            # ---- v0.2 新增：案例库 ----
            "case_base": {
                "chains": {},
                "chain_index": {
                    "by_port": {},
                    "by_service": {},
                    "by_chain_type": {},
                    "by_pattern": {},
                    "by_os": {},
                    "by_tag": {},
                },
                "chain_templates": {},
            },

            # ---- v0.2 新增：跨环境迁移 ----
            "cross_env_transfer": {
                "transferability": {},
                "last_updated": now,
            },

            # ---- v0.2 新增：经验记录（LLM RAG 可检索） ----
            "experiences": [],
            "experience_index": {
                "by_pattern": {},
                "by_target_type": {},
                "by_signal": {},
                "by_result": {"success": [], "fail": []}
            },

            # ---- 元数据 ----
            "meta": {
                "total_experiments": 0,
                "total_chains": 0,
                "total_experiences": 0,
                "created_at": now,
                "last_updated": now,
                "version": "0.2",
            }
        }

    def _migrate_v01(self, old_data: dict) -> dict:
        """从 v0.1 格式迁移到 v0.2"""
        logger.info("[自学习v2] 迁移旧数据 → v0.2")
        new = self._fresh_data()
        # 保留原有统计
        for key in ("pattern_stats", "pattern_weights", "env_adaptation", "confidence_calibration"):
            if key in old_data:
                new[key] = old_data[key]
        if "meta" in old_data:
            new["meta"]["total_experiments"] = old_data["meta"].get("total_experiments", 0)
            new["meta"]["created_at"] = old_data["meta"].get("created_at", time.time())
        return new

    def get_experience_count(self) -> int:
        """获取经验总数（兼容旧版调用）"""
        return len(self._data.get("experiences", self._data.get("experiments", [])))

    def _save(self):
        """持久化"""
        self._data["meta"]["last_updated"] = time.time()
        try:
            os.makedirs(os.path.dirname(self._storage_path) or ".", exist_ok=True)
            with open(self._storage_path, "w") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except IOError as e:
            logger.error(f"[自学习v2] 保存失败: {e}")

    # ============================================================
    # 单步假设记录（原有，兼容保持）
    # ============================================================

    def record_result(self, hypothesis: AttackHypothesis, success: bool,
                      target_type: str = "unknown"):
        """记录一次假设验证的结果"""
        pattern_id = self._infer_pattern_id(hypothesis)
        stats = self._data["pattern_stats"]
        if pattern_id not in stats:
            stats[pattern_id] = {}
        if target_type not in stats[pattern_id]:
            stats[pattern_id][target_type] = {"success": 0, "total": 0, "last_seen": 0}
        stats[pattern_id][target_type]["total"] += 1
        if success:
            stats[pattern_id][target_type]["success"] += 1
        stats[pattern_id][target_type]["last_seen"] = time.time()
        self._data["meta"]["total_experiments"] += 1
        self._update_weights(pattern_id, target_type)
        self._update_calibration(pattern_id)
        self._save()
        logger.info(f"[自学习v2] 记录: {hypothesis.name} "
                    f"{'✅' if success else '❌'} "
                    f"target={target_type} "
                    f"total={self._data['meta']['total_experiments']}")

    # ============================================================

    # ============================================================
    # 扫描回调记录（由 engine_api.py 调用）
    # ============================================================

    def record_scan_callback(self, task_id: str, target: str,
                             scan_type: str = "unknown",
                             findings: list = None,
                             status: str = "completed") -> int:
        """记录扫描回调结果"""
        from app.engine.models import AttackHypothesis, HypothesisStatus
        findings = findings or []
        success = status == "completed" and len(findings) > 0

        hypothesis = AttackHypothesis()
        hypothesis.name = f"扫描验证: {scan_type}@{target}"
        hypothesis.pattern_id = scan_type
        hypothesis.description = f"扫描任务 {task_id}: {scan_type} 对 {target}"
        hypothesis.source_confidence = 0.8 if success else 0.3
        hypothesis.status = HypothesisStatus.CONFIRMED if success else HypothesisStatus.PARTIAL
        hypothesis.impact = "high" if any(f.get("severity") in ("high", "critical") for f in findings) else "medium"
        hypothesis.env_hint = ""

        self.record_result(hypothesis, success, target_type=scan_type)

        vuln_count = len(findings)
        if vuln_count > 0:
            exp_hypothesis = { "name": hypothesis.name, "pattern_id": scan_type, "confidence": 0.8, "target": target }
            exp_target = {"host": target, "type": scan_type}
            exp_signals = []
            for f in findings:
                sig = {"type": f.get("type", "vulnerability"),
                       "name": f.get("name", f.get("title", "unknown")),
                       "severity": f.get("severity", "medium")}
                exp_signals.append(sig)

            self.record_experience(
                hypothesis=exp_hypothesis,
                target=exp_target,
                reasoning_path=[f"{scan_type} automated scan"],
                verification={"method": scan_type, "result": f"Found {vuln_count} issues"},
                signals=exp_signals,
                exploitation=[{"status": status, "findings": vuln_count}],
                success=success,
                duration=0.0,
            )

        logger.info(f"[扫描回调] {task_id}: {scan_type}@{target} -> "
                    f"{'✅' if success else '❌'} vulns={vuln_count}")
        return vuln_count


    # ★★★ 新增：完整攻击链记录 ★★★
    # ============================================================


    # ============================================================
    # 经验记录 — 每个扫描的详细记录（LLM RAG 可检索）
    # ============================================================

    def record_experience(self, hypothesis: dict, target: dict,
                          reasoning_path: list,
                          verification: dict,
                          signals: list,
                          exploitation: list,
                          success: bool,
                          duration: float = 0.0) -> str:
        """记录一次扫描经验的完整信息，供 LLM 作为 RAG 参考"""
        import uuid
        exp_id = f"exp-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        pattern_id = hypothesis.get("pattern_id", "unknown")

        entry = {
            "exp_id": exp_id,
            "created_at": time.time(),
            "target": target,
            "hypothesis": hypothesis,
            "signals": signals,
            "reasoning_path": reasoning_path,
            "verification": verification,
            "exploitation": exploitation,
            "success": success,
            "duration": duration,
            "pattern_id": pattern_id,
            "target_type": target.get("type", "unknown"),
        }

        self._data["experiences"].append(entry)

        # Update indexes
        idx = self._data["experience_index"]
        if pattern_id not in idx["by_pattern"]:
            idx["by_pattern"][pattern_id] = []
        idx["by_pattern"][pattern_id].append(exp_id)

        tt = target.get("type", "unknown")
        if tt not in idx["by_target_type"]:
            idx["by_target_type"][tt] = []
        idx["by_target_type"][tt].append(exp_id)

        for sig in signals:
            sk = sig.get("type", "unknown")
            if sk not in idx["by_signal"]:
                idx["by_signal"][sk] = []
            idx["by_signal"][sk].append(exp_id)

        rk = "success" if success else "fail"
        idx["by_result"][rk].append(exp_id)

        self._data["meta"]["total_experiences"] = len(self._data["experiences"])
        self._data["meta"]["last_updated"] = time.time()
        self._save()
        logger.info(f"[经验记录] {exp_id}: {pattern_id} -> success={success}")

        # auto index to Qdrant
        try:
            from app.engine.vector_store import RAGEngine
            rag = RAGEngine()
            rag.index_experience(self._data, force=False)
        except Exception as e:
            logger.debug(f"[learning] Qdrant sync skipped: {e}")

        return exp_id

    def search_experiences(self, pattern_id: str = None,
                           target_type: str = None,
                           signal_type: str = None,
                           limit: int = 5) -> list:
        """按条件检索过往经验，供 LLM 推理时参考"""
        idx = self._data["experience_index"]
        candidates = set()

        if pattern_id and pattern_id in idx["by_pattern"]:
            candidates.update(idx["by_pattern"][pattern_id])
        if target_type and target_type in idx["by_target_type"]:
            candidates.update(idx["by_target_type"][target_type])
        if signal_type and signal_type in idx["by_signal"]:
            candidates.update(idx["by_signal"][signal_type])

        if not candidates:
            candidates = {e["exp_id"] for e in self._data["experiences"] if e.get("exp_id")}

        exp_map = {e["exp_id"]: e for e in self._data["experiences"] if e.get("exp_id")}
        results = []
        for eid in candidates:
            entry = exp_map.get(eid)
            if not entry:
                continue
            if pattern_id and entry.get("pattern_id") != pattern_id:
                continue
            if target_type and entry.get("target_type") != target_type:
                continue
            results.append(entry)

        results.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return results[:limit]

    def search_experiences_semantic(self, query: str,
                                    top_k: int = 3) -> list:
        """使用 RAG 语义检索经验库"""
        try:
            from app.engine.vector_store import RAGEngine
            rag = RAGEngine()
            results = rag.search(query, top_k=top_k,
                                collections=["experience"])
            return results
        except Exception as e:
            logger.warning(f"[Learning] semantic search failed: {e}")
            return []

    def get_experience_summary(self, pattern_id: str = None,
                                target_type: str = None) -> dict:
        """获取经验的聚合统计摘要"""
        entries = self._data["experiences"]
        if pattern_id:
            entries = [e for e in entries if e.get("pattern_id") == pattern_id]
        if target_type:
            entries = [e for e in entries if e.get("target_type") == target_type]

        if not entries:
            return {"total": 0, "success_count": 0, "fail_count": 0, "success_rate": 0.0}

        success_count = sum(1 for e in entries if e.get("success"))
        fail_count = len(entries) - success_count
        return {
            "total": len(entries),
            "success_count": success_count,
            "fail_count": fail_count,
            "success_rate": round(success_count / len(entries), 2) if entries else 0.0,
        }


    def record_attack_chain(self, chain_id: str, title: str,
                            target: dict, steps: list[dict],
                            chain_type: str = "unknown",
                            tags: Optional[list[str]] = None,
                            source: str = "imported"):
        """记录一条完整的攻击链

        Args:
            chain_id: 唯一标识（如 "case-win10-full-breach"）
            title: 人类可读标题
            target: 目标特征字典，包含:
                - ip: str
                - os: str (optional)
                - ports: list[int] (optional)
                - services: list[str] (optional)
            steps: 步骤列表，每步包含:
                - step_id: str
                - name: str
                - pattern_id: str (假设类型)
                - success: bool
                - evidence: str (关键证据)
                - target_type: str (目标环境类型)
                - parent_step_id: Optional[str] (依赖的上一步)
            chain_type: 链类型 (如 "web->container->host")
            tags: 标签列表
            source: "manual" | "engine" | "imported"

        Returns:
            dict: 记录结果摘要
        """
        tags = tags or []

        # ---- Step 1: 构建链记录 ----
        now = time.time()
        steps_success = sum(1 for s in steps if s.get("success", False))
        total_steps = len(steps)
        overall_success = steps_success / total_steps if total_steps > 0 else 0.0

        chain_record = {
            "chain_id": chain_id,
            "title": title,
            "target": {
                "ip": target.get("ip", ""),
                "os": target.get("os", ""),
                "ports": target.get("ports", []),
                "services": target.get("services", []),
            },
            "steps": steps,
            "chain_type": chain_type,
            "tags": tags,
            "source": source,
            "total_steps": total_steps,
            "success_steps": steps_success,
            "overall_success": overall_success,
            "created_at": now,
        }

        # ---- Step 2: 存入案例库 ----
        cb = self._data["case_base"]
        cb["chains"][chain_id] = chain_record

        # ---- Step 3: 更新索引 ----
        idx = cb["chain_index"]

        # 按端口索引
        for port in target.get("ports", []):
            pkey = str(port)
            if pkey not in idx["by_port"]:
                idx["by_port"][pkey] = []
            if chain_id not in idx["by_port"][pkey]:
                idx["by_port"][pkey].append(chain_id)

        # 按服务索引
        for svc in target.get("services", []):
            skey = svc.lower()
            if skey not in idx["by_service"]:
                idx["by_service"][skey] = []
            if chain_id not in idx["by_service"][skey]:
                idx["by_service"][skey].append(chain_id)

        # 按链类型索引
        ctkey = chain_type
        if ctkey not in idx["by_chain_type"]:
            idx["by_chain_type"][ctkey] = []
        if chain_id not in idx["by_chain_type"][ctkey]:
            idx["by_chain_type"][ctkey].append(chain_id)

        # 按模式索引（每步的 pattern_id）
        for step in steps:
            pid = step.get("pattern_id", "")
            if pid:
                if pid not in idx["by_pattern"]:
                    idx["by_pattern"][pid] = []
                if chain_id not in idx["by_pattern"][pid]:
                    idx["by_pattern"][pid].append(chain_id)

        # 按OS索引
        os_name = target.get("os", "")
        if os_name:
            if os_name not in idx["by_os"]:
                idx["by_os"][os_name] = []
            if chain_id not in idx["by_os"][os_name]:
                idx["by_os"][os_name].append(chain_id)

        # 按标签索引
        for tag in tags:
            if tag not in idx["by_tag"]:
                idx["by_tag"][tag] = []
            if chain_id not in idx["by_tag"][tag]:
                idx["by_tag"][tag].append(chain_id)

        # ---- Step 4: 更新链模板统计 ----
        templates = cb["chain_templates"]
        if ctkey not in templates:
            templates[ctkey] = {
                "count": 0,
                "success_count": 0,
                "total_steps": 0,
                "success_steps": 0,
                "step_patterns": {},  # {step_index: {pattern_id: count}}
                "chain_name": CHAIN_TYPES.get(ctkey, ctkey),
            }
        tpl = templates[ctkey]
        tpl["count"] += 1
        if overall_success >= 0.5:
            tpl["success_count"] += 1
        tpl["total_steps"] += total_steps
        tpl["success_steps"] += steps_success

        # 更新步骤模式统计
        for i, step in enumerate(steps):
            pid = step.get("pattern_id", "unknown")
            sidx = f"step_{i}"
            if sidx not in tpl["step_patterns"]:
                tpl["step_patterns"][sidx] = {}
            if pid not in tpl["step_patterns"][sidx]:
                tpl["step_patterns"][sidx][pid] = 0
            tpl["step_patterns"][sidx][pid] += 1

        # ---- Step 5: 每步也作为单条实验记录（用于置信度计算） ----
        for step in steps:
            pid = step.get("pattern_id", "unknown")
            target_type = step.get("target_type", "unknown")
            success = step.get("success", False)
            # 直接操作 pattern_stats（不调 record_result 避免重复 _save）
            if pid not in self._data["pattern_stats"]:
                self._data["pattern_stats"][pid] = {}
            if target_type not in self._data["pattern_stats"][pid]:
                self._data["pattern_stats"][pid][target_type] = {"success": 0, "total": 0, "last_seen": 0}
            self._data["pattern_stats"][pid][target_type]["total"] += 1
            if success:
                self._data["pattern_stats"][pid][target_type]["success"] += 1
            self._data["pattern_stats"][pid][target_type]["last_seen"] = now
            self._data["meta"]["total_experiments"] += 1
            self._update_weights(pid, target_type)

        # ---- Step 6: 跨环境迁移学习 ----
        self._update_cross_env_transfer(steps, chain_type)

        # ---- Step 7: 更新元数据 ----
        self._data["meta"]["total_chains"] = len(cb["chains"])

        # ---- Step 8: 持久化 ----
        self._save()

        logger.info(f"[自学习v2] 🏆 案例入库: {title} | "
                    f"类型={chain_type} | 步骤={total_steps}({steps_success}成功) | "
                    f"目标={target.get('ip','')} | "
                    f"总案例={self._data['meta']['total_chains']} | "
                    f"总实验={self._data['meta']['total_experiments']}")

        return {
            "chain_id": chain_id,
            "success_rate": overall_success,
            "steps_recorded": total_steps,
            "experiments_added": total_steps,
        }

    def _update_cross_env_transfer(self, steps: list[dict], chain_type: str):
        """更新跨环境迁移矩阵

        如果同一个模式在不同环境都有成功记录，增加迁移率。
        """
        transfer = self._data["cross_env_transfer"]["transferability"]
        for step in steps:
            pid = step.get("pattern_id", "")
            ttype = step.get("target_type", "")
            success = step.get("success", False)
            if not pid or not ttype or not success:
                continue

            # 对于这个模式，查看它在其他环境的成功率
            # 如果当前成功 + 在其他环境也有成功 → 增加迁移率
            stats = self._data["pattern_stats"].get(pid, {})
            other_envs = [e for e in stats if e != ttype and stats[e]["total"] >= MIN_TRANSFER_TRIALS]

            if pid not in transfer:
                transfer[pid] = {}

            for other_env in other_envs:
                if other_env not in transfer[pid]:
                    transfer[pid][other_env] = {"success": 0, "total": 0}

                o_stats = stats[other_env]
                if o_stats["total"] >= MIN_TRANSFER_TRIALS:
                    rate = o_stats["success"] / o_stats["total"]
                    transfer[pid][other_env]["total"] += 1
                    if rate > 0.5:
                        transfer[pid][other_env]["success"] += 1

        self._data["cross_env_transfer"]["last_updated"] = time.time()

    # ============================================================
    # ★★★ 新增：案例检索 ★★★
    # ============================================================

    def search_similar_chains(self, target_features: dict,
                              top_k: int = 5) -> list[dict]:
        """检索最相似的过往案例

        Args:
            target_features: 目标特征字典，包含:
                - ports: list[int]
                - services: list[str]
                - os: str (optional)
                - tags: list[str] (optional)
            top_k: 返回 top-k

        Returns:
            [{"chain_id": str, "title": str, "chain_type": str,
              "overall_success": float, "match_score": float,
              "steps": [...], "tags": [...]}]
        """
        cb = self._data["case_base"]
        idx = cb["chain_index"]
        chains = cb["chains"]

        if not chains:
            return []

        # 计算每个案例的匹配分数
        scores = defaultdict(float)

        # 端口匹配 +2
        for port in target_features.get("ports", []):
            pkey = str(port)
            for cid in idx["by_port"].get(pkey, []):
                scores[cid] += 2.0

        # 服务匹配 +2
        for svc in target_features.get("services", []):
            skey = svc.lower()
            for cid in idx["by_service"].get(skey, []):
                scores[cid] += 2.0

        # OS 匹配 +3 (强特征)
        os_name = target_features.get("os", "")
        if os_name:
            for cid in idx["by_os"].get(os_name, []):
                scores[cid] += 3.0

        # 标签匹配 +1
        for tag in target_features.get("tags", []):
            for cid in idx["by_tag"].get(tag, []):
                scores[cid] += 1.0

        # 没有匹配时返回最近案例
        if not scores:
            recent = list(chains.keys())[-top_k:]
            return [chains[cid] for cid in recent]

        # 排序返回 top-k
        sorted_chains = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        results = []
        for cid, score in sorted_chains[:top_k]:
            chain = chains[cid]
            results.append({
                "chain_id": cid,
                "title": chain["title"],
                "chain_type": chain["chain_type"],
                "overall_success": chain["overall_success"],
                "match_score": round(score, 1),
                "total_steps": chain["total_steps"],
                "steps": chain["steps"],
                "target": chain["target"],
                "tags": chain["tags"],
            })

        return results

    def get_chain_templates(self, min_occurrences: int = 2) -> list[dict]:
        """获取通用攻击链模板

        Args:
            min_occurrences: 最少出现次数

        Returns:
            [{"chain_type": str, "name": str, "count": int,
              "success_rate": float, "avg_steps": float,
              "step_patterns": {step_index: top_patterns}}]
        """
        templates = self._data["case_base"]["chain_templates"]
        results = []

        for ctkey, tpl in templates.items():
            if tpl["count"] < min_occurrences:
                continue

            success_rate = tpl["success_count"] / tpl["count"] if tpl["count"] > 0 else 0
            avg_steps = tpl["total_steps"] / tpl["count"] if tpl["count"] > 0 else 0

            # 每步最常用的模式
            step_patterns = {}
            for sidx, patterns in tpl["step_patterns"].items():
                sorted_p = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
                step_patterns[sidx] = [
                    {"pattern_id": pid, "occurrences": cnt}
                    for pid, cnt in sorted_p[:3]
                ]

            results.append({
                "chain_type": ctkey,
                "name": tpl["chain_name"],
                "count": tpl["count"],
                "success_rate": round(success_rate, 3),
                "avg_steps": round(avg_steps, 1),
                "step_patterns": step_patterns,
            })

        results.sort(key=lambda x: x["count"], reverse=True)
        return results

    # ============================================================
    # ★★★ 新增：跨环境迁移查询 ★★★
    # ============================================================

    def get_transfer_rate(self, pattern_id: str,
                          from_env: str, to_env: str) -> float:
        """获取攻击模式从 from_env 到 to_env 的迁移成功率

        例如: ssh-key-leak 在 linux→windows 上是否也有效？

        Returns:
            迁移率 (0.0~1.0)，如果没有数据则返回 None
        """
        transfer = self._data["cross_env_transfer"]["transferability"]
        pid_data = transfer.get(pattern_id, {})
        env_data = pid_data.get(f"{from_env}→{to_env}", {})
        if env_data.get("total", 0) >= MIN_TRANSFER_TRIALS:
            return env_data["success"] / env_data["total"]
        return None

    def get_cross_env_hot_patterns(self, target_env: str, top_k: int = 5) -> list[dict]:
        """对目标环境最可能有效的迁移模式

        在目标环境本身数据不足时，从其他环境迁移最成功的模式。
        """
        transfer = self._data["cross_env_transfer"]["transferability"]
        candidates = []

        for pid, envs in transfer.items():
            for env_key, data in envs.items():
                if data["total"] >= MIN_TRANSFER_TRIALS and f"→{target_env}" in env_key:
                    rate = data["success"] / data["total"]
                    candidates.append({
                        "pattern_id": pid,
                        "transfer_rate": rate,
                        "trials": data["total"],
                        "from_env": env_key.split("→")[0],
                    })

        candidates.sort(key=lambda x: x["transfer_rate"], reverse=True)
        return candidates[:top_k]

    # ============================================================
    # 原有接口（保持兼容）
    # ============================================================


    def get_pattern_summary(self) -> dict:
        """获取模式统计摘要"""
        stats = self._data.get("pattern_stats", {})
        result = {}
        for pid, targets in stats.items():
            total_ok = sum(t.get("success", 0) for t in targets.values())
            total_all = sum(t.get("total", 0) for t in targets.values())
            if total_all > 0:
                result[pid] = {
                    "targets": len(targets),
                    "total": total_all,
                    "success": total_ok,
                    "rate": round(total_ok / total_all, 3),
                }
        return result
    def _infer_pattern_id(self, h: AttackHypothesis) -> str:
        if h.pattern_id:
            return h.pattern_id
        surface = h.source_attack_surface or ""
        if surface.startswith("llm-generated"):
            name_lower = h.name.lower()
            mapping = {
                "web": "web-injection", "injection": "web-injection",
                "xss": "web-injection", "csrf": "web-injection",
                "ssh": "ssh-breach", "redis": "redis-noauth",
                "mysql": "db-weak-cred", "postgres": "db-weak-cred",
                "database": "db-weak-cred",
                "smb": "smb-anonymous",
                "everything": "everything-http",
                "container": "container-escape",
                "docker": "container-escape",
                "ztna": "ztna-attack", "headscale": "ztna-attack",
                "browser": "browser-password",
                "keepass": "keepass-crack", "kdbx": "keepass-crack",
                "cred": "cred-reuse", "password": "cred-reuse",
                "firewall": "fw-management", "nsg": "fw-management",
                "sunlogin": "sunlogin-breach", "sun": "sunlogin-breach",
                "finalshell": "finalshell-config",
            }
            for keyword, pid in mapping.items():
                if keyword in name_lower:
                    return pid
            return "custom-llm"
        return surface.split("/")[-1].replace(".md", "")

    def _update_weights(self, pattern_id: str, target_type: str):
        stats = self._data["pattern_stats"].get(pattern_id, {}).get(target_type, {})
        total = stats.get("total", 0)
        success = stats.get("success", 0)
        if total < 3:
            return
        success_rate = success / total
        alpha = 0.1
        weights = self._data["pattern_weights"]
        key = f"{pattern_id}@{target_type}"
        old_w = weights.get(key, 0.5)
        new_w = old_w + alpha * (success_rate - old_w)
        weights[key] = round(max(0.0, min(1.0, new_w)), 4)
        env = self._data["env_adaptation"]
        if target_type not in env:
            env[target_type] = {}
        env[target_type][pattern_id] = round(success_rate, 3)

    def _update_calibration(self, pattern_id: str):
        pass

    def get_adjusted_confidence(self, hypothesis: AttackHypothesis,
                                target_type: str = "common") -> float:
        base = hypothesis.source_confidence
        pattern_id = self._infer_pattern_id(hypothesis)
        stats = self._data["pattern_stats"].get(pattern_id, {})
        best_rate = 0.5
        for tt, s in stats.items():
            if s["total"] >= 3:
                rate = s["success"] / s["total"]
                if rate > best_rate:
                    best_rate = rate
        weight_key = f"{pattern_id}@{target_type}"
        weight = self._data["pattern_weights"].get(weight_key, 0.5)
        adjusted = base * 0.6 + best_rate * 0.25 + weight * 0.15
        return round(min(1.0, adjusted), 4)

    def get_env_hot_patterns(self, target_type: str, top_k: int = 5) -> list[dict]:
        env = self._data["env_adaptation"].get(target_type, {})
        sorted_patterns = sorted(env.items(), key=lambda x: x[1], reverse=True)
        results = []
        for pid, rate in sorted_patterns[:top_k]:
            stats = self._data["pattern_stats"].get(pid, {}).get(target_type, {})
            name = self._resolve_pattern_name(pid)
            results.append({
                "pattern_id": pid,
                "name": name,
                "success_rate": rate,
                "trials": stats.get("total", 0),
            })
        return results

    def get_cold_patterns(self, target_type: str, min_trials: int = 3) -> list[dict]:
        env = self._data["env_adaptation"].get(target_type, {})
        cold = [
            (pid, rate) for pid, rate in env.items()
            if rate < 0.3
            and self._data["pattern_stats"].get(pid, {}).get(target_type, {}).get("total", 0) >= min_trials
        ]
        cold.sort(key=lambda x: x[1])
        results = []
        for pid, rate in cold[:5]:
            results.append({
                "pattern_id": pid,
                "name": self._resolve_pattern_name(pid),
                "success_rate": rate,
            })
        return results

    def get_summary(self) -> dict:
        data = self._data
        pattern_stats = data["pattern_stats"]
        cb = data["case_base"]

        total_experiments = data["meta"]["total_experiments"]
        total_chains = data["meta"]["total_chains"]
        total_patterns = len(pattern_stats)

        all_success = sum(
            s["success"]
            for pstats in pattern_stats.values()
            for s in pstats.values()
        )
        all_total = sum(
            s["total"]
            for pstats in pattern_stats.values()
            for s in pstats.values()
        )
        overall_rate = round(all_success / all_total, 3) if all_total > 0 else 0

        # 案例库统计
        chain_types = list(cb["chain_index"]["by_chain_type"].keys())
        template_count = len(cb["chain_templates"])

        return {
            "version": data["meta"]["version"],
            "total_experiments": total_experiments,
            "total_chains": total_chains,
            "total_patterns": total_patterns,
            "overall_success_rate": overall_rate,
            "environments_adapted": list(data["env_adaptation"].keys()),
            "chain_types_covered": chain_types,
            "chain_templates": template_count,
            "patterns_with_data": [
                {"pattern_id": pid, "environments": list(pstats.keys())}
                for pid, pstats in pattern_stats.items()
            ],
        }

    def reset(self):
        self._data = self._fresh_data()
        self._save()
        logger.info("[自学习v2] 数据已重置")

    # ============================================================
    # 工具方法
    # ============================================================

    @staticmethod
    def _resolve_pattern_name(pattern_id: str) -> str:
        try:
            from .knowledge import KnowledgeBaseEngine
            rule = KnowledgeBaseEngine.get_pattern_by_id(pattern_id)
            if rule:
                return rule.name
        except ImportError:
            pass
        return pattern_id

    def get_case(self, chain_id: str) -> Optional[dict]:
        """按 ID 获取单个案例"""
        return self._data["case_base"]["chains"].get(chain_id)

    def list_chains(self, chain_type: Optional[str] = None,
                    tag: Optional[str] = None,
                    limit: int = 20) -> list[dict]:
        """列出案例"""
        cb = self._data["case_base"]
        idx = cb["chain_index"]
        chains = cb["chains"]

        if chain_type:
            cids = idx["by_chain_type"].get(chain_type, [])
        elif tag:
            cids = idx["by_tag"].get(tag, [])
        else:
            cids = list(chains.keys())

        results = []
        for cid in cids[:limit]:
            c = chains[cid]
            results.append({
                "chain_id": cid,
                "title": c["title"],
                "chain_type": c["chain_type"],
                "overall_success": c["overall_success"],
                "total_steps": c["total_steps"],
                "target": c["target"],
                "tags": c["tags"],
                "source": c["source"],
            })

        results.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return results
