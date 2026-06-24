"""
经验自蒸馏模块 (Experience Self-Distillation)

在每次成功利用后自动将经验写入 Qdrant 经验库,
实现「成功→学习→复用」闭环.

工作流程:
  1. Worker 调用 distill_from_exploit(state, exploit_result, action_params)
  2. 构造经验 payload
  3. 调用 BGE 获取 embedding
  4. Upsert 到 Qdrant experience 集合
"""

import json
import uuid
import hashlib
import logging
import time
import urllib.request

logger = logging.getLogger(__name__)

BGE_URL = "http://yunjing-bge:8000/embed"
QDRANT_URL = "http://yunjing-qdrant:6333/collections/experience/points"
COLLECTION = "experience"


def _get_embedding(text: str) -> list:
    """通过 BGE 服务获取文本的 1024 维 embedding 向量."""
    req = urllib.request.Request(
        BGE_URL,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=30)
    data = json.loads(resp.read())
    return data["vector"]  # [float; 1024]


def _build_text(payload: dict) -> str:
    """构建用于 embedding 的文本字段."""
    target_name = payload.get("target", {})
    if isinstance(target_name, dict):
        target_name = target_name.get("name", str(target_name))
    parts = [
        f"[{payload.get('pattern_id', 'unknown')}].",
        f"假设: {payload.get('hypothesis', {}).get('name', '未知')}.",
        f"类型: {payload.get('target_type', 'unknown')}.",
        f"目标: {target_name}.",
    ]
    v = payload.get("verification", {})
    parts.append(f"验证: {json.dumps(v, ensure_ascii=False)}.")
    signals = payload.get("signals", [])
    parts.append(f"信号: {'; '.join(s.get('value','') for s in signals)}.")
    expl = payload.get("exploitation", [])
    parts.append(
        f"利用: {json.dumps(expl, ensure_ascii=False)}."
    )
    rp = payload.get("reasoning_path", [])
    parts.append(f"推理链: {' -> '.join(rp)}")
    return " ".join(parts)


def _generate_exp_id() -> str:
    """生成唯一经验 ID."""
    ts = int(time.time())
    suffix = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:6]
    return f"exp-{ts}-{suffix}"


def _resolve_target(target) -> str:
    """将 target 统一为字符串 IP/域名."""
    if isinstance(target, str):
        # 如果 target 包含协议头
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).hostname or target
        return target
    elif isinstance(target, dict):
        # 从 dict 中提取 name 或 ip 字段
        for key in ("ip", "host", "name", "target"):
            val = target.get(key)
            if val:
                return str(val)
        return str(target)
    return str(target)


def _get_sessions(exploit_result: dict) -> list:
    """从 exploit_result 提取 sessions 列表, 兼容各种键名."""
    for key in ("sessions_created", "sessions", "session_created", "sessions_list"):
        val = exploit_result.get(key, [])
        if val:
            return val if isinstance(val, list) else [val]
    return []


def distill_from_exploit(
    state: dict,
    exploit_result: dict,
    action_params: dict,
    target: str,
) -> dict:
    """
    从成功利用结果中萃取经验, 写入 Qdrant.

    Args:
        state: 当前扫描状态 (含 ports, services, credentials 等)
        exploit_result: exploit 动作的返回结果
        action_params: exploit 动作的参数
        target: 扫描目标 IP/域名

    Returns:
        写入 Qdrant 的 payload, 或 None 如果失败
    """
    target_str = _resolve_target(target)

    # --- 提取端口和服务信息 ---
    sessions = _get_sessions(exploit_result)
    
    # [Fix 3] 优先从 session 自身获取端口和类型
    session_port = 0
    session_type_name = "unknown"
    if sessions:
        s0 = sessions[0]
        session_port = s0.get("port", 0)
        st = s0.get("session_type", s0.get("type", ""))
        if isinstance(st, str):
            session_type_name = st
        elif hasattr(st, "value"):
            session_type_name = st.value
    
    # 端口: session.port > action_params > state.services
    port = session_port or 0
    if not port or port == 0:
        port = action_params.get("port", 0)
    if not port or port == 0:
        pl = action_params.get("ports", [])
        if pl:
            port = pl[0] if isinstance(pl, list) else int(pl)
    if not port or port == 0:
        for ps in sorted(state.get("services", {}).keys(), key=lambda x: int(x) if x.isdigit() else 9999):
            port = int(ps)
            break
    
    # 服务名: 优先从 session_type 推断
    if session_type_name in ("http", "php_webshell", "reverse_shell"):
        service_name = session_type_name
    elif session_type_name in ("ssh",):
        service_name = "ssh"
    elif session_type_name in ("smb_exec", "wmi_exec", "winrm"):
        service_name = session_type_name
    else:
        svc_info = state.get("services", {}).get(str(port), {})
        service_name = svc_info.get("name", svc_info.get("service", session_type_name))
        # 从 state.services 取第一个
        for p_str in sorted(state.get("services", {}).keys(), key=lambda x: int(x) if x.isdigit() else 9999):
            port = int(p_str)
            break

    # 获取服务信息
    svc_info = state.get("services", {}).get(str(port), {})
    service_name = svc_info.get("name", svc_info.get("service", "unknown"))
    product = svc_info.get("product", svc_info.get("version", ""))

    # 构建 method_label
    method_label = f"{service_name}/{port}" if port else service_name
    # 从凭据提取用户名
    cred_user = ""
    cred_pass = ""
    # 从 params 中取
    if action_params.get("username"):
        cred_user = action_params["username"]
        cred_pass = action_params.get("password", "")
    elif action_params.get("credentials"):
        creds = action_params["credentials"]
        if isinstance(creds, list) and creds:
            cred_user = creds[0].get("username", "")
            cred_pass = creds[0].get("password", "")
    # 从 state 中取
    if not cred_user:
        state_creds = state.get("credentials", [])
        if state_creds:
            c = state_creds[0]
            if isinstance(c, dict):
                cred_user = c.get("username", "")
                cred_pass = c.get("password", "")

    if cred_user:
        method_label += f" ({cred_user}/{cred_pass})"

    # --- 构建更易搜索的 source_text ---
    source_lines = [
        f"目标: {target_str}",
    ]
    if port:
        source_lines.append(f"端口: {port}")
    source_lines.append(f"服务: {service_name}")
    if product:
        source_lines.append(f"版本: {product}")
    if cred_user:
        source_lines.append(f"凭据: {cred_user}/{cred_pass}")
    if sessions:
        source_lines.append(f"Sessions: {len(sessions)}")
        for s in sessions[:3]:
            source_lines.append(f"  - {s.get('type','?')} {s.get('target','?')} user={s.get('username','?')}")
    source_text = "\n".join(source_lines)

    # --- 构建 payload ---
    payload = {
        "exp_id": _generate_exp_id(),
        "created_at": time.time(),
        "target": {
            "type": "ip",
            "name": target_str,
        },
        "hypothesis": {
            "name": f"{method_label} 利用@{target_str}",
            "pattern_id": f"{service_name}-exploit",
            "target": target_str,
            "confidence": 0.9,
        },
        "signals": [
            {"type": "port", "value": str(port), "reason": f"开放 {service_name} 端口 {port}"},
            {"type": "credential", "value": f"{cred_user}/{cred_pass}",
             "reason": f"凭据验证成功"},
        ],
        "reasoning_path": [
            "端口扫描",
            "服务识别",
            "漏洞扫描",
            "凭证测试",
            f"利用({method_label})",
            "成功",
        ],
        "verification": {
            "method": service_name,
            "payload": "",
            "expected": "",
            "actual": f"建立 {len(sessions)} 个 session",
            "confirmed": bool(sessions),
        },
        "exploitation": [
            {
                "action": f"{service_name} 利用 {method_label}",
                "result": "success",
                "success": True,
            }
        ],
        "success": True,
        "duration": exploit_result.get("elapsed", 0),
        "pattern_id": f"{service_name}-exploit",
        "target_type": target_str,
        "source_text": source_text,
        "text": "",  # will be filled below
    }
    payload["text"] = _build_text(payload)

    # --- 获取 embedding ---
    try:
        # 用 source_text 做 embedding，区分于 knowledge 的 text
        embed_text = source_text + "\n" + payload["text"]
        vector = _get_embedding(embed_text)
    except Exception as e:
        logger.warning("[经验蒸馏] BGE embedding 失败: %s", e)
        return None

    # --- 写入 Qdrant ---
    point_id = hash(payload["exp_id"]) & 0x7FFFFFFFFFFFFFFF  # positive int64
    qdrant_payload = {
        "points": [
            {
                "id": point_id,
                "vector": vector,
                "payload": payload,
            }
        ]
    }

    try:
        req = urllib.request.Request(
            QDRANT_URL + "?wait=true",
            data=json.dumps(qdrant_payload).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        if result.get("status") == "ok":
            logger.info("[经验蒸馏] ✅ 成功写入经验: %s %s", payload["exp_id"], method_label)
        else:
            logger.warning("[经验蒸馏] Qdrant 响应异常: %s", result)
        return payload
    except Exception as e:
        logger.warning("[经验蒸馏] Qdrant 写入失败: %s", e)
        return None

