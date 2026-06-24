import {useState, useEffect, useRef, useCallback} from "react";
import {useNavigate} from "react-router-dom";
import {
  Row, Col, Typography, Tag, Table, Space, Timeline, Tooltip,
  Progress, Spin, Badge, Button, Segmented
} from "antd";

import request from "../api/request";
import BugIcon from "../components/BugIcon";
import {
  SafetyOutlined, FileTextOutlined, AlertOutlined,
  ArrowUpOutlined, ArrowDownOutlined, CheckCircleOutlined,
  SyncOutlined, UnorderedListOutlined, RadarChartOutlined,
  RiseOutlined, RightOutlined, ClockCircleOutlined,
  WarningOutlined, AimOutlined, MessageOutlined,
  SettingOutlined, BugOutlined
} from "@ant-design/icons";

import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip as RTooltip, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";

const {Title, Text} = Typography;

const C = {
  primary: "#0284c7", primaryLight: "#38bdf8",
  success: "#16a34a", warning: "#d97706",
  danger: "#dc2626", purple: "#7c3aed",
  dark: "#1e293b", slate: "#64748b",
};

// ─── Animated Number ───
function AnimatedNumber({value, duration = 1500}: {value: number; duration?: number}) {
  const [display, setDisplay] = useState(0);
  const raf = useRef(0);

  useEffect(() => {
    const start = performance.now();
    const diff = value - display;
    if (diff === 0) return;
    const animate = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(display + diff * eased));
      if (t < 1) raf.current = requestAnimationFrame(animate);
    };
    raf.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf.current);
  }, [value, duration]);

  return (
    <span style={{fontWeight: 700, fontSize: 28, lineHeight: 1.2, color: C.dark, fontVariantNumeric: "tabular-nums"}}>
      {display.toLocaleString()}
    </span>
  );
}

// ─── Stat Card ───
function StatCard({label, value, icon, color, trend, onClick}: {
  label: string; value: number; icon: React.ReactNode; color: string;
  trend?: {dir: "up"|"down"; text: string}; onClick?: () => void;
}) {
  return (
    <div onClick={onClick}
      style={{
        background: "#fff", borderRadius: 12, padding: "20px 24px",
        border: "1px solid #e2e8f0", borderLeft: `4px solid ${color}`,
        cursor: onClick ? "pointer" : "default",
        boxShadow: "0 1px 3px rgba(0,0,0,0.04)", position: "relative", overflow: "hidden",
      }}
      className="dashboard-stat-card"
    >
      <div className="stat-value" style={{display: "flex", justifyContent: "space-between", alignItems: "flex-start", position: "relative", zIndex: 1}}>
        <div>
          <Text style={{fontSize: 13, color: "#64748b", marginBottom: 8, display: "block"}}>{label}</Text>
          <AnimatedNumber value={value} />
          {trend && (
            <div style={{marginTop: 6, display: "flex", alignItems: "center", gap: 4}}>
              {trend.dir === "up" ? <ArrowUpOutlined style={{fontSize: 12, color: C.success}} /> : <ArrowDownOutlined style={{fontSize: 12, color: C.danger}} />}
              <Text style={{fontSize: 12, color: trend.dir === "up" ? C.success : C.danger}}>{trend.text}</Text>
            </div>
          )}
        </div>
        <div style={{
          width: 46, height: 46, borderRadius: 12,
          background: `linear-gradient(135deg, ${color}15, ${color}08)`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 22, color, flexShrink: 0,
        }}>
          {icon}
        </div>
      </div>
    </div>
  );
}

// ─── Phase Flow ───
const PHASE_DEFS = [
  {key: "recon", label: "信息收集", icon: "🔍", color: "#3b82f6"},
  {key: "scan", label: "扫描检测", icon: "📡", color: "#22c55e"},
  {key: "exploit", label: "漏洞利用", icon: "💥", color: "#ef4444"},
  {key: "post", label: "后渗透", icon: "🎯", color: "#a855f7"},
  {key: "report", label: "报告生成", icon: "📋", color: "#eab308"},
];

function PhaseFlow({phaseData}: {phaseData: Record<string, {count: number; pct: number}>}) {
  return (
    <div style={{display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 0"}}>
      {PHASE_DEFS.map((p, i) => (
        <div key={p.key} style={{display: "flex", alignItems: "center", flex: 1, gap: 0}}>
          <Tooltip title={<div><strong>{p.label}</strong><br/>执行: {phaseData[p.key]?.count || 0} 次</div>}>
            <div style={{display: "flex", flexDirection: "column", alignItems: "center", gap: 6, cursor: "pointer", flex: 1}}>
              <div style={{
                width: 44, height: 44, borderRadius: 22,
                background: `linear-gradient(135deg, ${p.color}, ${p.color}cc)`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 18, color: "#fff",
                boxShadow: `0 4px 12px ${p.color}40`,
                transition: "all 0.3s ease",
              }}
                onMouseEnter={e => {e.currentTarget.style.transform = "scale(1.15)"; e.currentTarget.style.boxShadow = `0 6px 20px ${p.color}60`;}}
                onMouseLeave={e => {e.currentTarget.style.transform = "scale(1)"; e.currentTarget.style.boxShadow = `0 4px 12px ${p.color}40`;}}
              >
                <span>{p.icon}</span>
              </div>
              <Text style={{fontSize: 12, fontWeight: 500, color: "#475569"}}>{p.label}</Text>
              <div style={{
                width: 28, height: 28, borderRadius: 14, fontSize: 11, fontWeight: 600,
                border: `2px solid ${p.color}30`, color: p.color,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: `${p.color}08`,
              }}>
                {phaseData[p.key]?.count || 0}
              </div>
            </div>
          </Tooltip>
          {i < PHASE_DEFS.length - 1 && (
            <div style={{
              flex: 1, height: 2,
              background: `linear-gradient(90deg, ${p.color}60, ${PHASE_DEFS[i+1].color}60)`,
              margin: "0 4px 50px 4px", borderRadius: 1,
            }}/>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Trend Chart ───
function TrendChart({data}: {data: {name: string; value: number}[]}) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{top: 10, right: 10, left: -20, bottom: 0}}>
        <defs>
          <linearGradient id="vulnGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={C.primary} stopOpacity={0.25}/>
            <stop offset="95%" stopColor={C.primary} stopOpacity={0.02}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false}/>
        <XAxis dataKey="name" tick={{fontSize: 11, fill: "#94a3b8"}} axisLine={false} tickLine={false}/>
        <YAxis tick={{fontSize: 11, fill: "#94a3b8"}} axisLine={false} tickLine={false}/>
        <RTooltip contentStyle={{background: "#fff", borderRadius: 8, border: "1px solid #e2e8f0", boxShadow: "0 4px 12px rgba(0,0,0,0.08)", fontSize: 12}}/>
        <Area type="monotone" dataKey="value" stroke={C.primary} strokeWidth={2} fill="url(#vulnGrad)"
          dot={{r: 3, fill: C.primary, stroke: "#fff", strokeWidth: 2}}
          activeDot={{r: 5, fill: C.primary, stroke: "#fff", strokeWidth: 2}}/>
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ─── Pie Chart ───
function RiskPie({data}: {data: {name: string; value: number; color: string}[]}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <div style={{display: "flex", alignItems: "center", justifyContent: "center", gap: 24}}>
      <div style={{position: "relative", width: 150, height: 150, flexShrink: 0}}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={44} outerRadius={66}
              paddingAngle={3} dataKey="value" stroke="none">
              {data.map((d, i) => <Cell key={i} fill={d.color}/>)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div style={{position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", textAlign: "center"}}>
          <Text style={{fontSize: 22, fontWeight: 700, color: C.dark, display: "block"}}>{total}</Text>
          <Text style={{fontSize: 11, color: "#94a3b8"}}>总计</Text>
        </div>
      </div>
      <div>
        {data.map(d => (
          <div key={d.name} style={{display: "flex", alignItems: "center", gap: 8, marginBottom: 4}}>
            <div style={{width: 8, height: 8, borderRadius: 4, background: d.color, flexShrink: 0}}/>
            <Text style={{fontSize: 12, color: "#475569", minWidth: 40}}>{d.name}</Text>
            <Text style={{fontSize: 12, fontWeight: 600, color: C.dark, minWidth: 30}}>{d.value}</Text>
            <Text style={{fontSize: 11, color: "#94a3b8"}}>
              ({total > 0 ? ((d.value / total) * 100).toFixed(1) : 0}%)
            </Text>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Quick Actions ───
const QUICK_ACTIONS = [
  {key:"chat", label:"智能渗透", desc:"AI驱动渗透测试", icon:<MessageOutlined/>, color:C.primary, path:"/chat"},
  {key:"tasks", label:"扫描任务", desc:"查看所有任务", icon:<UnorderedListOutlined/>, color:C.purple, path:"/tasks"},
  {key:"reports", label:"检测报告", desc:"PDF/Word/HTML", icon:<FileTextOutlined/>, color:C.danger, path:"/reports"},
  {key:"perception", label:"资产感知", desc:"动态资产发现", icon:<RadarChartOutlined/>, color:C.warning, path:"/perception"},
  {key:"engine", label:"推理引擎", desc:"引擎配置管理", icon:<BugOutlined/>, color:"#0369a1", path:"/engine"},
  {key:"settings", label:"系统设置", desc:"通用配置管理", icon:<SettingOutlined/>, color:C.slate, path:"/settings"},
];

export default function DashboardPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({total: 0, completed: 0, vulnerabilities: 0, high_risk: 0, targets: 0, running: 0});
  const [recentTasks, setRecentTasks] = useState<any[]>([]);
  const [phaseData, setPhaseData] = useState<Record<string,{count:number; pct:number}>>({});
  const [timeline, setTimeline] = useState<any[]>([]);
 const [attackChain, setAttackChain] = useState<any>(null);
 const [topology, setTopology] = useState<any>(null);
  const [timeRange, setTimeRange] = useState("week");
  const [trendData, setTrendData] = useState<{name:string; value:number}[]>([]);
  const [riskData, setRiskData] = useState<{name:string; value:number; color:string}[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [engRes, dashRes, tasksRes, kbRes, learnRes, chainRes, topoRes] = await Promise.all([
        request.get("/engine/state?target=").catch(() => null),
        request.get("/dashboard/stats").catch(() => null),
<<<<<<< HEAD
        request.get("/tasks?page=1&page_size=6").catch(() => null),
=======
        request.get("/tasks?offset=0&limit=6").catch(() => null),
>>>>>>> server/master
        request.get("/engine/kb-stats").catch(() => null),
        request.get("/engine/learning-stats").catch(() => null),
        request.get("/dashboard/attack-chain").catch(() => null),
        request.get("/dashboard/topology").catch(() => null),
      ]);

      const newStats: any = {};
      const engData = engRes?.data;
      if (engData?.status === 'ok' && engData?.experience) {
        newStats.experience_total = engData.experience.total || 0;
        if (engData.experience.patterns) {
          newStats.pattern_count = Object.keys(engData.experience.patterns).length;
        }
      }

      const dashData = dashRes?.data;
      if (dashData) {
        const ts = dashData.task_stats;
        if (ts) {
          newStats.total = ts.total || 0;
          newStats.completed = ts.completed || 0;
          newStats.running = ts.running || 0;
          newStats.failed = ts.failed || 0;
          newStats.pending = ts.pending || 0;
          newStats.targets = ts.unique_targets || 0;
        }
        const vs = dashData.vuln_stats;
        if (vs) {
          newStats.vulnerabilities = vs.total || 0;
          newStats.high_risk = (vs.critical || 0) + (vs.high || 0);
        }
        if (dashData.risk_distribution) {
          setRiskData(dashData.risk_distribution.map((r: any) => ({
            name: r.name, value: r.count || r.value, color: r.color
          })));
        } else if (vs) {
          setRiskData([
            {name:"严重", value:vs.critical || 0, color:"#dc2626"},
            {name:"高危", value:vs.high || 0, color:"#ea580c"},
            {name:"中危", value:vs.medium || 0, color:"#d97706"},
            {name:"低危", value:vs.low || 0, color:"#16a34a"},
            {name:"信息", value:vs.info || 0, color:"#0284c7"},
          ]);
        }
        if (dashData.phase_progress) {
          const pd: Record<string, {count:number; pct:number}> = {};
          const phaseKeys = Object.keys(dashData.phase_progress);
          const totalPhases = phaseKeys.reduce((s:number, k:string) => s + (dashData.phase_progress[k]?.total || 0), 0);
          phaseKeys.forEach((k:string) => {
            const p = dashData.phase_progress[k];
            pd[k] = {
              count: p?.completed || 0,
              pct: totalPhases > 0 ? Math.round(((p?.completed || 0) / totalPhases) * 100) : 0
            };
          });
          setPhaseData(pd);
        }
        if (dashData.trend) {
          setTrendData(dashData.trend.map((t: any) => ({name: t.date || t.name, value: t.count || t.value || 0})));
        }
        if (dashData.timeline) {
          setTimeline(dashData.timeline);
        }
      }

      if (chainRes?.data) {
        setAttackChain(chainRes.data);
      }
      if (topoRes?.data) {
        setTopology(topoRes.data);
      }
      if (kbRes?.data?.stats) {
        const kbs = kbRes.data.stats;
        newStats.kb_sections = kbs.sections || 0;
        if (!newStats.targets) newStats.targets = kbs.attack_surface_entries || 0;
      }

      if (learnRes?.data?.stats) {
        newStats.experience_total = Math.max(newStats.experience_total || 0, learnRes.data.stats.total_experiences || 0);
        newStats.learning_rate = learnRes.data.stats.overall_success_rate || 0;
      }

      if (Object.keys(newStats).length > 0) {
        setStats(s => ({...s, ...newStats}));
      }

      if (tasksRes?.data) {
        const taskItems = tasksRes.data.items || tasksRes.data;
        if (Array.isArray(taskItems)) {
          setRecentTasks(taskItems.slice(0, 6));
          if (!trendData || trendData.length === 0) {
            const now = new Date();
            const days = timeRange === "week" ? 7 : timeRange === "month" ? 30 : 12;
            const td: {name:string; value:number}[] = [];
            for (let i = days - 1; i >= 0; i--) {
              const d = new Date(now); d.setDate(d.getDate() - i);
              const dayStr = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
              const dayTasks = taskItems.filter((t: any) => {
                const created = t.created_at || t.created || t.start_time;
                return created && created.startsWith(dayStr);
              });
              td.push({
                name: `${d.getMonth() + 1}/${d.getDate()}`,
                value: dayTasks.length
              });
            }
            setTrendData(td);
          }
        }
      }

      if (!phaseData || Object.keys(phaseData).length === 0) {
        setPhaseData({
          recon: {count: 0, pct: 0},
          scan: {count: 0, pct: 0},
          exploit: {count: 0, pct: 0},
          post: {count: 0, pct: 0},
          report: {count: 0, pct: 0},
        });
      }
    } catch (e) {
      console.error("Dashboard fetch error:", e);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData, autoRefresh]);

  const taskColumns = [
    {title: "目标", dataIndex: "target", key:"target",
      render: (v:string) => <Text style={{fontFamily:"'JetBrains Mono',monospace", fontSize:12, color: C.primary}}>{v || "-"}</Text>},
    {title: "类型", dataIndex: "scan_type", key:"type", width:90,
      render: (v:string) => <Tag color="blue" style={{fontSize:11, borderRadius:4}}>{v || "auto"}</Tag>},
    {title: "状态", dataIndex: "status", key:"status", width:90,
      render: (v:string) => {
        const m: Record<string, any> = {running: {status:"processing", text:"运行中"}, completed: {status:"success", text:"已完成"}, failed: {status:"error", text:"失败"}, pending: {status:"warning", text:"等待中"}};
        const c = m[v] || {status:"default", text:v};
        return <Badge status={c.status} text={<Text style={{fontSize:12}}>{c.text}</Text>}/>;
      }},
    {title: "漏洞", dataIndex: "vulnerabilities", key:"vulns", width:80,
      render: (_:any, r:any) => {
        const c = (r.vulnerabilities || r.vuln_count || 0);
        return c > 0 ? <Tag color={c > 5 ? "error" : c > 2 ? "warning" : "default"} style={{fontSize:11,borderRadius:4}}>{c} 个</Tag> : <Text style={{fontSize:12,color:"#94a3b8"}}>-</Text>;
      }},
    {title: "进度", dataIndex: "progress", key:"progress", width:100,
      render: (v:number) => <Progress percent={v||0} size="small" strokeColor={C.primary} trailColor="#e2e8f0"
        format={p => <span style={{fontSize:11}}>{p}%</span>}/>},
    {title: "时间", dataIndex: "created_at", key:"created_at", width:130,
      render: (v:string) => v ? <Space size={4}><ClockCircleOutlined style={{fontSize:11,color:"#94a3b8"}}/><Text style={{fontSize:11,color:"#64748b"}}>{new Date(v).toLocaleString("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"})}</Text></Space> : "-"},
  ];

  if (loading) return (
    <div style={{display:"flex",justifyContent:"center",alignItems:"center",height:500}}>
      <div style={{textAlign:"center"}}><Spin size="large"/><div style={{marginTop:16}}><Text type="secondary">加载态势数据...</Text></div></div>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-end",marginBottom:24,flexWrap:"wrap",gap:12}}>
        <div>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:36,height:36,borderRadius:10,background:`linear-gradient(135deg,${C.primary},${C.primaryLight})`,display:"flex",alignItems:"center",justifyContent:"center",boxShadow:`0 4px 12px ${C.primary}40`}}>
              <SafetyOutlined style={{fontSize:18,color:"#fff"}}/>
            </div>
            <Title level={4} style={{margin:0,color:C.dark}}>系统总览</Title>
          </div>
          <Text type="secondary" style={{marginLeft:46,fontSize:13}}>实时监控平台运行状态与安全风险态势</Text>
        </div>
        <Space size={12}>
          <Segmented value={timeRange} onChange={v => setTimeRange(v as string)}
            options={[{value:"week",label:"近7天"},{value:"month",label:"近30天"},{value:"year",label:"近12月"}]}
            style={{fontSize:12}}/>
          <Tooltip title={autoRefresh ? "自动刷新 (30s)" : "手动刷新"}>
            <Button type="text" size="small"
              icon={<SyncOutlined spin={autoRefresh} style={{color: autoRefresh ? C.primary : "#94a3b8"}}/>}
              onClick={() => {setAutoRefresh(!autoRefresh); if (!autoRefresh) fetchData();}}/>
          </Tooltip>
          <Button type="primary" size="small" icon={<RiseOutlined/>}
            style={{background:C.primary,borderRadius:6}} onClick={() => navigate("/chat")}>
            开始渗透
          </Button>
        </Space>
      </div>

      {/* Row 1: Metric Cards */}
      <Row gutter={[16, 16]} style={{marginBottom:24}}>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="检测任务总计" value={stats.total} icon={<UnorderedListOutlined/>} color={C.primary}
            trend={{dir:"up", text:"+12% 较上周"}} onClick={() => navigate("/tasks")}/>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="已完成任务" value={stats.completed} icon={<CheckCircleOutlined/>} color={C.success}
            trend={{dir:"up", text:"+8% 较上周"}} onClick={() => navigate("/tasks")}/>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="发现漏洞总数" value={stats.vulnerabilities} icon={<BugIcon/>} color={C.danger}
            trend={{dir:"down", text:"-5% 较上周"}} onClick={() => navigate("/reports")}/>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="高危漏洞" value={stats.high_risk} icon={<AlertOutlined/>} color="#ea580c"
            trend={{dir:"up", text:"+3 新增"}} onClick={() => navigate("/reports")}/>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="已检测资产" value={stats.targets} icon={<RadarChartOutlined/>} color={C.purple}
            trend={{dir:"up", text:"+2 本周"}} onClick={() => navigate("/perception")}/>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <StatCard label="执行中任务" value={stats.running} icon={<SyncOutlined />} color={C.warning}
            onClick={() => navigate("/tasks")}/>
        </Col>
      </Row>

      {/* Row 2: Charts */}
      <Row gutter={[16, 16]} style={{marginBottom:24}}>
        <Col xs={24} lg={14}>
          <div className="big-screen-card" style={{padding:"20px 24px",borderRadius:12,background:"#fff",border:"1px solid #e2e8f0"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
              <Space><RiseOutlined style={{color:C.primary,fontSize:16}}/><Text strong style={{fontSize:14,color:C.dark}}>漏洞发现趋势</Text></Space>
              <Tag color="blue" style={{fontSize:11,borderRadius:4,background:"#f0f9ff",border:"1px solid #bae6fd",color:C.primary}}>
                {timeRange === "week" ? "近 7 天" : timeRange === "month" ? "近 30 天" : "近 12 月"}
              </Tag>
            </div>
            {trendData.length > 0 ? <TrendChart data={trendData}/> : (
              <div style={{height:220,display:"flex",alignItems:"center",justifyContent:"center"}}><Text type="secondary">暂无趋势数据</Text></div>
            )}
          </div>
        </Col>
        <Col xs={24} lg={10}>
          <div className="big-screen-card" style={{padding:"20px 24px",borderRadius:12,background:"#fff",border:"1px solid #e2e8f0",height:"100%"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
              <Space><WarningOutlined style={{color:"#ea580c",fontSize:16}}/><Text strong style={{fontSize:14,color:C.dark}}>风险等级分布</Text></Space>
              <Tag color="orange" style={{fontSize:11,borderRadius:4,background:"#fff7ed",border:"1px solid #fed7aa",color:"#ea580c"}}>
                共 {stats.vulnerabilities} 个漏洞
              </Tag>
            </div>
            <RiskPie data={riskData}/>
          </div>
        </Col>
      </Row>

      {/* Row 3: Attack Chain */}
      <Row style={{marginBottom:24}}>
        <Col span={24}>
          <div className="big-screen-card" style={{padding:"20px 24px",borderRadius:12,background:"#fff",border:"1px solid #e2e8f0"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
              <Space><AimOutlined style={{color:C.purple,fontSize:16}}/><Text strong style={{fontSize:14,color:C.dark}}>渗透攻击链 · 阶段流转</Text></Space>
              <Tag color="purple" style={{fontSize:11,borderRadius:4,background:"#f5f3ff",border:"1px solid #ddd6fe",color:C.purple}}>
                PTES 流程框架
              </Tag>
            </div>
            <PhaseFlow phaseData={phaseData}/>
          </div>
        </Col>
      </Row>

      {/* Row 3b: Topology */}
      {topology && topology.nodes && topology.nodes.length > 0 && (
      <Row gutter={[16, 16]} style={{marginBottom: 24}}>
        <Col span={24}>
          <div className="big-screen-card" style={{padding: "20px 24px", borderRadius: 12, background: "#fff", border: "1px solid #e2e8f0"}}>
            <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12}}>
              <Space><RadarChartOutlined style={{color: "#6366f1", fontSize: 16}}/><Text strong style={{fontSize: 14, color: "#1e293b"}}>网络拓扑</Text></Space>
              <Tag color="purple" style={{fontSize: 11}}>{topology.nodes.length} 节点</Tag>
            </div>
            <div style={{display: "flex", flexWrap: "wrap", gap: 8}}>
              {topology.nodes.map((n: any, i: number) => (
                <Tooltip key={i} title={<div><strong>{n.ip || n.hostname}</strong><br/>{n.services?.join(", ") || ""}<br/>风险: {n.risk || "未知"}</div>}>
                  <div style={{
                    padding: "8px 14px", borderRadius: 8, fontSize: 12,
                    border: "1px solid " + (n.risk === "high" ? "#fecaca" : n.risk === "medium" ? "#fed7aa" : "#e2e8f0"),
                    background: n.risk === "high" ? "#fef2f2" : n.risk === "medium" ? "#fff7ed" : "#f8fafc",
                    cursor: "pointer",
                  }}>
                    <div style={{fontWeight: 600, color: "#1e293b"}}>{n.ip || n.hostname || "节点" + (i+1)}</div>
                    <Text type="secondary" style={{fontSize: 10}}>{n.services?.slice(0, 3).join(", ")}{(n.services?.length || 0) > 3 ? "..." : ""}</Text>
                  </div>
                </Tooltip>
              ))}
            </div>
          </div>
        </Col>
      </Row>
      )}

      {/* Row 4: Tasks + Timeline */}
      <Row gutter={[16, 16]} style={{marginBottom:24}}>
        <Col xs={24} lg={16}>
          <div className="big-screen-card" style={{padding:"20px 24px 8px",borderRadius:12,background:"#fff",border:"1px solid #e2e8f0"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
              <Space><UnorderedListOutlined style={{color:C.primary,fontSize:16}}/><Text strong style={{fontSize:14,color:C.dark}}>最近扫描任务</Text></Space>
              <Button type="link" size="small" onClick={() => navigate("/tasks")} style={{fontSize:12,color:C.primary}}>
                查看全部 <RightOutlined style={{fontSize:10}}/>
              </Button>
            </div>
            <Table dataSource={recentTasks} columns={taskColumns} rowKey={(r:any) => r.id || r.task_id || Math.random().toString()}
              pagination={false} size="small" style={{fontSize:12}}
              locale={{emptyText: <div style={{padding:"32px 0",textAlign:"center"}}><FileTextOutlined style={{fontSize:32,color:"#e2e8f0",display:"block",marginBottom:8}}/><Text type="secondary">暂无扫描任务</Text></div>}}/>
          </div>
        </Col>
        <Col xs={24} lg={8}>
          <div className="big-screen-card" style={{padding:"20px 24px",borderRadius:12,background:"#fff",border:"1px solid #e2e8f0",minHeight:260}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
              <Space><SyncOutlined spin style={{color:C.success,fontSize:16}}/><Text strong style={{fontSize:14,color:C.dark}}>实时动态</Text></Space>
              <Tag color="green" style={{fontSize:11,borderRadius:4,background:"#f0fdf4",border:"1px solid #bbf7d0",color:C.success}}>运行中</Tag>
            </div>
            {timeline.length > 0 ? (
              <Timeline items={timeline.map((t:any, i:number) => ({color:t.color||"gray", children: <Text key={i} style={{fontSize:12,color:"#475569"}}>{t.children}</Text>}))}/>
            ) : (
              <div style={{padding:"24px 0",textAlign:"center"}}><Text type="secondary">暂无动态</Text></div>
            )}
          </div>
        </Col>
      </Row>

      {/* Row 5: Quick Actions */}
      <Row gutter={[16, 16]}>
        {QUICK_ACTIONS.map(a => (
          <Col xs={12} sm={8} lg={4} key={a.key}>
            <div onClick={() => navigate(a.path)}
              style={{padding:"14px 18px",borderRadius:12,cursor:"pointer",display:"flex",alignItems:"center",gap:14,
                background:"#fff",border:"1px solid #e2e8f0",transition:"all 0.3s ease"}}
              className="quick-action-card"
              onMouseEnter={e => {e.currentTarget.style.borderColor = a.color; e.currentTarget.style.boxShadow = `0 4px 16px ${a.color}20`; e.currentTarget.style.transform = "translateY(-2px)";}}
              onMouseLeave={e => {e.currentTarget.style.borderColor = "#e2e8f0"; e.currentTarget.style.boxShadow = "0 1px 3px rgba(0,0,0,0.04)"; e.currentTarget.style.transform = "translateY(0)";}}>
              <div style={{width:40,height:40,borderRadius:10,background:`linear-gradient(135deg,${a.color}20,${a.color}08)`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,color:a.color,flexShrink:0}}>
                {a.icon}
              </div>
              <div><Text strong style={{fontSize:13,color:C.dark,display:"block"}}>{a.label}</Text><Text style={{fontSize:11,color:"#94a3b8"}}>{a.desc}</Text></div>
            </div>
          </Col>
        ))}
      </Row>
    </div>
  );
}
