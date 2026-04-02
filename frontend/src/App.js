import { useState, useEffect, useRef, useCallback } from "react";
import "@/App.css";
import axios from "axios";
import { 
  Shield, Radar, Bug, Globe, Crosshair, Fingerprint,
  Play, Square, Download, Trash2, Clock, Terminal, Cpu,
  AlertTriangle, CheckCircle, XCircle, Copy, History,
  ChevronRight, Zap, Target, GitBranch, Server, Unlock, Skull, RefreshCw
} from "lucide-react";
import { ScrollArea } from "./components/ui/scroll-area";
import { Progress } from "./components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const TOOLS = [
  { id: "waf", name: "WAF Detection", description: "Detecta firewalls", icon: Shield, color: "#00FF41" },
  { id: "nmap", name: "Nmap", description: "Escaneo de puertos", icon: Radar, color: "#00FF41" },
  { id: "nikto", name: "Nikto", description: "Vulnerabilidades web", icon: Bug, color: "#FF003C" },
  { id: "whatweb", name: "WhatWeb", description: "Fingerprinting", icon: Fingerprint, color: "#FFB000" },
  { id: "subfinder", name: "Subfinder", description: "Subdominios", icon: Globe, color: "#00F0FF" },
  { id: "sn1per", name: "Sn1per", description: "Recon automatizado", icon: Crosshair, color: "#FF003C" }
];

const NODE_ICONS = { target: Target, service: Server, vulnerability: Bug, exploit: Skull, access: Unlock, defense: Shield, subdomain: Globe };
const NODE_COLORS = { target: "#00FF41", service: "#00F0FF", vulnerability: "#FF003C", exploit: "#FFB000", access: "#00FF41", defense: "#FFB000", subdomain: "#00F0FF" };
const STATUS_COLORS = { pending: "#008F11", testing: "#FFB000", success: "#00FF41", failed: "#FF003C", verified: "#00F0FF" };

const ASCII_LOGO = `██╗  ██╗ █████╗ ██╗     ██╗
██║ ██╔╝██╔══██╗██║     ██║
█████╔╝ ███████║██║     ██║
██╔═██╗ ██╔══██║██║     ██║
██║  ██╗██║  ██║███████╗██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝
   PENTEST SUITE v2.0`;

function App() {
  const [target, setTarget] = useState("");
  const [selectedTools, setSelectedTools] = useState(["waf", "nmap", "nikto"]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [attackTree, setAttackTree] = useState(null);
  const [terminalLines, setTerminalLines] = useState([
    { type: "system", text: "KALI PENTEST AUTOMATION SUITE v2.0 INITIALIZED" },
    { type: "system", text: "Sistema listo. Ingresa un objetivo para comenzar." }
  ]);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("tools");
  const [msfModule, setMsfModule] = useState(null);
  const [msfModules, setMsfModules] = useState([]);
  const [moduleSearch, setModuleSearch] = useState("");
  const [msfPort, setMsfPort] = useState("");
  const [msfExecuting, setMsfExecuting] = useState(false);
  const [msfResult, setMsfResult] = useState(null);
  const terminalRef = useRef(null);
  const pollIntervalRef = useRef(null);

  const addTerminalLine = useCallback((type, text) => {
    setTerminalLines(prev => [...prev, { type, text }]);
  }, []);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLines]);

  const loadHistory = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/scan/history`);
      setHistory(response.data);
    } catch (error) { console.error("Error loading history:", error); }
  }, []);

  const loadMsfModules = useCallback(async (query = "") => {
    try {
      const response = await axios.get(`${API}/metasploit/modules`, { params: { query } });
      setMsfModules(response.data.modules);
    } catch (error) { console.error("Error loading MSF modules:", error); }
  }, []);

  useEffect(() => { loadHistory(); loadMsfModules(); }, [loadHistory, loadMsfModules]);

  const toggleTool = (toolId) => {
    setSelectedTools(prev => prev.includes(toolId) ? prev.filter(t => t !== toolId) : [...prev, toolId]);
  };

  const startScan = async () => {
    if (!target.trim() || selectedTools.length === 0) {
      addTerminalLine("error", "ERROR: Target o herramientas no especificados");
      return;
    }
    setIsScanning(true);
    setAttackTree(null);
    addTerminalLine("command", `> Iniciando escaneo: ${target}`);

    try {
      const response = await axios.post(`${API}/scan/start`, { target, scan_types: selectedTools });
      setCurrentScanId(response.data.scan_id);
      addTerminalLine("success", `Scan ID: ${response.data.scan_id}`);
      pollIntervalRef.current = setInterval(() => pollScanStatus(response.data.scan_id), 2000);
    } catch (error) {
      addTerminalLine("error", `ERROR: ${error.response?.data?.detail || error.message}`);
      setIsScanning(false);
    }
  };

  const pollScanStatus = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);
      if (response.data.current_tool) addTerminalLine("info", `[${response.data.progress}%] Ejecutando: ${response.data.current_tool.toUpperCase()}`);
      if (response.data.attack_tree) setAttackTree(response.data.attack_tree);
      if (response.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("success", "═══════════════════════════════════════");
        addTerminalLine("success", "ESCANEO COMPLETADO - ÁRBOL DE ATAQUE GENERADO");
        addTerminalLine("success", "═══════════════════════════════════════");
        loadHistory();
        setActiveTab("tree");
      }
      if (response.data.status === "error") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("error", "ERROR EN EL ESCANEO");
      }
    } catch (error) { console.error("Error polling status:", error); }
  };

  const stopScan = () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    setIsScanning(false);
    addTerminalLine("warning", "Escaneo detenido");
  };

  const updateNodeStatus = async (nodeId, status) => {
    if (!currentScanId) return;
    try {
      await axios.put(`${API}/scan/${currentScanId}/tree/node/${nodeId}`, { status });
      const response = await axios.get(`${API}/scan/${currentScanId}/tree`);
      setAttackTree(response.data);
      addTerminalLine("info", `Nodo ${nodeId} → ${status.toUpperCase()}`);
    } catch (error) { addTerminalLine("error", `Error: ${error.message}`); }
  };

  const executeMsfExploit = async () => {
    if (!msfModule) return;
    setMsfExecuting(true);
    addTerminalLine("command", `> msfconsole -x "use ${msfModule}; set RHOSTS ${target}; run"`);
    try {
      const response = await axios.post(`${API}/metasploit/execute`, {
        scan_id: currentScanId || "",
        node_id: "",
        module: msfModule,
        target_host: target || "127.0.0.1",
        target_port: msfPort ? parseInt(msfPort) : null,
        options: {}
      });
      setMsfResult(response.data);
      if (response.data.success) {
        addTerminalLine("success", `EXPLOIT EXITOSO: ${msfModule}`);
        if (response.data.session_opened) addTerminalLine("success", "¡SESIÓN OBTENIDA!");
      } else {
        addTerminalLine("warning", `Exploit sin éxito: ${msfModule}`);
      }
      if (currentScanId) {
        const treeResponse = await axios.get(`${API}/scan/${currentScanId}/tree`);
        setAttackTree(treeResponse.data);
      }
    } catch (error) {
      setMsfResult({ error: error.message });
      addTerminalLine("error", `Error: ${error.message}`);
    }
    setMsfExecuting(false);
  };

  const copyToClipboard = (text) => { navigator.clipboard.writeText(text); addTerminalLine("info", "Copiado"); };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/report`);
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `pentest-report-${scanId}.json`; a.click();
      URL.revokeObjectURL(url);
      addTerminalLine("success", "Reporte descargado");
    } catch (error) { addTerminalLine("error", "Error descargando reporte"); }
  };

  const deleteScan = async (scanId) => {
    try {
      await axios.delete(`${API}/scan/${scanId}`);
      loadHistory();
      if (currentScanId === scanId) { setAttackTree(null); setScanStatus(null); setCurrentScanId(null); }
      addTerminalLine("info", "Escaneo eliminado");
    } catch (error) { addTerminalLine("error", "Error eliminando"); }
  };

  const loadScan = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);
      setCurrentScanId(scanId);
      if (response.data.attack_tree) setAttackTree(response.data.attack_tree);
      addTerminalLine("info", `Cargando escaneo: ${scanId}`);
      setActiveTab("tree");
    } catch (error) { addTerminalLine("error", "Error cargando"); }
  };

  // Get tree nodes as flat list
  const getTreeNodes = () => {
    if (!attackTree) return [];
    const nodes = [];
    if (attackTree.root) {
      nodes.push({ ...attackTree.root, depth: 0, isRoot: true });
      if (attackTree.root.children && attackTree.nodes) {
        attackTree.root.children.forEach(childId => {
          const node = attackTree.nodes[childId];
          if (node) nodes.push({ ...node, depth: 1 });
        });
      }
    }
    return nodes;
  };

  const treeNodes = getTreeNodes();
  const treeStats = {
    total: Object.keys(attackTree?.nodes || {}).length,
    pending: Object.values(attackTree?.nodes || {}).filter(n => n.status === "pending").length,
    verified: Object.values(attackTree?.nodes || {}).filter(n => n.status === "verified").length,
    success: Object.values(attackTree?.nodes || {}).filter(n => n.status === "success").length,
    failed: Object.values(attackTree?.nodes || {}).filter(n => n.status === "failed").length
  };

  return (
    <div className="app-container crt-flicker">
      <div className="scanlines" />
      <div className="matrix-bg" />

      <header className="app-header">
        <div className="app-logo">
          <div className="logo-icon"><Zap size={24} className="text-[#00FF41]" /></div>
          <h1 data-testid="app-title">KALI PENTEST SUITE</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-[#008F11] uppercase tracking-widest">{isScanning ? "SCANNING..." : "READY"}</span>
          {isScanning && <div className="w-2 h-2 bg-[#00FF41] rounded-full animate-pulse" />}
        </div>
      </header>

      <main className="main-grid">
        <section className="target-section panel p-4" data-testid="target-section">
          <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center relative z-10">
            <div className="flex-1">
              <label className="text-xs text-[#008F11] uppercase tracking-widest mb-2 block">TARGET</label>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="ejemplo.com o 192.168.1.1" className="matrix-input w-full" disabled={isScanning} data-testid="target-input" />
            </div>
            <div className="flex gap-2">
              {!isScanning ? (
                <button onClick={startScan} className="matrix-btn" disabled={!target.trim() || selectedTools.length === 0} data-testid="start-scan-btn"><Play size={16} /> INICIAR SCAN</button>
              ) : (
                <button onClick={stopScan} className="matrix-btn matrix-btn-danger" data-testid="stop-scan-btn"><Square size={16} /> DETENER</button>
              )}
            </div>
          </div>
          {isScanning && scanStatus && (
            <div className="mt-4 relative z-10">
              <div className="flex justify-between text-xs text-[#008F11] mb-1">
                <span>PROGRESO: {scanStatus.current_tool?.toUpperCase() || "INICIANDO"}</span>
                <span>{scanStatus.progress}%</span>
              </div>
              <Progress value={scanStatus.progress} className="h-1 bg-[#0a140a]" />
            </div>
          )}
        </section>

        <section className="terminal-panel panel flex flex-col" data-testid="terminal-panel">
          <div className="panel-header">
            <div className="flex items-center gap-2"><Terminal size={16} /><span>TERMINAL OUTPUT</span></div>
            <button onClick={() => setTerminalLines([])} className="text-[#008F11] hover:text-[#00FF41]" data-testid="clear-terminal-btn">CLEAR</button>
          </div>
          <ScrollArea className="flex-1 p-4 terminal-output" ref={terminalRef}>
            <pre className="ascii-logo text-center mb-4">{ASCII_LOGO}</pre>
            {terminalLines.map((line, idx) => (
              <div key={idx} className={`terminal-line ${line.type === 'error' ? 'text-[#FF003C]' : line.type === 'warning' ? 'text-[#FFB000]' : line.type === 'success' ? 'text-[#00FF41]' : line.type === 'command' ? 'text-[#00F0FF]' : 'text-[#008F11]'}`}>
                <span className="terminal-prompt">{line.type === 'command' ? '$ ' : line.type === 'error' ? '[X] ' : line.type === 'warning' ? '[!] ' : line.type === 'success' ? '[✓] ' : '[>] '}</span>{line.text}
              </div>
            ))}
            {isScanning && <span className="cursor-blink">_</span>}
          </ScrollArea>
        </section>

        <section className="ai-panel panel flex flex-col" data-testid="ai-panel">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col h-full">
            <TabsList className="bg-transparent border-b border-[#00FF41]/20 rounded-none p-0 flex-wrap">
              <TabsTrigger value="tools" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00FF41] data-[state=active]:bg-transparent data-[state=active]:text-[#00FF41] text-[#008F11] uppercase tracking-widest text-xs px-3 py-3" data-testid="tools-tab">TOOLS</TabsTrigger>
              <TabsTrigger value="tree" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FFB000] data-[state=active]:bg-transparent data-[state=active]:text-[#FFB000] text-[#008F11] uppercase tracking-widest text-xs px-3 py-3" data-testid="tree-tab"><GitBranch size={14} className="mr-1" />MAPA</TabsTrigger>
              <TabsTrigger value="msf" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FF003C] data-[state=active]:bg-transparent data-[state=active]:text-[#FF003C] text-[#008F11] uppercase tracking-widest text-xs px-3 py-3" data-testid="msf-tab"><Skull size={14} className="mr-1" />MSF</TabsTrigger>
              <TabsTrigger value="ai" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00F0FF] data-[state=active]:bg-transparent data-[state=active]:text-[#00F0FF] text-[#008F11] uppercase tracking-widest text-xs px-3 py-3" data-testid="ai-tab"><Cpu size={14} className="mr-1" />AI</TabsTrigger>
              <TabsTrigger value="history" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00FF41] data-[state=active]:bg-transparent data-[state=active]:text-[#00FF41] text-[#008F11] uppercase tracking-widest text-xs px-3 py-3" data-testid="history-tab"><History size={14} className="mr-1" />HIST</TabsTrigger>
            </TabsList>

            <TabsContent value="tools" className="flex-1 overflow-auto p-4 mt-0">
              <p className="text-xs text-[#008F11] mb-4 uppercase tracking-wider">Selecciona las herramientas:</p>
              <div className="tool-grid">
                {TOOLS.map(tool => {
                  const Icon = tool.icon;
                  const isSelected = selectedTools.includes(tool.id);
                  return (
                    <div key={tool.id} onClick={() => !isScanning && toggleTool(tool.id)} className={`tool-card ${isSelected ? 'selected' : ''} ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`} data-testid={`tool-${tool.id}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <input type="checkbox" checked={isSelected} onChange={() => {}} className="matrix-checkbox" disabled={isScanning} />
                        <Icon size={18} style={{ color: tool.color }} />
                      </div>
                      <h3 className="text-sm font-bold uppercase tracking-wider" style={{ color: tool.color }}>{tool.name}</h3>
                      <p className="text-xs text-[#008F11] mt-1">{tool.description}</p>
                    </div>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="tree" className="flex-1 overflow-auto mt-0">
              <div className="h-full flex flex-col">
                {attackTree && (
                  <div className="flex items-center gap-4 p-3 border-b border-[#00FF41]/20 text-xs flex-wrap">
                    <span className="text-[#008F11]">NODOS: {treeStats.total}</span>
                    <span style={{ color: STATUS_COLORS.pending }}>PENDIENTES: {treeStats.pending}</span>
                    <span style={{ color: STATUS_COLORS.verified }}>VERIFICADOS: {treeStats.verified}</span>
                    <span style={{ color: STATUS_COLORS.success }}>EXITOSOS: {treeStats.success}</span>
                    <span style={{ color: STATUS_COLORS.failed }}>FALLIDOS: {treeStats.failed}</span>
                  </div>
                )}
                <ScrollArea className="flex-1 p-4">
                  {treeNodes.length > 0 ? (
                    <div className="attack-tree space-y-1">
                      {treeNodes.map((node, idx) => {
                        const Icon = NODE_ICONS[node.type] || Server;
                        const color = NODE_COLORS[node.type] || "#00FF41";
                        return (
                          <div key={node.id || idx} style={{ marginLeft: node.depth * 24 }} className="flex items-start gap-2 p-2 border-l-2 hover:bg-[#00FF41]/5" style={{ borderLeftColor: STATUS_COLORS[node.status] || STATUS_COLORS.pending, marginLeft: node.depth * 24 }}>
                            <Icon size={16} style={{ color }} className="flex-shrink-0 mt-0.5" />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-bold truncate" style={{ color }}>{node.name}</span>
                                {node.severity && <span className={`badge-${node.severity === 'critical' ? 'critical' : node.severity === 'high' ? 'high' : 'medium'}`}>{node.severity.toUpperCase()}</span>}
                                <span className="text-xs px-1.5 py-0.5 uppercase tracking-wider" style={{ color: STATUS_COLORS[node.status], border: `1px solid ${STATUS_COLORS[node.status]}40` }}>{node.status}</span>
                              </div>
                              <p className="text-xs text-[#008F11] mt-1 truncate">{node.description}</p>
                              {node.type === "exploit" && node.status === "pending" && (
                                <div className="flex gap-2 mt-2">
                                  <button onClick={() => { setMsfModule(node.data?.module || node.name); setActiveTab("msf"); }} className="matrix-btn text-xs py-1 px-2"><Skull size={12} /> EJECUTAR</button>
                                  <button onClick={() => updateNodeStatus(node.id, "verified")} className="text-xs text-[#00F0FF] hover:underline">[VERIFICADO]</button>
                                </div>
                              )}
                              {node.type !== "exploit" && node.status === "pending" && !node.isRoot && (
                                <div className="flex gap-2 mt-2">
                                  <button onClick={() => updateNodeStatus(node.id, "testing")} className="text-xs text-[#FFB000] hover:underline">[PROBAR]</button>
                                  <button onClick={() => updateNodeStatus(node.id, "verified")} className="text-xs text-[#00F0FF] hover:underline">[VERIFICADO]</button>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center">
                      <GitBranch size={48} className="text-[#FFB000] opacity-30 mb-4" />
                      <p className="text-[#008F11] text-sm uppercase tracking-wider">{isScanning ? "Generando árbol..." : "Inicia un escaneo para ver el mapa"}</p>
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            <TabsContent value="msf" className="flex-1 overflow-auto mt-0 p-4">
              {msfModule ? (
                <div className="panel p-4 border border-[#FF003C]/50">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-[#FF003C] uppercase tracking-widest flex items-center gap-2"><Skull size={18} /> METASPLOIT</h3>
                    <button onClick={() => { setMsfModule(null); setMsfResult(null); }} className="text-[#008F11] hover:text-[#FF003C]"><XCircle size={18} /></button>
                  </div>
                  <div className="space-y-3">
                    <div><label className="text-xs text-[#008F11] uppercase tracking-wider">Módulo</label><div className="matrix-input bg-black/80 text-[#FF003C] mt-1">{msfModule}</div></div>
                    <div><label className="text-xs text-[#008F11] uppercase tracking-wider">Target</label><input type="text" value={target || "127.0.0.1"} readOnly className="matrix-input w-full mt-1" /></div>
                    <div><label className="text-xs text-[#008F11] uppercase tracking-wider">Puerto</label><input type="text" value={msfPort} onChange={(e) => setMsfPort(e.target.value)} placeholder="80, 443..." className="matrix-input w-full mt-1" data-testid="msf-port-input" /></div>
                    <button onClick={executeMsfExploit} disabled={msfExecuting} className="matrix-btn w-full justify-center" style={{ borderColor: "#FF003C", color: "#FF003C" }} data-testid="msf-execute-btn">
                      {msfExecuting ? <><RefreshCw size={14} className="animate-spin" /> EJECUTANDO...</> : <><Play size={14} /> EJECUTAR EXPLOIT</>}
                    </button>
                    {msfResult && (
                      <div className={`p-3 border ${msfResult.success ? 'border-[#00FF41]/50 bg-[#00FF41]/10' : 'border-[#FF003C]/50 bg-[#FF003C]/10'}`}>
                        <div className="flex items-center gap-2 mb-2">
                          {msfResult.success ? <CheckCircle size={16} className="text-[#00FF41]" /> : <XCircle size={16} className="text-[#FF003C]" />}
                          <span className={msfResult.success ? 'text-[#00FF41]' : 'text-[#FF003C]'}>{msfResult.success ? 'EXITOSO' : 'FALLIDO'}</span>
                          {msfResult.session_opened && <span className="badge-critical">¡SESIÓN!</span>}
                        </div>
                        {msfResult.simulated && <p className="text-xs text-[#FFB000] mb-2">[SIMULADO]</p>}
                        <pre className="text-xs text-[#008F11] overflow-auto max-h-32 bg-black/50 p-2">{msfResult.rc_command || msfResult.output || msfResult.error}</pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div><label className="text-xs text-[#008F11] uppercase tracking-wider mb-2 block">BUSCAR MÓDULOS</label><input type="text" value={moduleSearch} onChange={(e) => { setModuleSearch(e.target.value); loadMsfModules(e.target.value); }} placeholder="apache, smb..." className="matrix-input w-full" data-testid="msf-search-input" /></div>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-2">
                      {msfModules.map((mod, idx) => (
                        <div key={idx} onClick={() => setMsfModule(mod.name)} className="p-3 border border-[#FF003C]/30 hover:border-[#FF003C] cursor-pointer" data-testid={`msf-module-${idx}`}>
                          <div className="flex items-center justify-between"><span className="text-sm text-[#FF003C] font-mono">{mod.name}</span><span className={`text-xs ${mod.rank === 'excellent' ? 'text-[#00FF41]' : 'text-[#008F11]'}`}>{mod.rank}</span></div>
                          <p className="text-xs text-[#008F11] mt-1">{mod.description}</p>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
            </TabsContent>

            <TabsContent value="ai" className="flex-1 overflow-auto mt-0">
              <div className="panel-ai h-full">
                <div className="panel-header panel-header-ai"><div className="flex items-center gap-2"><Cpu size={16} className="text-[#00F0FF]" /><span className="text-[#00F0FF]">KIMI K2 ANALYSIS</span></div></div>
                <ScrollArea className="h-[calc(100%-50px)] p-4">
                  {scanStatus?.ai_analysis ? (
                    <div className="space-y-4">
                      <div className="text-sm text-[#00F0FF] whitespace-pre-wrap font-mono leading-relaxed">{scanStatus.ai_analysis}</div>
                      {scanStatus.exploit_suggestions?.length > 0 && (
                        <div className="mt-6">
                          <h4 className="text-xs uppercase tracking-widest text-[#FF003C] mb-3 flex items-center gap-2"><AlertTriangle size={14} />EXPLOITS</h4>
                          {scanStatus.exploit_suggestions.map((exploit, idx) => (
                            <div key={idx} className="exploit-card">
                              <div className="flex items-center justify-between">
                                <span className="badge-critical">{exploit.type}</span>
                                <div className="flex gap-2">
                                  <button onClick={() => copyToClipboard(exploit.commands?.join('\n') || exploit.command)} className="text-[#008F11] hover:text-[#00FF41]"><Copy size={14} /></button>
                                  {exploit.module && <button onClick={() => { setMsfModule(exploit.module); setActiveTab("msf"); }} className="text-[#FF003C]"><Play size={14} /></button>}
                                </div>
                              </div>
                              <div className="exploit-command">{exploit.commands?.join('\n') || exploit.command}</div>
                            </div>
                          ))}
                        </div>
                      )}
                      {currentScanId && <button onClick={() => downloadReport(currentScanId)} className="matrix-btn w-full justify-center mt-4" data-testid="download-report-btn"><Download size={16} /> DESCARGAR REPORTE</button>}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center"><Cpu size={48} className="text-[#00F0FF] opacity-30 mb-4" /><p className="text-[#008F11] text-sm uppercase tracking-wider">{isScanning ? "Esperando..." : "Inicia escaneo para ver análisis"}</p></div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            <TabsContent value="history" className="flex-1 overflow-auto mt-0">
              <ScrollArea className="h-full">
                {history.length > 0 ? (
                  <div className="history-list">
                    {history.map(scan => (
                      <div key={scan.id} className="history-item">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            {scan.status === 'completed' ? <CheckCircle size={14} className="text-[#00FF41]" /> : <XCircle size={14} className="text-[#FF003C]" />}
                            <span className="text-sm font-bold">{scan.target}</span>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-[#008F11]">
                            <span>{new Date(scan.created_at).toLocaleString()}</span>
                            <span>{scan.tools_used?.length || 0} tools</span>
                            <span className={scan.vulnerabilities_found > 0 ? 'text-[#FF003C]' : ''}>{scan.vulnerabilities_found} vulns</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button onClick={() => loadScan(scan.id)} className="text-[#008F11] hover:text-[#00FF41] p-2"><ChevronRight size={18} /></button>
                          <button onClick={() => downloadReport(scan.id)} className="text-[#008F11] hover:text-[#00FF41] p-2"><Download size={16} /></button>
                          <button onClick={() => deleteScan(scan.id)} className="text-[#008F11] hover:text-[#FF003C] p-2"><Trash2 size={16} /></button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center p-8"><History size={48} className="text-[#008F11] opacity-30 mb-4" /><p className="text-[#008F11] text-sm uppercase tracking-wider">Sin historial</p></div>
                )}
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </section>
      </main>

      <footer className="status-bar">
        <div className="status-indicator"><div className={`status-dot ${isScanning ? 'warning' : ''}`} /><span>SISTEMA: {isScanning ? 'ESCANEANDO' : 'OPERATIVO'}</span></div>
        <div className="flex items-center gap-6">
          <span>TARGET: {target || 'N/A'}</span>
          <span>TOOLS: {selectedTools.length}/6</span>
          {attackTree && <span className="text-[#FFB000]">NODOS: {treeStats.total}</span>}
          <span>MSF: {msfModule ? 'ACTIVO' : 'READY'}</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
