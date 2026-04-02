import { useState, useEffect, useRef, useCallback } from "react";
import "@/App.css";
import axios from "axios";
import { 
  Shield, 
  Radar, 
  Bug, 
  Globe, 
  Crosshair, 
  Fingerprint,
  Play,
  Square,
  Download,
  Trash2,
  Clock,
  Terminal,
  Cpu,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Copy,
  History,
  ChevronRight,
  Zap
} from "lucide-react";
import { ScrollArea } from "./components/ui/scroll-area";
import { Progress } from "./components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Tool configurations
const TOOLS = [
  { id: "waf", name: "WAF Detection", description: "Detecta firewalls", icon: Shield, color: "#00FF41" },
  { id: "nmap", name: "Nmap", description: "Escaneo de puertos", icon: Radar, color: "#00FF41" },
  { id: "nikto", name: "Nikto", description: "Vulnerabilidades web", icon: Bug, color: "#FF003C" },
  { id: "whatweb", name: "WhatWeb", description: "Fingerprinting", icon: Fingerprint, color: "#FFB000" },
  { id: "subfinder", name: "Subfinder", description: "Subdominios", icon: Globe, color: "#00F0FF" },
  { id: "sn1per", name: "Sn1per", description: "Recon automatizado", icon: Crosshair, color: "#FF003C" }
];

// ASCII Art Logo
const ASCII_LOGO = `
██╗  ██╗ █████╗ ██╗     ██╗
██║ ██╔╝██╔══██╗██║     ██║
█████╔╝ ███████║██║     ██║
██╔═██╗ ██╔══██║██║     ██║
██║  ██╗██║  ██║███████╗██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝
    PENTEST SUITE v1.0
`;

function App() {
  const [target, setTarget] = useState("");
  const [selectedTools, setSelectedTools] = useState(["waf", "nmap", "nikto"]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [terminalLines, setTerminalLines] = useState([
    { type: "system", text: "KALI PENTEST AUTOMATION SUITE INITIALIZED" },
    { type: "system", text: "Sistema listo. Ingresa un objetivo para comenzar." }
  ]);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("tools");
  const terminalRef = useRef(null);
  const pollIntervalRef = useRef(null);

  // Add line to terminal
  const addTerminalLine = useCallback((type, text) => {
    setTerminalLines(prev => [...prev, { type, text, timestamp: new Date().toISOString() }]);
  }, []);

  // Scroll terminal to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  // Load scan history
  const loadHistory = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/scan/history`);
      setHistory(response.data);
    } catch (error) {
      console.error("Error loading history:", error);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // Toggle tool selection
  const toggleTool = (toolId) => {
    setSelectedTools(prev => 
      prev.includes(toolId) 
        ? prev.filter(t => t !== toolId)
        : [...prev, toolId]
    );
  };

  // Start scan
  const startScan = async () => {
    if (!target.trim()) {
      addTerminalLine("error", "ERROR: Target no especificado");
      return;
    }

    if (selectedTools.length === 0) {
      addTerminalLine("error", "ERROR: Selecciona al menos una herramienta");
      return;
    }

    setIsScanning(true);
    addTerminalLine("command", `> Iniciando escaneo: ${target}`);
    addTerminalLine("info", `Herramientas seleccionadas: ${selectedTools.join(", ")}`);

    try {
      const response = await axios.post(`${API}/scan/start`, {
        target: target,
        scan_types: selectedTools
      });

      setCurrentScanId(response.data.scan_id);
      addTerminalLine("success", `Scan ID: ${response.data.scan_id}`);
      
      // Start polling for status
      pollIntervalRef.current = setInterval(() => {
        pollScanStatus(response.data.scan_id);
      }, 2000);

    } catch (error) {
      addTerminalLine("error", `ERROR: ${error.response?.data?.detail || error.message}`);
      setIsScanning(false);
    }
  };

  // Poll scan status
  const pollScanStatus = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);

      // Add tool output to terminal
      if (response.data.current_tool) {
        addTerminalLine("info", `[${response.data.progress}%] Ejecutando: ${response.data.current_tool.toUpperCase()}`);
      }

      // Check results for new data
      if (response.data.results) {
        Object.entries(response.data.results).forEach(([tool, result]) => {
          if (result && !terminalLines.some(l => l.text?.includes(`${tool} completado`))) {
            if (result.error) {
              addTerminalLine("warning", `${tool}: ${result.error}`);
            }
          }
        });
      }

      // Scan completed
      if (response.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("success", "═══════════════════════════════════════");
        addTerminalLine("success", "ESCANEO COMPLETADO");
        addTerminalLine("success", "═══════════════════════════════════════");
        
        // Show summary
        if (response.data.results) {
          Object.entries(response.data.results).forEach(([tool, result]) => {
            if (result.ports) {
              addTerminalLine("info", `NMAP: ${result.ports.length} puertos encontrados`);
            }
            if (result.vulnerabilities) {
              addTerminalLine("warning", `NIKTO: ${result.vulnerabilities.length} vulnerabilidades`);
            }
            if (result.subdomains) {
              addTerminalLine("info", `SUBFINDER: ${result.subdomains.length} subdominios`);
            }
            if (result.waf) {
              addTerminalLine("info", `WAF: ${result.waf}`);
            }
          });
        }

        loadHistory();
        setActiveTab("ai");
      }

      // Scan error
      if (response.data.status === "error") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("error", "ERROR EN EL ESCANEO");
      }

    } catch (error) {
      console.error("Error polling status:", error);
    }
  };

  // Stop scan
  const stopScan = () => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
    }
    setIsScanning(false);
    addTerminalLine("warning", "Escaneo detenido por el usuario");
  };

  // Copy to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    addTerminalLine("info", "Copiado al portapapeles");
  };

  // Download report
  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/report`);
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pentest-report-${scanId}.json`;
      a.click();
      URL.revokeObjectURL(url);
      addTerminalLine("success", "Reporte descargado");
    } catch (error) {
      addTerminalLine("error", "Error descargando reporte");
    }
  };

  // Delete scan
  const deleteScan = async (scanId) => {
    try {
      await axios.delete(`${API}/scan/${scanId}`);
      loadHistory();
      addTerminalLine("info", "Escaneo eliminado del historial");
    } catch (error) {
      addTerminalLine("error", "Error eliminando escaneo");
    }
  };

  // Load historical scan
  const loadScan = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);
      setCurrentScanId(scanId);
      addTerminalLine("info", `Cargando escaneo: ${scanId}`);
      setActiveTab("ai");
    } catch (error) {
      addTerminalLine("error", "Error cargando escaneo");
    }
  };

  return (
    <div className="app-container crt-flicker">
      {/* Scanlines Overlay */}
      <div className="scanlines" />
      
      {/* Matrix Background */}
      <div className="matrix-bg" />

      {/* Header */}
      <header className="app-header">
        <div className="app-logo">
          <div className="logo-icon">
            <Zap size={24} className="text-[#00FF41]" />
          </div>
          <h1 data-testid="app-title">KALI PENTEST SUITE</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-[#008F11] uppercase tracking-widest">
            {isScanning ? "SCANNING..." : "READY"}
          </span>
          {isScanning && (
            <div className="w-2 h-2 bg-[#00FF41] rounded-full animate-pulse" />
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="main-grid">
        {/* Target Input Section */}
        <section className="target-section panel p-4" data-testid="target-section">
          <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center relative z-10">
            <div className="flex-1">
              <label className="text-xs text-[#008F11] uppercase tracking-widest mb-2 block">
                TARGET
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="ejemplo.com o 192.168.1.1"
                className="matrix-input w-full"
                disabled={isScanning}
                data-testid="target-input"
              />
            </div>
            <div className="flex gap-2">
              {!isScanning ? (
                <button 
                  onClick={startScan}
                  className="matrix-btn"
                  disabled={!target.trim() || selectedTools.length === 0}
                  data-testid="start-scan-btn"
                >
                  <Play size={16} />
                  INICIAR SCAN
                </button>
              ) : (
                <button 
                  onClick={stopScan}
                  className="matrix-btn matrix-btn-danger"
                  data-testid="stop-scan-btn"
                >
                  <Square size={16} />
                  DETENER
                </button>
              )}
            </div>
          </div>
          
          {/* Progress Bar */}
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

        {/* Left Panel - Terminal */}
        <section className="terminal-panel panel flex flex-col" data-testid="terminal-panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <Terminal size={16} />
              <span>TERMINAL OUTPUT</span>
            </div>
            <button 
              onClick={() => setTerminalLines([])}
              className="text-[#008F11] hover:text-[#00FF41]"
              data-testid="clear-terminal-btn"
            >
              CLEAR
            </button>
          </div>
          <ScrollArea className="flex-1 p-4 terminal-output" ref={terminalRef}>
            <pre className="ascii-logo text-center mb-4">{ASCII_LOGO}</pre>
            {terminalLines.map((line, idx) => (
              <div 
                key={idx} 
                className={`terminal-line ${
                  line.type === 'error' ? 'text-[#FF003C]' : 
                  line.type === 'warning' ? 'text-[#FFB000]' : 
                  line.type === 'success' ? 'text-[#00FF41]' :
                  line.type === 'command' ? 'text-[#00F0FF]' :
                  line.type === 'system' ? 'text-[#008F11]' :
                  'text-[#00FF41]'
                }`}
              >
                <span className="terminal-prompt">
                  {line.type === 'command' ? '$ ' : 
                   line.type === 'error' ? '[X] ' : 
                   line.type === 'warning' ? '[!] ' : 
                   line.type === 'success' ? '[✓] ' : 
                   '[>] '}
                </span>
                {line.text}
              </div>
            ))}
            {isScanning && <span className="cursor-blink">_</span>}
          </ScrollArea>
        </section>

        {/* Right Panel - Tools & AI */}
        <section className="ai-panel panel flex flex-col" data-testid="ai-panel">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col h-full">
            <TabsList className="bg-transparent border-b border-[#00FF41]/20 rounded-none p-0">
              <TabsTrigger 
                value="tools" 
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00FF41] data-[state=active]:bg-transparent data-[state=active]:text-[#00FF41] text-[#008F11] uppercase tracking-widest text-xs px-4 py-3"
                data-testid="tools-tab"
              >
                HERRAMIENTAS
              </TabsTrigger>
              <TabsTrigger 
                value="ai" 
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00F0FF] data-[state=active]:bg-transparent data-[state=active]:text-[#00F0FF] text-[#008F11] uppercase tracking-widest text-xs px-4 py-3"
                data-testid="ai-tab"
              >
                <Cpu size={14} className="mr-2" />
                KIMI AI
              </TabsTrigger>
              <TabsTrigger 
                value="history" 
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00FF41] data-[state=active]:bg-transparent data-[state=active]:text-[#00FF41] text-[#008F11] uppercase tracking-widest text-xs px-4 py-3"
                data-testid="history-tab"
              >
                <History size={14} className="mr-2" />
                HISTORIAL
              </TabsTrigger>
            </TabsList>

            {/* Tools Tab */}
            <TabsContent value="tools" className="flex-1 overflow-auto p-4 mt-0">
              <p className="text-xs text-[#008F11] mb-4 uppercase tracking-wider">
                Selecciona las herramientas para el escaneo:
              </p>
              <div className="tool-grid">
                {TOOLS.map(tool => {
                  const Icon = tool.icon;
                  const isSelected = selectedTools.includes(tool.id);
                  return (
                    <div
                      key={tool.id}
                      onClick={() => !isScanning && toggleTool(tool.id)}
                      className={`tool-card ${isSelected ? 'selected' : ''} ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                      data-testid={`tool-${tool.id}`}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="matrix-checkbox"
                          disabled={isScanning}
                        />
                        <Icon size={18} style={{ color: tool.color }} />
                      </div>
                      <h3 className="text-sm font-bold uppercase tracking-wider" style={{ color: tool.color }}>
                        {tool.name}
                      </h3>
                      <p className="text-xs text-[#008F11] mt-1">{tool.description}</p>
                    </div>
                  );
                })}
              </div>
            </TabsContent>

            {/* AI Analysis Tab */}
            <TabsContent value="ai" className="flex-1 overflow-auto mt-0">
              <div className="panel-ai h-full">
                <div className="panel-header panel-header-ai">
                  <div className="flex items-center gap-2">
                    <Cpu size={16} className="text-[#00F0FF]" />
                    <span className="text-[#00F0FF]">KIMI K2 ANALYSIS</span>
                  </div>
                </div>
                <ScrollArea className="h-[calc(100%-50px)] p-4">
                  {scanStatus?.ai_analysis ? (
                    <div className="space-y-4">
                      {/* AI Analysis Text */}
                      <div className="text-sm text-[#00F0FF] whitespace-pre-wrap font-mono leading-relaxed">
                        {scanStatus.ai_analysis}
                      </div>

                      {/* Exploit Suggestions */}
                      {scanStatus.exploit_suggestions && scanStatus.exploit_suggestions.length > 0 && (
                        <div className="mt-6">
                          <h4 className="text-xs uppercase tracking-widest text-[#FF003C] mb-3 flex items-center gap-2">
                            <AlertTriangle size={14} />
                            EXPLOITS SUGERIDOS
                          </h4>
                          {scanStatus.exploit_suggestions.map((exploit, idx) => (
                            <div key={idx} className="exploit-card">
                              <div className="flex items-center justify-between">
                                <span className="badge-critical">{exploit.type}</span>
                                <button 
                                  onClick={() => copyToClipboard(exploit.command)}
                                  className="text-[#008F11] hover:text-[#00FF41]"
                                  data-testid={`copy-exploit-${idx}`}
                                >
                                  <Copy size={14} />
                                </button>
                              </div>
                              <div className="exploit-command">
                                {exploit.command}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Download Report Button */}
                      {currentScanId && (
                        <button
                          onClick={() => downloadReport(currentScanId)}
                          className="matrix-btn w-full justify-center mt-4"
                          data-testid="download-report-btn"
                        >
                          <Download size={16} />
                          DESCARGAR REPORTE
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center">
                      <Cpu size={48} className="text-[#00F0FF] opacity-30 mb-4" />
                      <p className="text-[#008F11] text-sm uppercase tracking-wider">
                        {isScanning ? "Esperando resultados del escaneo..." : "Inicia un escaneo para ver el análisis de IA"}
                      </p>
                      {isScanning && <div className="ascii-spinner text-[#00F0FF] text-2xl mt-4" />}
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            {/* History Tab */}
            <TabsContent value="history" className="flex-1 overflow-auto mt-0">
              <ScrollArea className="h-full">
                {history.length > 0 ? (
                  <div className="history-list">
                    {history.map(scan => (
                      <div key={scan.id} className="history-item">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            {scan.status === 'completed' ? (
                              <CheckCircle size={14} className="text-[#00FF41]" />
                            ) : scan.status === 'error' ? (
                              <XCircle size={14} className="text-[#FF003C]" />
                            ) : (
                              <Clock size={14} className="text-[#FFB000]" />
                            )}
                            <span className="text-sm font-bold">{scan.target}</span>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-[#008F11]">
                            <span>{new Date(scan.created_at).toLocaleString()}</span>
                            <span>{scan.tools_used?.length || 0} herramientas</span>
                            <span className={scan.vulnerabilities_found > 0 ? 'text-[#FF003C]' : ''}>
                              {scan.vulnerabilities_found} vulns
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => loadScan(scan.id)}
                            className="text-[#008F11] hover:text-[#00FF41] p-2"
                            data-testid={`load-scan-${scan.id}`}
                          >
                            <ChevronRight size={18} />
                          </button>
                          <button
                            onClick={() => downloadReport(scan.id)}
                            className="text-[#008F11] hover:text-[#00FF41] p-2"
                            data-testid={`download-scan-${scan.id}`}
                          >
                            <Download size={16} />
                          </button>
                          <button
                            onClick={() => deleteScan(scan.id)}
                            className="text-[#008F11] hover:text-[#FF003C] p-2"
                            data-testid={`delete-scan-${scan.id}`}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center p-8">
                    <History size={48} className="text-[#008F11] opacity-30 mb-4" />
                    <p className="text-[#008F11] text-sm uppercase tracking-wider">
                      No hay escaneos en el historial
                    </p>
                  </div>
                )}
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </section>
      </main>

      {/* Status Bar */}
      <footer className="status-bar">
        <div className="status-indicator">
          <div className={`status-dot ${isScanning ? 'warning' : ''}`} />
          <span>SISTEMA: {isScanning ? 'EJECUTANDO ESCANEO' : 'OPERATIVO'}</span>
        </div>
        <div className="flex items-center gap-6">
          <span>TARGET: {target || 'NO DEFINIDO'}</span>
          <span>TOOLS: {selectedTools.length}/6</span>
          <span>KIMI K2: {process.env.REACT_APP_KIMI_ENABLED !== 'false' ? 'CONECTADO' : 'DESCONECTADO'}</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
