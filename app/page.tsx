"use client"

import type React from "react"

import { useState, useRef, useCallback } from "react"
import {
  AlertTriangle,
  Code,
  Upload,
  FileCode,
  Cat,
  X,
  ChevronDown,
  Lightbulb,
  Sparkles,
  Shield,
  Search,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { analyzeCode, analyzeSkidLevel } from "@/lib/code-analyzer"
import { Card } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { motion } from "framer-motion"
import { ThemeToggle } from "@/components/theme-toggle"
import { useTheme } from "next-themes"

// Add this function to safely check if we're in the browser
const isBrowser = () => typeof window !== "undefined"

// Framer Motion variants for animations
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
    },
  },
}

const itemVariants = {
  hidden: { y: 20, opacity: 0 },
  visible: {
    y: 0,
    opacity: 1,
    transition: {
      type: "spring",
      stiffness: 100,
      damping: 10,
    },
  },
}

// Signature patterns to search for
const SIGNATURE_PATTERNS = [
  {
    name: "Discord Webhooks",
    pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/(\d+)\/([A-Za-z0-9.\-_]+)/g,
    description: "Discord webhook URLs used for data exfiltration",
    severity: "high",
  },
  {
    name: "Discord Tokens",
    pattern: /(?:[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84})/g,
    description: "Discord authentication tokens",
    severity: "high",
  },
  {
    name: "API Keys & Tokens",
    pattern:
      /(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret)(?:\s*=\s*|\s*:\s*)["']?([A-Za-z0-9_\-.]{10,})/gi,
    description: "API keys and access tokens",
    severity: "high",
  },
  {
    name: "Environment Variables",
    pattern:
      /(?:process\.env|os\.getenv|os\.environ|System\.getenv)\s*(?:\[\s*["']|\.get\(\s*["']|["'(])([A-Za-z0-9_]+)/g,
    description: "Access to environment variables",
    severity: "medium",
  },
  {
    name: "Windows AppData",
    pattern:
      /(?:%APPDATA%|%LOCALAPPDATA%|os\.getenv\s*$$\s*["']APPDATA["']\s*$$|os\.getenv\s*$$\s*["']LOCALAPPDATA["']\s*$$)/g,
    description: "Access to Windows AppData directories",
    severity: "medium",
  },
  {
    name: "Base64 Encoded Data",
    pattern: /(?:["']|=\s*["'])[A-Za-z0-9+/]{20,}={0,2}["']/g,
    description: "Base64 encoded data, potentially obfuscated code",
    severity: "medium",
  },
  {
    name: "IP Addresses",
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    description: "Hardcoded IP addresses",
    severity: "medium",
  },
  {
    name: "URLs",
    pattern: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&//=]*)/g,
    description: "URLs to external resources",
    severity: "low",
  },
  {
    name: "Hex Encoded Strings",
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+/g,
    description: "Hex encoded strings, potentially obfuscated code",
    severity: "medium",
  },
  {
    name: "Unicode Escapes",
    pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4})+/g,
    description: "Unicode escape sequences, potentially obfuscated code",
    severity: "medium",
  },
  {
    name: "Eval Usage",
    pattern:
      /(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?:["'`]|(?:atob|decodeURIComponent|String\.fromCharCode))/g,
    description: "Dynamic code execution, often used for obfuscation",
    severity: "high",
  },
  {
    name: "Cryptocurrency Addresses",
    pattern: /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b|(?:r|X)[a-zA-Z0-9]{24,34}\b/g,
    description: "Cryptocurrency wallet addresses",
    severity: "medium",
  },
  {
    name: "File System Access",
    pattern:
      /(?:fs\.(?:read|write|append)|open\s*$$\s*["'].*?["']\s*,\s*["'](?:w|r|a|wb|rb|ab)["']\s*$$|fopen\s*\(\s*["'].*?["']\s*,\s*["'](?:w|r|a|wb|rb|ab))/g,
    description: "File system read/write operations",
    severity: "medium",
  },
  {
    name: "Command Execution",
    pattern:
      /(?:exec|spawn|execSync|spawnSync|system|popen|subprocess\.(?:Popen|call|run)|child_process|ShellExecute|WScript\.Shell)/g,
    description: "Command execution functions",
    severity: "high",
  },
  {
    name: "Registry Access",
    pattern: /(?:HKEY_|Registry\.|reg\s+(?:add|delete|query)|RegCreateKey|RegSetValue|RegGetValue)/g,
    description: "Windows registry access",
    severity: "medium",
  },
  {
    name: "Obfuscated Function Calls",
    pattern: /\[['"]\w+['"]\]\s*\(/g,
    description: "Obfuscated function calls using bracket notation",
    severity: "medium",
  },
  {
    name: "String Concatenation",
    pattern: /(?:["']\s*\+\s*["']){3,}/g,
    description: "Excessive string concatenation, often used for obfuscation",
    severity: "low",
  },
  {
    name: "Suspicious Comments",
    pattern: /\/\/\s*(?:TODO|HACK|FIXME|XXX|NOTE|bypass|steal|grab|token|webhook|exfiltrate|hide|obfuscate)/gi,
    description: "Suspicious comments in code",
    severity: "low",
  },
  {
    name: "Suspicious Variable Names",
    pattern:
      /\b(?:hack|steal|grab|token|webhook|exfiltrate|hide|obfuscate|backdoor|trojan|keylogger|rat|botnet|exploit|payload|malware|virus|worm|ransom)\w*\b/gi,
    description: "Variables with suspicious names",
    severity: "low",
  },
]

// Function to find signatures in code
const findSignatures = (code: string) => {
  const results: Array<{
    name: string
    description: string
    severity: string
    matches: string[]
  }> = []

  SIGNATURE_PATTERNS.forEach((pattern) => {
    const matches = [...code.matchAll(pattern.pattern)].map((match) => match[0])

    if (matches.length > 0) {
      results.push({
        name: pattern.name,
        description: pattern.description,
        severity: pattern.severity,
        matches: [...new Set(matches)], // Remove duplicates
      })
    }
  })

  return results
}

export default function CodeAnalyzer() {
  const [code, setCode] = useState("")
  const [language, setLanguage] = useState("python")
  const [fileName, setFileName] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [activeTab, setActiveTab] = useState("upload")
  const [results, setResults] = useState<{
    webhooks: string[]
    connections: string[]
    malwareScore: number
    detectedBehaviors: Array<{
      name: string
      description: string
      severity: "low" | "medium" | "high"
      confidence: number
      matches: string[]
    }>
    suspiciousImports: string[]
    fileType: string
    detectionCount?: number
  } | null>(null)
  const [skidResults, setSkidResults] = useState<{
    skidScore: number
    cringeComments: string[]
    webhookCount: number
    hardcodedPaths: string[]
    copyPastePatterns: string[]
    skidLevel: "Script Kiddie Apprentice" | "Intermediate Skid" | "Advanced Skid" | "Master Skid" | "1337 h4x0r"
    advice: string
  } | null>(null)
  const [signatureResults, setSignatureResults] = useState<Array<{
    name: string
    description: string
    severity: string
    matches: string[]
  }> | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [showLoadingAnimation, setShowLoadingAnimation] = useState(false)
  const { theme } = useTheme()

  const playMeow = () => {
    // Visual animation only - no sound
    const catIcon = document.querySelector(".cat-icon")
    if (catIcon) {
      catIcon.classList.add("animate-wiggle")
      setTimeout(() => {
        catIcon.classList.remove("animate-wiggle")
      }, 500)
    }
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setFileName(file.name)

    // Auto-detect language from file extension
    const extension = file.name.split(".").pop()?.toLowerCase() || ""
    if (extension === "py") {
      setLanguage("python")
    } else if (extension === "java" || extension === "class") {
      setLanguage("java")
    } else if (extension === "cpp" || extension === "c" || extension === "h" || extension === "hpp") {
      setLanguage("cpp")
    } else if (extension === "js") {
      setLanguage("javascript")
    } else if (extension === "ts" || extension === "tsx") {
      setLanguage("typescript")
    } else if (extension === "ps1") {
      setLanguage("powershell")
    } else if (extension === "vbs") {
      setLanguage("vbscript")
    } else if (extension === "bat" || extension === "cmd") {
      setLanguage("batch")
    } else if (extension === "php") {
      setLanguage("php")
    } else if (extension === "rb") {
      setLanguage("ruby")
    } else if (extension === "go") {
      setLanguage("go")
    } else if (extension === "rs") {
      setLanguage("rust")
    } else if (extension === "swift") {
      setLanguage("swift")
    } else if (extension === "kt") {
      setLanguage("kotlin")
    } else if (extension === "cs") {
      setLanguage("csharp")
    } else if (extension === "sh" || extension === "bash") {
      setLanguage("shell")
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const content = e.target?.result as string
      setCode(content)
    }
    reader.readAsText(file)
  }

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
  }

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0]
      setFileName(file.name)

      // Auto-detect language from file extension
      const extension = file.name.split(".").pop()?.toLowerCase() || ""
      if (extension === "py") {
        setLanguage("python")
      } else if (extension === "java" || extension === "class") {
        setLanguage("java")
      } else if (extension === "cpp" || extension === "c" || extension === "h" || extension === "hpp") {
        setLanguage("cpp")
      } else if (extension === "js") {
        setLanguage("javascript")
      } else if (extension === "ts" || extension === "tsx") {
        setLanguage("typescript")
      } else if (extension === "ps1") {
        setLanguage("powershell")
      } else if (extension === "vbs") {
        setLanguage("vbscript")
      } else if (extension === "bat" || extension === "cmd") {
        setLanguage("batch")
      } else if (extension === "php") {
        setLanguage("php")
      } else if (extension === "rb") {
        setLanguage("ruby")
      } else if (extension === "go") {
        setLanguage("go")
      } else if (extension === "rs") {
        setLanguage("rust")
      } else if (extension === "swift") {
        setLanguage("swift")
      } else if (extension === "kt") {
        setLanguage("kotlin")
      } else if (extension === "cs") {
        setLanguage("csharp")
      } else if (extension === "sh" || extension === "bash") {
        setLanguage("shell")
      }

      const reader = new FileReader()
      reader.onload = (e) => {
        const content = e.target?.result as string
        setCode(content)
      }
      reader.readAsText(file)
    }
  }, [])

  const handleAnalyze = async () => {
    if (!code.trim()) return

    setIsAnalyzing(true)
    setShowLoadingAnimation(true)
    try {
      const analysisResults = await analyzeCode(code, language, fileName)
      setResults(analysisResults)
    } catch (error) {
      console.error("Analysis failed:", error)
    } finally {
      setIsAnalyzing(false)
      setTimeout(() => setShowLoadingAnimation(false), 300) // Keep animation a bit longer for smoother transition
    }
  }

  const handleSkidAnalyze = async () => {
    if (!code.trim()) return

    setIsAnalyzing(true)
    setShowLoadingAnimation(true)
    try {
      const skidAnalysisResults = await analyzeSkidLevel(code, language)
      setSkidResults(skidAnalysisResults)
    } catch (error) {
      console.error("Skid analysis failed:", error)
    } finally {
      setIsAnalyzing(false)
      setTimeout(() => setShowLoadingAnimation(false), 300)
    }
  }

  const handleSignatureAnalyze = () => {
    if (!code.trim()) return

    setIsAnalyzing(true)
    setShowLoadingAnimation(true)

    // Simulate async operation for consistent UX
    setTimeout(() => {
      try {
        const signatures = findSignatures(code)
        setSignatureResults(signatures)
      } catch (error) {
        console.error("Signature analysis failed:", error)
      } finally {
        setIsAnalyzing(false)
        setTimeout(() => setShowLoadingAnimation(false), 300)
      }
    }, 500)
  }

  const clearResults = () => {
    setResults(null)
    setSkidResults(null)
    setSignatureResults(null)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "text-red-400"
      case "medium":
        return "text-amber-400"
      case "low":
        return "text-blue-400"
      default:
        return "text-gray-400"
    }
  }

  const getSeverityBgColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "bg-red-900/60 text-red-200"
      case "medium":
        return "bg-amber-900/60 text-amber-200"
      case "low":
        return "bg-blue-900/60 text-blue-200"
      default:
        return "bg-gray-900/60 text-gray-200"
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 75) return "bg-gradient-to-r from-red-600 to-red-500"
    if (score >= 50) return "bg-gradient-to-r from-amber-600 to-amber-500"
    if (score >= 25) return "bg-gradient-to-r from-blue-600 to-blue-500"
    return "bg-gradient-to-r from-green-600 to-green-500"
  }

  const getSkidScoreColor = (score: number) => {
    if (score >= 80) return "bg-gradient-to-r from-purple-600 to-fuchsia-500"
    if (score >= 60) return "bg-gradient-to-r from-red-600 to-rose-500"
    if (score >= 40) return "bg-gradient-to-r from-amber-600 to-yellow-500"
    if (score >= 20) return "bg-gradient-to-r from-blue-600 to-cyan-500"
    return "bg-gradient-to-r from-green-600 to-emerald-500"
  }

  const getRiskLabel = (score: number, detectionCount: number) => {
    if (detectionCount > 5) return "Where did you even get this?!"
    if (score >= 75) return "High Risk"
    if (score >= 50) return "Medium Risk"
    if (score >= 25) return "Low Risk"
    return "Safe"
  }

  // Track the active tab
  const handleTabChange = (value: string) => {
    setActiveTab(value)
    // Clear results when switching tabs
    if ((value === "upload" || value === "paste") && (skidResults || signatureResults)) {
      setSkidResults(null)
      setSignatureResults(null)
    } else if (value === "skidcheck" && (results || signatureResults)) {
      setResults(null)
      setSignatureResults(null)
    } else if (value === "signatures" && (results || skidResults)) {
      setResults(null)
      setSkidResults(null)
    }
  }

  return (
    <main className="min-h-screen w-full bg-gradient-to-b from-background to-black dark:from-background dark:to-black text-foreground p-4 sm:p-6 md:p-10 lg:p-16">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex items-center justify-between mb-8 sm:mb-12 border-b border-border/40 pb-4 sm:pb-6 max-w-7xl mx-auto w-full"
      >
        <h1 className="text-2xl sm:text-3xl font-bold flex items-center">
          <motion.div
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
            onClick={playMeow}
            className="cursor-pointer"
          >
            <Cat className="mr-2 sm:mr-3 h-6 w-6 sm:h-8 sm:w-8 text-black dark:text-purple-400 cat-icon" />
          </motion.div>
          <span className="gradient-text">ByteMePlz</span>
        </h1>
        <div className="flex items-center gap-3">
          <ThemeToggle />
          <div className="hidden md:flex items-center space-x-2 text-sm text-muted-foreground">
            <Shield className="h-4 w-4 text-black dark:text-purple-400" />
            <span>Malware Detection Engine</span>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2, duration: 0.5 }}
        className="max-w-7xl mx-auto w-full"
      >
        <Tabs defaultValue="upload" className="mb-12" onValueChange={handleTabChange}>
          <TabsList className="w-full bg-secondary/50 backdrop-blur-sm border border-border/30 rounded-xl p-1 overflow-x-auto flex-nowrap scrollbar-hide">
            <TabsTrigger
              value="upload"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all duration-200 flex-1"
            >
              <Upload className="mr-2 h-4 w-4" />
              <span className="hidden sm:inline">Upload File</span>
              <span className="sm:hidden">Upload</span>
            </TabsTrigger>
            <TabsTrigger
              value="paste"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all duration-200 flex-1"
            >
              <Code className="mr-2 h-4 w-4" />
              <span className="hidden sm:inline">Paste Code</span>
              <span className="sm:hidden">Paste</span>
            </TabsTrigger>
            <TabsTrigger
              value="signatures"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all duration-200 flex-1"
            >
              <Search className="mr-2 h-4 w-4" />
              <span className="hidden sm:inline">Signature Finder</span>
              <span className="sm:hidden">Signatures</span>
            </TabsTrigger>
            <TabsTrigger
              value="skidcheck"
              className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all duration-200 flex-1"
            >
              <Lightbulb className="mr-2 h-4 w-4" />
              <span className="hidden sm:inline">SkidCheck™</span>
              <span className="sm:hidden">Skid</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="mt-8">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="gradient-border"
            >
              <div
                className="border-2 border-dashed border-border/50 rounded-xl p-6 sm:p-10 md:p-16 text-center cursor-pointer hover:border-primary/50 transition-colors bg-secondary/30 backdrop-blur-sm"
                onClick={() => fileInputRef.current?.click()}
                onDragOver={handleDragOver}
                onDrop={handleDrop}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  className="hidden"
                  accept=".py,.java,.cpp,.c,.h,.js,.ts,.tsx,.ps1,.vbs,.bat,.cmd,.hpp,.class,.sh,.bash,.pl,.rb,.php,.go,.rs,.swift,.kt,.cs"
                />
                <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} className="mb-4">
                  <FileCode className="h-12 w-12 sm:h-16 sm:w-16 mx-auto text-primary/70" />
                </motion.div>
                <p className="mb-2 text-lg sm:text-xl font-medium">Drag and drop your code file here</p>
                <p className="text-sm text-muted-foreground mb-4">or click to browse</p>
                <p className="text-xs text-muted-foreground max-w-md mx-auto">
                  Supports Python, Java, C++, JavaScript, TypeScript, PowerShell, PHP, Ruby, Go, Rust, Swift, Kotlin,
                  C#, and more
                </p>
                {fileName && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-6 p-3 bg-secondary/70 rounded-lg flex items-center justify-between max-w-md mx-auto"
                  >
                    <span className="text-sm truncate max-w-[80%]">{fileName}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation()
                        setFileName("")
                        setCode("")
                      }}
                      className="h-8 w-8 p-0 rounded-full hover:bg-primary/20"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </motion.div>
                )}
              </div>
            </motion.div>
          </TabsContent>

          <TabsContent value="paste" className="mt-8">
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
              <div className="flex flex-col md:flex-row items-start md:items-center gap-4 mb-4">
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="w-full md:w-[180px] border-border/50 bg-secondary/30 backdrop-blur-sm">
                    <SelectValue placeholder="Select language" />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary/80 backdrop-blur-md border-border/50">
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="java">Java</SelectItem>
                    <SelectItem value="cpp">C++</SelectItem>
                    <SelectItem value="javascript">JavaScript</SelectItem>
                    <SelectItem value="typescript">TypeScript</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="vbscript">VBScript</SelectItem>
                    <SelectItem value="batch">Batch</SelectItem>
                    <SelectItem value="php">PHP</SelectItem>
                    <SelectItem value="ruby">Ruby</SelectItem>
                    <SelectItem value="go">Go</SelectItem>
                    <SelectItem value="rust">Rust</SelectItem>
                    <SelectItem value="swift">Swift</SelectItem>
                    <SelectItem value="kotlin">Kotlin</SelectItem>
                    <SelectItem value="csharp">C#</SelectItem>
                    <SelectItem value="shell">Shell/Bash</SelectItem>
                  </SelectContent>
                </Select>

                <p className="text-sm text-muted-foreground hidden md:block">Paste your code below for analysis</p>
              </div>

              <Textarea
                placeholder={`Paste your ${language} code here for analysis...`}
                className="min-h-[300px] sm:min-h-[400px] border-border/50 bg-secondary/30 backdrop-blur-sm text-foreground rounded-xl resize-none focus:border-primary/50 transition-colors"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </motion.div>
          </TabsContent>

          <TabsContent value="signatures" className="mt-8">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="glass rounded-xl p-4 sm:p-6 mb-4 border border-border/30"
            >
              <h3 className="text-xl font-bold mb-3 flex items-center">
                <Search className="mr-2 h-5 w-5 text-black dark:text-purple-400" />
                <span className="gradient-text">Signature Finder</span>
              </h3>
              <p className="text-muted-foreground mb-4">
                Search for sketchy strings, domains, or obfuscation patterns inside a script. Detects:
              </p>
              <ul className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 mb-4">
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Discord webhooks & tokens
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  API keys & access tokens
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Obfuscated code patterns
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Suspicious environment variables
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Hardcoded IP addresses & URLs
                </li>
              </ul>
              <Textarea
                placeholder="Paste your code here to find suspicious signatures..."
                className="min-h-[200px] sm:min-h-[300px] border-border/50 bg-secondary/50 text-foreground mb-6 rounded-xl resize-none focus:border-primary/50 transition-colors"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <div className="flex items-center gap-4">
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="w-full md:w-[180px] border-border/50 bg-secondary/50">
                    <SelectValue placeholder="Select language" />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary/80 backdrop-blur-md border-border/50">
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="java">Java</SelectItem>
                    <SelectItem value="cpp">C++</SelectItem>
                    <SelectItem value="javascript">JavaScript</SelectItem>
                    <SelectItem value="typescript">TypeScript</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="vbscript">VBScript</SelectItem>
                    <SelectItem value="batch">Batch</SelectItem>
                    <SelectItem value="php">PHP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </motion.div>
          </TabsContent>

          <TabsContent value="skidcheck" className="mt-8">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="glass rounded-xl p-4 sm:p-6 mb-4 border border-border/30"
            >
              <h3 className="text-xl font-bold mb-3 flex items-center">
                <Lightbulb className="mr-2 h-5 w-5 text-yellow-400" />
                <span className="gradient-text">SkidCheck™ - Skid Level Detector</span>
              </h3>
              <p className="text-muted-foreground mb-4">
                Rates how cringe your malware is and detects if it's a "1337 sk1dd3d r4t". Scores based on:
              </p>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Use of cringe comments
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Overuse of webhooks
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Hardcoded paths
                </li>
                <li className="flex items-center text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 mr-2"></span>
                  Copy-paste script kid energy
                </li>
              </ul>
              <Textarea
                placeholder={`Paste your ${language} code here for skid level analysis...`}
                className="min-h-[200px] sm:min-h-[300px] border-border/50 bg-secondary/50 text-foreground mb-6 rounded-xl resize-none focus:border-primary/50 transition-colors"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <div className="flex items-center gap-4">
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="w-full md:w-[180px] border-border/50 bg-secondary/50">
                    <SelectValue placeholder="Select language" />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary/80 backdrop-blur-md border-border/50">
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="java">Java</SelectItem>
                    <SelectItem value="cpp">C++</SelectItem>
                    <SelectItem value="javascript">JavaScript</SelectItem>
                    <SelectItem value="typescript">TypeScript</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="vbscript">VBScript</SelectItem>
                    <SelectItem value="batch">Batch</SelectItem>
                    <SelectItem value="php">PHP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </motion.div>
          </TabsContent>
        </Tabs>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3, duration: 0.5 }}
        className="flex flex-col sm:flex-row justify-center items-center gap-4 my-8 sm:my-12 max-w-7xl mx-auto w-full"
      >
        {!results && !skidResults && !signatureResults && (
          <Button
            onClick={
              activeTab === "skidcheck"
                ? handleSkidAnalyze
                : activeTab === "signatures"
                  ? handleSignatureAnalyze
                  : handleAnalyze
            }
            disabled={isAnalyzing || !code.trim()}
            className={`relative overflow-hidden px-6 py-5 sm:px-8 sm:py-6 text-base sm:text-lg w-full sm:w-auto bg-primary hover:bg-primary/80 rounded-xl transition-all duration-300 shadow-lg`}
          >
            {showLoadingAnimation && <span className="absolute inset-0 loading-shimmer"></span>}
            {isAnalyzing ? (
              <div className="flex items-center">
                <svg
                  className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
                Analyzing...
              </div>
            ) : activeTab === "skidcheck" ? (
              <div className="flex items-center">
                <Lightbulb className="mr-2 h-5 w-5" />
                Analyze Skid Level
              </div>
            ) : activeTab === "signatures" ? (
              <div className="flex items-center">
                <Search className="mr-2 h-5 w-5" />
                Find Signatures
              </div>
            ) : (
              <div className="flex items-center">
                <Sparkles className="mr-2 h-5 w-5" />
                Analyze for Malware
              </div>
            )}
          </Button>
        )}

        {(results || skidResults || signatureResults) && (
          <Button
            onClick={clearResults}
            className="relative overflow-hidden px-6 py-5 sm:px-8 sm:py-6 text-base sm:text-lg w-full sm:w-auto bg-secondary/80 hover:bg-secondary/60 rounded-xl transition-all duration-300 shadow-lg"
          >
            <div className="flex items-center">
              <X className="mr-2 h-5 w-5" />
              Clear Results
            </div>
          </Button>
        )}
      </motion.div>

      {results && (
        <motion.div
          initial="hidden"
          animate="visible"
          variants={containerVariants}
          className="mt-8 sm:mt-12 glass p-4 sm:p-8 md:p-10 rounded-xl border border-border/30 shadow-lg max-w-7xl mx-auto w-full"
        >
          <motion.div variants={itemVariants} className="flex justify-between items-center mb-6">
            <h2 className="text-xl sm:text-2xl font-bold gradient-text">Analysis Results</h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={clearResults}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4 mr-1" /> Clear
            </Button>
          </motion.div>

          <motion.div variants={itemVariants} className="mb-8">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4 gap-2">
              <h3 className="text-lg sm:text-xl font-semibold">Malware Score: {results.malwareScore}/100</h3>
              <div
                className={`px-3 sm:px-4 py-1 sm:py-1.5 rounded-full text-sm font-medium ${
                  results.malwareScore >= 75
                    ? "bg-red-900/60 text-red-200"
                    : results.malwareScore >= 50
                      ? "bg-amber-900/60 text-amber-200"
                      : results.malwareScore >= 25
                        ? "bg-blue-900/60 text-blue-200"
                        : "bg-green-900/60 text-green-200"
                } backdrop-blur-sm`}
              >
                {getRiskLabel(results.malwareScore, results.detectedBehaviors.length)}
              </div>
            </div>

            <Progress
              value={results.malwareScore}
              max={100}
              className="h-2 sm:h-3 mb-4 bg-secondary/70 rounded-full overflow-hidden"
              indicatorClassName={`${getScoreColor(results.malwareScore)} transition-all duration-1000 ease-in-out`}
            />

            <p className="text-muted-foreground mb-4 text-sm sm:text-base">
              {results.detectedBehaviors.length > 5
                ? "Extremely high risk! This code contains numerous malicious patterns. Where did you even get this?!"
                : results.malwareScore >= 75
                  ? "High risk detected! This code contains multiple patterns commonly found in malware."
                  : results.malwareScore >= 50
                    ? "Medium risk detected. Several suspicious patterns were found that may indicate malicious intent."
                    : results.malwareScore >= 25
                      ? "Low risk. Some suspicious patterns were found, but they may be legitimate."
                      : "No significant malicious patterns detected."}
            </p>
          </motion.div>

          {results.detectedBehaviors.length > 0 && (
            <motion.div variants={itemVariants}>
              <Card className="p-4 sm:p-6 md:p-8 mb-8 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl overflow-hidden">
                <h3 className="text-base sm:text-lg font-semibold mb-4 flex items-center">
                  <AlertTriangle className="h-4 sm:h-5 w-4 sm:w-5 mr-2 text-amber-400" />
                  Detected Malicious Behaviors ({results.detectedBehaviors.length})
                </h3>

                <div className="space-y-3">
                  {results.detectedBehaviors.map((behavior, index) => (
                    <Collapsible key={index} className="border border-border/50 rounded-lg overflow-hidden">
                      <CollapsibleTrigger className="flex justify-between items-center w-full p-2 sm:p-3 hover:bg-secondary/70 transition-colors">
                        <div className="flex items-center">
                          <span
                            className={`mr-2 font-medium ${getSeverityColor(behavior.severity)} text-sm sm:text-base`}
                          >
                            {behavior.name}
                          </span>
                          <span className="text-xs px-2 py-0.5 rounded-full bg-secondary/70">
                            {behavior.confidence}% confidence
                          </span>
                        </div>
                        <ChevronDown className="h-4 w-4 text-muted-foreground collapsible-icon" />
                      </CollapsibleTrigger>
                      <CollapsibleContent className="p-4 border-t border-border/50 bg-secondary/50">
                        <p className="text-sm text-muted-foreground mb-3">{behavior.description}</p>
                        {behavior.matches.length > 0 && (
                          <div className="mt-2">
                            <h4 className="text-xs font-medium text-muted-foreground mb-2">Detected Patterns:</h4>
                            <div className="bg-background/80 p-3 rounded-lg text-xs font-mono overflow-x-auto max-h-32 overflow-y-auto">
                              {behavior.matches.map((match, idx) => (
                                <div key={idx} className="mb-1.5 last:mb-0 text-foreground/80">
                                  {match}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </CollapsibleContent>
                    </Collapsible>
                  ))}
                </div>
              </Card>
            </motion.div>
          )}

          {results.suspiciousImports.length > 0 && (
            <motion.div variants={itemVariants}>
              <Card className="p-4 sm:p-6 md:p-8 mb-8 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl">
                <h3 className="text-base sm:text-lg font-semibold mb-3 flex items-center">
                  <AlertTriangle className="h-4 sm:h-5 w-4 sm:w-5 mr-2 text-amber-400" />
                  Suspicious Imports/Libraries
                </h3>
                <div className="bg-background/80 p-3 rounded-lg text-sm font-mono">
                  {results.suspiciousImports.map((imp, index) => (
                    <div key={index} className="mb-1.5 last:mb-0">
                      {imp}
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  These imports are commonly used in malicious code for various purposes.
                </p>
              </Card>
            </motion.div>
          )}

          {results.webhooks.length > 0 && (
            <motion.div variants={itemVariants}>
              <Card className="p-4 sm:p-6 md:p-8 mb-8 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl">
                <h3 className="text-base sm:text-lg font-semibold mb-3 flex items-center">
                  <AlertTriangle className="h-4 sm:h-5 w-4 sm:w-5 mr-2 text-red-400" />
                  Discord Webhooks Found
                </h3>
                <div className="bg-background/80 p-3 rounded-lg text-sm font-mono overflow-x-auto">
                  {results.webhooks.map((webhook, index) => (
                    <div key={index} className="mb-1.5 last:mb-0 break-all">
                      {webhook}
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  Discord webhooks are commonly used to exfiltrate data to external servers.
                </p>
              </Card>
            </motion.div>
          )}

          {results.connections.length > 0 && (
            <motion.div variants={itemVariants}>
              <Card className="p-4 sm:p-6 md:p-8 mb-8 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl">
                <h3 className="text-base sm:text-lg font-semibold mb-3 flex items-center">
                  <AlertTriangle className="h-4 sm:h-5 w-4 sm:w-5 mr-2 text-amber-400" />
                  Suspicious Network Connections
                </h3>
                <div className="bg-background/80 p-3 rounded-lg text-sm font-mono overflow-x-auto">
                  {results.connections.map((connection, index) => (
                    <div key={index} className="mb-1.5 last:mb-0 break-all">
                      {connection}
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  These connections might be used to communicate with command and control servers.
                </p>
              </Card>
            </motion.div>
          )}

          {results.detectedBehaviors.length === 0 &&
            results.suspiciousImports.length === 0 &&
            results.webhooks.length === 0 &&
            results.connections.length === 0 && (
              <motion.div variants={itemVariants}>
                <Card className="p-4 sm:p-6 md:p-8 mb-8 border-border/30 bg-green-900/20 backdrop-blur-sm rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="bg-green-500/20 p-2 rounded-full">
                      <Cat className="h-4 sm:h-5 w-4 sm:w-5 text-green-400" />
                    </div>
                    <p className="font-medium text-green-200">No suspicious behaviors or patterns detected.</p>
                  </div>
                </Card>
              </motion.div>
            )}
        </motion.div>
      )}

      {skidResults && (
        <motion.div
          initial="hidden"
          animate="visible"
          variants={containerVariants}
          className="mt-8 sm:mt-12 glass p-4 sm:p-8 md:p-10 rounded-xl border border-border/30 shadow-lg max-w-7xl mx-auto w-full"
        >
          <motion.div variants={itemVariants} className="flex justify-between items-center mb-6">
            <h2 className="text-xl sm:text-2xl font-bold flex items-center">
              <Lightbulb className="mr-2 h-5 sm:h-6 w-5 sm:w-6 text-yellow-400" />
              <span className="gradient-text">SkidCheck™ Results</span>
            </h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={clearResults}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4 mr-1" /> Clear
            </Button>
          </motion.div>

          <motion.div variants={itemVariants} className="mb-8">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4 gap-2">
              <h3 className="text-lg sm:text-xl font-semibold">Skid Score: {skidResults.skidScore}/100</h3>
              <div
                className={`px-3 sm:px-4 py-1 sm:py-1.5 rounded-full text-sm font-medium ${
                  skidResults.skidScore >= 80
                    ? "bg-purple-900/60 text-purple-200"
                    : skidResults.skidScore >= 60
                      ? "bg-red-900/60 text-red-200"
                      : skidResults.skidScore >= 40
                        ? "bg-amber-900/60 text-amber-200"
                        : skidResults.skidScore >= 20
                          ? "bg-blue-900/60 text-blue-200"
                          : "bg-green-900/60 text-green-200"
                } backdrop-blur-sm`}
              >
                {skidResults.skidLevel}
              </div>
            </div>

            <Progress
              value={skidResults.skidScore}
              max={100}
              className="h-2 sm:h-3 mb-4 bg-secondary/70 rounded-full overflow-hidden"
              indicatorClassName={`${getSkidScoreColor(skidResults.skidScore)} transition-all duration-1000 ease-in-out`}
            />

            <p className="text-muted-foreground mb-6 text-sm sm:text-base">{skidResults.advice}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
              {skidResults.cringeComments.length > 0 && (
                <motion.div variants={itemVariants}>
                  <Card className="p-3 sm:p-5 md:p-6 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl h-full">
                    <h3 className="text-sm sm:text-md font-semibold mb-3 flex items-center">
                      <span className="text-yellow-400 mr-2">💬</span>
                      Cringe Comments
                    </h3>
                    <div className="bg-background/80 p-3 rounded-lg text-sm font-mono max-h-40 overflow-y-auto">
                      {skidResults.cringeComments.map((comment, index) => (
                        <div key={index} className="mb-1.5 last:mb-0 text-foreground/80">
                          {comment}
                        </div>
                      ))}
                    </div>
                  </Card>
                </motion.div>
              )}

              {skidResults.webhookCount > 0 && (
                <motion.div variants={itemVariants}>
                  <Card className="p-3 sm:p-5 md:p-6 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl h-full">
                    <h3 className="text-sm sm:text-md font-semibold mb-3 flex items-center">
                      <span className="text-blue-400 mr-2">🔗</span>
                      Webhook Usage
                    </h3>
                    <div className="bg-background/80 p-3 rounded-lg">
                      <p className="text-foreground/80 text-sm sm:text-base">
                        {skidResults.webhookCount === 1
                          ? "1 webhook found"
                          : `${skidResults.webhookCount} webhooks found`}
                      </p>
                      {skidResults.webhookCount > 2 && (
                        <p className="text-muted-foreground text-xs sm:text-sm mt-2">
                          Using multiple webhooks is a common script kiddie technique
                        </p>
                      )}
                    </div>
                  </Card>
                </motion.div>
              )}

              {skidResults.hardcodedPaths.length > 0 && (
                <motion.div variants={itemVariants}>
                  <Card className="p-3 sm:p-5 md:p-6 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl h-full">
                    <h3 className="text-sm sm:text-md font-semibold mb-3 flex items-center">
                      <span className="text-red-400 mr-2">📁</span>
                      Hardcoded Paths
                    </h3>
                    <div className="bg-background/80 p-3 rounded-lg text-sm font-mono max-h-40 overflow-y-auto">
                      {skidResults.hardcodedPaths.map((path, index) => (
                        <div key={index} className="mb-1.5 last:mb-0 text-foreground/80 break-all">
                          {path}
                        </div>
                      ))}
                    </div>
                  </Card>
                </motion.div>
              )}

              {skidResults.copyPastePatterns.length > 0 && (
                <motion.div variants={itemVariants}>
                  <Card className="p-3 sm:p-5 md:p-6 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl h-full">
                    <h3 className="text-sm sm:text-md font-semibold mb-3 flex items-center">
                      <span className="text-green-400 mr-2">📋</span>
                      Copy-Paste Patterns
                    </h3>
                    <div className="bg-background/80 p-3 rounded-lg text-sm font-mono max-h-40 overflow-y-auto">
                      {skidResults.copyPastePatterns.map((pattern, index) => (
                        <div key={index} className="mb-1.5 last:mb-0 text-foreground/80">
                          {pattern}
                        </div>
                      ))}
                    </div>
                  </Card>
                </motion.div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}

      {signatureResults && (
        <motion.div
          initial="hidden"
          animate="visible"
          variants={containerVariants}
          className="mt-8 sm:mt-12 glass p-4 sm:p-8 md:p-10 rounded-xl border border-border/30 shadow-lg max-w-7xl mx-auto w-full"
        >
          <motion.div variants={itemVariants} className="flex justify-between items-center mb-6">
            <h2 className="text-xl sm:text-2xl font-bold flex items-center">
              <Search className="mr-2 h-5 sm:h-6 w-5 sm:w-6 text-black dark:text-purple-400" />
              <span className="gradient-text">Signature Finder Results</span>
            </h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={clearResults}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4 mr-1" /> Clear
            </Button>
          </motion.div>

          {signatureResults.length > 0 ? (
            <motion.div variants={itemVariants}>
              <p className="text-muted-foreground mb-6 text-sm sm:text-base">
                Found {signatureResults.length} suspicious signature{signatureResults.length !== 1 ? "s" : ""} in the
                code.
              </p>

              <div className="space-y-4">
                {signatureResults.map((signature, index) => (
                  <Card
                    key={index}
                    className="p-3 sm:p-5 md:p-6 border-border/30 bg-secondary/30 backdrop-blur-sm rounded-xl"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm sm:text-md font-semibold flex items-center">
                        <AlertTriangle className={`mr-2 h-4 w-4 ${getSeverityColor(signature.severity)}`} />
                        {signature.name}
                      </h3>
                      <span className={`text-xs px-3 py-1 rounded-full ${getSeverityBgColor(signature.severity)}`}>
                        {signature.severity.charAt(0).toUpperCase() + signature.severity.slice(1)} Risk
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">{signature.description}</p>
                    <div className="bg-background/80 p-3 rounded-lg text-sm font-mono max-h-40 overflow-y-auto">
                      {signature.matches.map((match, idx) => (
                        <div key={idx} className="mb-1.5 last:mb-0 text-foreground/80 break-all">
                          {match}
                        </div>
                      ))}
                    </div>
                  </Card>
                ))}
              </div>
            </motion.div>
          ) : (
            <motion.div variants={itemVariants}>
              <Card className="p-4 sm:p-6 md:p-8 border-border/30 bg-green-900/20 backdrop-blur-sm rounded-xl">
                <div className="flex items-center gap-3">
                  <div className="bg-green-500/20 p-2 rounded-full">
                    <Search className="h-4 sm:h-5 w-4 sm:w-5 text-green-400" />
                  </div>
                  <p className="font-medium text-green-200">No suspicious signatures detected in the code.</p>
                </div>
              </Card>
            </motion.div>
          )}
        </motion.div>
      )}

      <motion.footer
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.5 }}
        className="mt-16 sm:mt-20 pt-6 sm:pt-8 border-t border-border/30 text-center text-muted-foreground max-w-7xl mx-auto w-full"
      >
        <p className="flex items-center justify-center gap-2">
          <Cat className="h-4 w-4 text-black dark:text-purple-400" />
          Owned by ValkDevices
        </p>
      </motion.footer>
    </main>
  )
}
