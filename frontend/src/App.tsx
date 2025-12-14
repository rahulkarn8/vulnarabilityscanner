import { useState } from 'react'
import axios from 'axios'
import { API_URL } from './config'
import FileTree from './components/FileTree'
import CodeViewer from './components/CodeViewer'
import VulnerabilityList from './components/VulnerabilityList'
import Header from './components/Header'
import Login from './components/Login'
import LoginPopup from './components/LoginPopup'
import Languages from './components/Languages'
import Pricing from './components/Pricing'
import Support from './components/Support'
import Footer from './components/Footer'
import { useAuth } from './contexts/AuthContext'
import './App.css'

export interface Vulnerability {
  line_number: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  vulnerability_type: string
  description: string
  code_snippet: string
  suggested_fix?: string
  scanner?: string  // e.g., "ai_attack", "core", "automotive", etc.
}

export interface FileAnalysis {
  language: string
  vulnerabilities: Vulnerability[]
  total_vulnerabilities: number
  error?: string
  full_path?: string  // For Git repo files
}

function App() {
  const { loading: authLoading, token, isAuthenticated } = useAuth()
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [fileContents, setFileContents] = useState<Record<string, string>>({})
  const [analysisResults, setAnalysisResults] = useState<Record<string, FileAnalysis>>({})
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null)
  const [loading, setLoading] = useState(false)
  const [currentView, setCurrentView] = useState<'dashboard' | 'languages' | 'pricing' | 'support'>('dashboard')
  const [scanType, setScanType] = useState<string>('Code Scan')
  const [scanTarget, setScanTarget] = useState<string>('Unknown')
  const [selectedFiles, setSelectedFiles] = useState<File[] | null>(null)
  const [fileList, setFileList] = useState<string[]>([])
  const [showLoginPopup, setShowLoginPopup] = useState(false)
  const [scanLimitInfo, setScanLimitInfo] = useState<{ scansUsed: number; scanLimit: number } | null>(null)

  // Configure axios to include auth token
  axios.defaults.headers.common['Authorization'] = token ? `Bearer ${token}` : ''
  axios.defaults.baseURL = API_URL

  if (authLoading) {
    return (
      <div className="app">
        <div className="loading-overlay">
          <div className="loading-spinner"></div>
          <p>Loading...</p>
        </div>
      </div>
    )
  }

  const handleGitRepoAnalyze = async (results: Record<string, FileAnalysis>, repoName: string) => {
    // Clear previous results if repoName is empty (repository changed)
    if (!repoName || repoName === '') {
      setAnalysisResults({})
      setFileList([])
      setSelectedFile('')
      setSelectedVulnerability(null)
      setFileContents({})
      return
    }
    
    // Store full paths for later file content fetching
    const newResults: Record<string, FileAnalysis> = {}
    for (const [filePath, fileData] of Object.entries(results)) {
      newResults[filePath] = fileData
    }
    setAnalysisResults(newResults)
    setScanType('Git Repository Scan')
    setScanTarget(repoName)
    // File contents will be loaded when files are selected
    setFileContents({})
    
    // Update fileList to match the results keys (GitHub repo files)
    const resultKeys = Object.keys(newResults)
    if (resultKeys.length > 0) {
      setFileList(resultKeys)
      
      // Auto-select the first file if available
      const firstFile = resultKeys[0]
      setSelectedFile(firstFile)
      
      // Set first vulnerability if available
      const firstFileData = newResults[firstFile]
      if (firstFileData && firstFileData.vulnerabilities && firstFileData.vulnerabilities.length > 0) {
        setSelectedVulnerability(firstFileData.vulnerabilities[0])
      } else {
        setSelectedVulnerability(null)
      }
    } else {
      // No files found, clear everything
      setFileList([])
      setSelectedFile('')
      setSelectedVulnerability(null)
    }
  }

  const loadFileContent = async (filePath: string, fullPath?: string) => {
    // If we have a full path from Git repo, fetch it from backend
    if (fullPath && !fileContents[filePath]) {
      try {
        const response = await axios.get(`${API_URL}/read-file`, {
          params: { file_path: fullPath },
          headers: token ? { Authorization: `Bearer ${token}` } : {}
        })
        setFileContents(prev => ({
          ...prev,
          [filePath]: response.data.content
        }))
      } catch (error) {
        console.error(`Error loading file ${filePath}:`, error)
      }
    }
  }

  const handleFileSelect = async (filePath: string) => {
    setSelectedFile(filePath)
    
    // If file content not loaded, try to load it
    const fileData = analysisResults[filePath] as any
    if (fileData && fileData.full_path && !fileContents[filePath]) {
      await loadFileContent(filePath, fileData.full_path)
    }
    
    // If content is already loaded (from directory selection), use it
    // Otherwise, content will be empty and CodeViewer will show empty
    const content = fileContents[filePath]
    if (!content) {
      console.log(`File content not found for: ${filePath}`)
      console.log('Available file contents keys:', Object.keys(fileContents))
      console.log('Available analysis results keys:', Object.keys(analysisResults))
    }
    
    const vulns = analysisResults[filePath]?.vulnerabilities || []
    if (vulns.length > 0) {
      setSelectedVulnerability(vulns[0])
    } else {
      setSelectedVulnerability(null)
    }
  }

  const handleVulnerabilitySelect = (vuln: Vulnerability) => {
    setSelectedVulnerability(vuln)
  }

  return (
    <div className="app">
      <Header
        onShowLogin={() => setShowLoginPopup(true)} 
        onScanLimitReached={(scansUsed, scanLimit) => {
          setScanLimitInfo({ scansUsed, scanLimit })
          setShowLoginPopup(true)
        }}
        onAnalyzeDirectory={(results) => {
          setAnalysisResults(results)
          setScanType('Directory Scan')
          setScanTarget('Directory')
          
          // Update fileList to match the results keys
          const resultKeys = Object.keys(results)
          if (resultKeys.length > 0) {
            setFileList(resultKeys)
            
            // Auto-select the first file if available
            const firstFile = resultKeys[0]
            setSelectedFile(firstFile)
            
            // Ensure file content is available for the selected file
            // If content is missing, try to match with existing contents
            if (!fileContents[firstFile]) {
              const matchingKey = Object.keys(fileContents).find(key => 
                key === firstFile || 
                key.endsWith(firstFile) || 
                firstFile.endsWith(key) ||
                key.split('/').pop() === firstFile.split('/').pop()
              )
              if (matchingKey) {
                setFileContents((prev: Record<string, string>) => ({
                  ...prev,
                  [firstFile]: prev[matchingKey]
                }))
              }
            }
            
            // Set first vulnerability if available
            const firstFileData = results[firstFile]
            if (firstFileData && firstFileData.vulnerabilities && firstFileData.vulnerabilities.length > 0) {
              setSelectedVulnerability(firstFileData.vulnerabilities[0])
            } else {
              setSelectedVulnerability(null)
            }
          }
        }}
        onAnalyzeFiles={(results) => {
          console.log('onAnalyzeFiles called with results:', results)
          setAnalysisResults(results)
          setScanType('File Upload Scan')
          setScanTarget('Uploaded Files')
          
          // Update fileList to match the results keys
          const fileKeys = Object.keys(results)
          console.log('Results file keys:', fileKeys)
          
          if (fileKeys.length > 0) {
            // Update fileList with result keys
            setFileList(prevList => {
              const combined = [...new Set([...prevList, ...fileKeys])]
              console.log('Updated fileList:', combined)
              return combined
            })
            
            // Auto-select the first file if not already selected
            if (!selectedFile || !fileKeys.includes(selectedFile)) {
              const firstFile = fileKeys[0]
              setSelectedFile(firstFile)
              console.log('Auto-selected first file:', firstFile)
            }
            
            // Set first vulnerability if available
            const firstFile = selectedFile || fileKeys[0]
            const firstFileData = results[firstFile]
            if (firstFileData && firstFileData.vulnerabilities && firstFileData.vulnerabilities.length > 0) {
              setSelectedVulnerability(firstFileData.vulnerabilities[0])
            } else {
              setSelectedVulnerability(null)
            }
          }
        }}
        onAnalyzeGitRepo={handleGitRepoAnalyze}
        setFileContents={(contents) => {
          // Merge new contents with existing ones to preserve previously loaded files
          setFileContents((prev: Record<string, string>) => ({ ...prev, ...contents }))
        }}
        setLoading={setLoading}
        currentView={currentView}
        onViewChange={setCurrentView}
        analysisResults={analysisResults}
        scanType={scanType}
        scanTarget={scanTarget}
        onDirectorySelected={(files) => {
          console.log('Files selected in App.tsx, files:', files)
          console.log('Files is array?', Array.isArray(files))
          console.log('Files length:', files?.length)
          
          // Files should already be an array from Header component
          const filesArray: File[] = Array.isArray(files) ? files : Array.from(files as FileList)
          setSelectedFiles(filesArray)
          
          // Build file list from selected files
          const newFileList: string[] = []
          filesArray.forEach((file: File) => {
            // For directory selection, use webkitRelativePath
            // For file upload, use file.name
            const fileKey = file.webkitRelativePath || file.name
            if (fileKey && !newFileList.includes(fileKey)) {
              newFileList.push(fileKey)
            }
          })
          console.log('File list built:', newFileList)
          console.log('File list length:', newFileList.length)
          console.log('Setting fileList state to:', newFileList)
          
          if (newFileList.length > 0) {
            setFileList(newFileList)
            console.log('FileList state updated!')
          } else {
            console.error('ERROR: No files to add to fileList!')
            console.error('filesArray:', filesArray)
            console.error('filesArray length:', filesArray.length)
          }
          
          // Auto-select the first file immediately
          if (newFileList.length > 0) {
            const firstFile = newFileList[0]
            setSelectedFile(firstFile)
            console.log('First file auto-selected:', firstFile)
          } else {
            console.warn('No files in fileList!')
          }
          
          // Don't clear analysis results immediately - let them persist
          // setAnalysisResults({})
          // setSelectedVulnerability(null)
        }}
        selectedFiles={selectedFiles}
      />
      
      {currentView === 'languages' && (
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <Languages />
        </div>
      )}
      
      {currentView === 'pricing' && (
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <Pricing />
        </div>
      )}
      
      {currentView === 'support' && (
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <Support />
        </div>
      )}
      
      {currentView === 'dashboard' && (
      <div className="dashboard-wrapper">
      <div className="dashboard-container">
        <div className="sidebar">
          {/* Show FileTree if there are files, otherwise show Login if not authenticated */}
          {(fileList.length > 0 || Object.keys(analysisResults).length > 0) ? (
            <FileTree
              files={fileList.length > 0 ? fileList : Object.keys(analysisResults)}
              selectedFile={selectedFile}
              onFileSelect={handleFileSelect}
              analysisResults={analysisResults}
            />
          ) : (
            !isAuthenticated ? (
              <Login />
            ) : (
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                height: '100%',
                color: '#64748b',
                fontSize: '0.9em'
              }}>
                {/* Left panel kept blank when no files and user is logged in */}
              </div>
            )
          )}
        </div>
        <div className="main-content">
          <div className="code-section">
            <CodeViewer
              filePath={selectedFile}
              content={selectedFile ? (fileContents[selectedFile] || '') : ''}
              vulnerabilities={selectedFile ? (analysisResults[selectedFile]?.vulnerabilities || []) : []}
              selectedVulnerability={selectedVulnerability}
              onVulnerabilitySelect={handleVulnerabilitySelect}
            />
          </div>
          <div className="vulnerability-section">
            <VulnerabilityList
              vulnerabilities={selectedFile ? analysisResults[selectedFile]?.vulnerabilities || [] : []}
              selectedVulnerability={selectedVulnerability}
              onVulnerabilitySelect={handleVulnerabilitySelect}
            />
          </div>
        </div>
      </div>
        <Footer />
      </div>
      )}
      {loading && (
        <div className="loading-overlay">
          <div className="loading-spinner"></div>
          <p>Analyzing code...</p>
        </div>
      )}
      <LoginPopup
        isOpen={showLoginPopup}
        onClose={() => {
          setShowLoginPopup(false)
          setScanLimitInfo(null)
        }}
        scansUsed={scanLimitInfo?.scansUsed || 0}
        scanLimit={scanLimitInfo?.scanLimit || 20}
      />
    </div>
  )
}

export default App

