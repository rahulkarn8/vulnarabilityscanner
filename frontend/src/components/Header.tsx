import { useState, useEffect } from 'react'
import axios from 'axios'
import { FolderOpen, FileCode, GitBranch, LogOut, Code2, DollarSign, Menu, ChevronDown, Download, User, HelpCircle } from 'lucide-react'
import { FileAnalysis } from '../App'
import { useAuth } from '../contexts/AuthContext'
import { API_URL } from '../config'
import ConfirmDialog from './ConfirmDialog'
import './Header.css'

interface HeaderProps {
  onAnalyzeDirectory: (results: Record<string, FileAnalysis>) => void
  onAnalyzeFiles: (results: Record<string, FileAnalysis>) => void
  onAnalyzeGitRepo: (results: Record<string, FileAnalysis>, repoName: string) => void
  setFileContents: (contents: Record<string, string>) => void
  setLoading: (loading: boolean) => void
  currentView?: 'dashboard' | 'languages' | 'pricing' | 'support'
  onViewChange?: (view: 'dashboard' | 'languages' | 'pricing' | 'support') => void
  analysisResults?: Record<string, FileAnalysis>
  scanType?: string
  scanTarget?: string
  onDirectorySelected?: (files: File[]) => void
  selectedFiles?: File[] | null
  onScanLimitReached?: (scansUsed: number, scanLimit: number) => void
}

function Header({ onAnalyzeDirectory, onAnalyzeFiles, onAnalyzeGitRepo, setFileContents, setLoading, currentView = 'dashboard', onViewChange, analysisResults, scanType, scanTarget, onDirectorySelected, selectedFiles, onScanLimitReached }: HeaderProps) {
  const { user, logout, token } = useAuth()
  const [repoUrl, setRepoUrl] = useState('')
  const [repoBranch, setRepoBranch] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)
  const [avatarMenuOpen, setAvatarMenuOpen] = useState(false)
  const [downloadingPDF, setDownloadingPDF] = useState(false)
  const [downloadingCompliance, setDownloadingCompliance] = useState(false)
  const [selectedDirectory, setSelectedDirectory] = useState<string>('')
  const [localLoading, setLocalLoading] = useState(false)
  const [localSelectedFiles, setLocalSelectedFiles] = useState<File[] | null>(null)
  const [repositories, setRepositories] = useState<Array<{id: number, name: string, full_name: string, url: string, clone_url: string, default_branch: string}>>([])
  const [branches, setBranches] = useState<Array<{name: string}>>([])
  const [selectedRepo, setSelectedRepo] = useState<string>('')
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [loadingBranches, setLoadingBranches] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[] | null>(null)
  const [pendingDirectoryName, setPendingDirectoryName] = useState<string>('')
  const [pendingCodeFilesCount, setPendingCodeFilesCount] = useState<number>(0)
  const [pendingTotalFilesCount, setPendingTotalFilesCount] = useState<number>(0)
  const [showTimeoutDialog, setShowTimeoutDialog] = useState(false)
  const [timeoutDialogMessage, setTimeoutDialogMessage] = useState<string>('')
  const [timeoutDialogOnConfirm, setTimeoutDialogOnConfirm] = useState<(() => void) | null>(null)

  const handleDirectorySelectViaAPI = async () => {
    // Try to use File System Access API which has a cleaner dialog
    // @ts-ignore - File System Access API types may not be available
    if ('showDirectoryPicker' in window) {
      try {
        // @ts-ignore
        const directoryHandle = await window.showDirectoryPicker()
        const filesArray: File[] = []
        
        const processDirectory = async (dirHandle: any, path = '') => {
          for await (const entry of dirHandle.values()) {
            if (entry.kind === 'file') {
              const file = await entry.getFile()
              if (file) {
                // Create a File object with webkitRelativePath for compatibility
                const relativePath = path ? `${path}/${entry.name}` : entry.name
                Object.defineProperty(file, 'webkitRelativePath', {
                  value: relativePath,
                  writable: false
                })
                filesArray.push(file)
              }
            } else if (entry.kind === 'directory') {
              const newPath = path ? `${path}/${entry.name}` : entry.name
              await processDirectory(entry, newPath)
            }
          }
        }
        
        await processDirectory(directoryHandle, directoryHandle.name)
        
        if (filesArray.length === 0) {
          return
        }
        
        // Process files the same way as regular directory select
        const firstFile = filesArray[0]
        const directoryName = (firstFile as any).webkitRelativePath?.split('/')[0] || directoryHandle.name || 'Selected Directory'
        
        // Filter function to count only code files
        const shouldIncludeFile = (file: File): boolean => {
          const filePath = (file as any).webkitRelativePath || file.name
          const fileName = file.name
          
          if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') {
            return false
          }
          
          const parts = filePath.split('/')
          if (parts.some((part: string) => part.startsWith('.') && part !== '.' && part !== '..')) {
            const ext = fileName.substring(fileName.lastIndexOf('.'))
            const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
            if (!codeExtensions.includes(ext.toLowerCase())) {
              return false
            }
          }
          
          const skipDirs = ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git', '.vscode', '.idea']
          if (parts.some((part: string) => skipDirs.includes(part))) {
            return false
          }
          
          const ext = fileName.substring(fileName.lastIndexOf('.'))
          const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
          return codeExtensions.includes(ext.toLowerCase())
        }
        
        const codeFilesCount = filesArray.filter(shouldIncludeFile).length
        const totalFilesCount = filesArray.length
        
        setPendingFiles(filesArray)
        setPendingDirectoryName(directoryName)
        setPendingCodeFilesCount(codeFilesCount)
        setPendingTotalFilesCount(totalFilesCount)
        setShowConfirmDialog(true)
      } catch (error: any) {
        // User cancelled or error occurred
        if (error.name !== 'AbortError') {
          console.error('Error accessing directory:', error)
        }
        return
      }
    }
  }

  const handleDirectorySelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files || files.length === 0) {
      setSelectedDirectory('')
      setLocalSelectedFiles(null)
      return
    }

    // Clear GitHub selections when directory is selected
    setSelectedRepo('')
    setRepoBranch('')
    setBranches([])
    setRepoUrl('')

    // Convert FileList to Array IMMEDIATELY - FileList is live and gets cleared when input resets
    const filesArray = Array.from(files)
    console.log('Directory selected, files count:', filesArray.length)
    
    // Get the directory name from the first file's path
    const firstFile = filesArray[0]
    const directoryName = firstFile.webkitRelativePath.split('/')[0] || 'Selected Directory'
    
    // Filter function to count only code files (exclude hidden/non-code files)
    const shouldIncludeFile = (file: File): boolean => {
      const filePath = file.webkitRelativePath || file.name
      const fileName = file.name
      
      // Skip .git directories and files
      if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') {
        return false
      }
      
      // Skip hidden files and directories (except if they're code files)
      const parts = filePath.split('/')
      if (parts.some(part => part.startsWith('.') && part !== '.' && part !== '..')) {
        // Allow hidden files if they have code extensions
        const ext = fileName.substring(fileName.lastIndexOf('.'))
        const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
        if (!codeExtensions.includes(ext.toLowerCase())) {
          return false
        }
      }
      
      // Skip common non-code directories
      const skipDirs = ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git', '.vscode', '.idea']
      if (parts.some(part => skipDirs.includes(part))) {
        return false
      }
      
      // Only include files with code extensions
      const ext = fileName.substring(fileName.lastIndexOf('.'))
      const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
      return codeExtensions.includes(ext.toLowerCase())
    }
    
    // Count only code files
    const codeFilesCount = filesArray.filter(shouldIncludeFile).length
    const totalFilesCount = filesArray.length
    
    // Store pending selection and show custom confirmation dialog
    setPendingFiles(filesArray)
    setPendingDirectoryName(directoryName)
    setPendingCodeFilesCount(codeFilesCount)
    setPendingTotalFilesCount(totalFilesCount)
    setShowConfirmDialog(true)
    
    // Reset the input so dialog can be shown
    event.target.value = ''
    
    console.log('Directory name:', directoryName)
    console.log('Total files stored:', filesArray.length)
    console.log('Code files count:', codeFilesCount)
    
    // Read file contents for display (without scanning)
    const contents: Record<string, string> = {}
    const fileList: string[] = []
    
    Array.from(files).forEach(file => {
      if (file.name.match(/\.(py|cpp|cxx|cc|c\+\+|c|hpp|h|arxml)$/i)) {
        const fileKey = file.webkitRelativePath || file.name
        fileList.push(fileKey)
        
        // Read file content asynchronously
        file.text().then(text => {
          contents[fileKey] = text
        }).catch(e => {
          console.error(`Error reading file ${file.name}:`, e)
        })
      }
    })
    
    // Wait for all files to be read, then set contents
    Promise.all(
      filesArray
        .filter(file => file.name.match(/\.(py|cpp|cxx|cc|c\+\+|c|hpp|h|arxml)$/i))
        .map(file => {
          const fileKey = file.webkitRelativePath || file.name
          return file.text().then(text => ({ fileKey, text }))
        })
    ).then(fileDataArray => {
      const allContents: Record<string, string> = {}
      fileDataArray.forEach(({ fileKey, text }) => {
        allContents[fileKey] = text
      })
      setFileContents(allContents)
    })
    
    // Notify parent component about selected files (pass array, not FileList)
    if (onDirectorySelected) {
      onDirectorySelected(filesArray)
    }
    
    // Reset the input so the same directory can be selected again
    // But keep the files reference in localSelectedFiles
    event.target.value = ''
  }

  const handleScanDirectory = async () => {
    // Use array directly - files should already be arrays
    const filesToScan = selectedFiles || localSelectedFiles
    
    console.log('Scan button clicked')
    console.log('selectedFiles:', selectedFiles)
    console.log('localSelectedFiles:', localSelectedFiles)
    console.log('selectedDirectory:', selectedDirectory)
    console.log('filesToScan:', filesToScan)
    console.log('filesToScan type:', Array.isArray(filesToScan) ? 'array' : typeof filesToScan)
    console.log('filesToScan length:', filesToScan?.length)
    
    if (!filesToScan || filesToScan.length === 0) {
      alert('Please select a directory first. No files found.')
      return
    }
    
    if (!selectedDirectory) {
      alert('Please select a directory first')
      return
    }

    setLocalLoading(true)
    setLoading(true)
    try {
      const formData = new FormData()
      
      // filesToScan should already be an array, but ensure it is
      const filesArray: File[] = Array.isArray(filesToScan) ? filesToScan : Array.from(filesToScan as FileList)
      console.log('Files array for scanning:', filesArray.length, 'files')
      
      // Filter function to exclude hidden files and non-code files
      const shouldIncludeFile = (file: File): boolean => {
        const filePath = file.webkitRelativePath || file.name
        const fileName = file.name
        
        // Skip .git directories and files
        if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') {
          return false
        }
        
        // Skip hidden files and directories (except if they're code files)
        const parts = filePath.split('/')
        if (parts.some(part => part.startsWith('.') && part !== '.' && part !== '..')) {
          // Allow hidden files if they have code extensions
          const ext = fileName.substring(fileName.lastIndexOf('.'))
          const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
          if (!codeExtensions.includes(ext.toLowerCase())) {
            return false
          }
        }
        
        // Skip common non-code directories
        const skipDirs = ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git', '.vscode', '.idea']
        if (parts.some(part => skipDirs.includes(part))) {
          return false
        }
        
        // Only include files with code extensions
        const ext = fileName.substring(fileName.lastIndexOf('.'))
        const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
        return codeExtensions.includes(ext.toLowerCase())
      }
      
      // Filter and add files to FormData, preserving their relative paths
      filesArray.forEach((file: File) => {
        if (shouldIncludeFile(file)) {
          formData.append('files', file, file.webkitRelativePath)
          console.log('Added file to FormData:', file.name, file.webkitRelativePath)
        }
      })

      const filesAdded = formData.getAll('files').length
      console.log('Total files added to FormData:', filesAdded)
      
      if (filesAdded === 0) {
        alert('No supported files found in the selected directory. Please select a directory containing Python, C++, or C files.')
        setLocalLoading(false)
        setLoading(false)
        return
      }

      const headers: any = {
        'Content-Type': 'multipart/form-data'
      }
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }

      // Use upload-files endpoint which can handle directory structure
      console.log('Sending request to:', `${API_URL}/upload-files`)
      console.log('Request headers:', headers)
      console.log('FormData files count:', formData.getAll('files').length)
      
      const response = await axios.post(`${API_URL}/upload-files`, formData, {
        headers,
        timeout: 300000  // 5 minute timeout for large scans
      })

      console.log('Scan response received:', response.status, response.statusText)
      console.log('Scan response data:', response.data)
      console.log('Scan response keys:', Object.keys(response.data))
      
      // Filter response to only include code files (exclude hidden/non-code files)
      const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
      const filteredResults: Record<string, FileAnalysis> = {}
      
      Object.entries(response.data).forEach(([filePath, fileData]: [string, any]) => {
        // Skip .git directories and files
        if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') {
          return
        }
        
        const parts = filePath.split('/')
        const skipDirs = ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git', '.vscode', '.idea']
        if (parts.some(part => skipDirs.includes(part))) {
          return
        }
        
        // Skip hidden files unless they have code extensions
        if (parts.some(part => part.startsWith('.') && part !== '.' && part !== '..')) {
          const fileName = parts[parts.length - 1]
          const ext = fileName.substring(fileName.lastIndexOf('.'))
          if (!codeExtensions.includes(ext.toLowerCase())) {
            return
          }
        }
        
        // Only include files with code extensions
        const fileName = parts[parts.length - 1]
        const ext = fileName.substring(fileName.lastIndexOf('.'))
        if (codeExtensions.includes(ext.toLowerCase())) {
          filteredResults[filePath] = fileData
          
          const vulnCount = fileData?.total_vulnerabilities || fileData?.vulnerabilities?.length || 0
          console.log(`File: ${filePath} - Vulnerabilities: ${vulnCount}`)
          if (vulnCount > 0) {
            console.log(`  Vulnerabilities:`, fileData.vulnerabilities)
          }
        }
      })

      // Then update analysis results with filtered files - this will trigger FileTree to show the files
      onAnalyzeDirectory(filteredResults)
    } catch (error: any) {
      console.error('Error analyzing directory:', error)
      console.error('Error details:', {
        code: error.code,
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        statusText: error.response?.statusText,
        config: {
          url: error.config?.url,
          method: error.config?.method
        }
      })
      
      // Handle scan limit reached (403 error)
      if (error.response?.status === 403) {
        const scanData = error.response.data?.detail || error.response.data
        if (scanData?.error === 'scan_limit_reached') {
          const scansUsed = scanData.scans_used || scanData.scan_count || 0
          const scanLimit = scanData.scan_limit || 5
          setLocalLoading(false)
          setLoading(false)
          if (onScanLimitReached) {
            onScanLimitReached(scansUsed, scanLimit)
          }
          return
        }
      }
      
      // Don't show error for 5xx server errors that might be temporary
      // The server might still be processing
      const isServerError = error.response?.status >= 500 && error.response?.status < 600
      const isTimeout = error.code === 'ECONNABORTED' || error.message.includes('timeout')
      
      if (error.code === 'ERR_NETWORK' || error.message === 'Network Error' || error.code === 'ECONNREFUSED') {
        // Network errors are usually fatal - show immediately
        alert(
          '❌ Network Error: Backend server is not running!\n\n' +
          'Please start the backend server first.\n\n' +
          `Trying to connect to: ${API_URL}/upload-files`
        )
      } else if (isTimeout) {
        // Timeout - but scan might still be processing on server
        // Show custom dialog instead of browser confirm
        setTimeoutDialogMessage(
          '⏱️ Request Timeout: The scan is taking longer than expected.\n\n' +
          'The scan might still be processing on the server.\n\n' +
          'Would you like to wait a bit longer?'
        )
        setTimeoutDialogOnConfirm(() => {
          // User wants to wait - don't show error, just keep loading
          console.log('User chose to wait - scan may still be processing')
          setLocalLoading(false)
          setLoading(false)
          setShowTimeoutDialog(false)
        })
        setShowTimeoutDialog(true)
        return
      } else if (isServerError) {
        // Server error - might be temporary, show custom dialog
        setTimeoutDialogMessage(
          '⚠️ Server Error: The scan encountered an issue.\n\n' +
          'This might be temporary. The scan may still be processing.\n\n' +
          'Would you like to wait a bit longer?'
        )
        setTimeoutDialogOnConfirm(() => {
          // User wants to wait - don't show error
          console.log('User chose to wait - scan may still be processing')
          setShowTimeoutDialog(false)
        })
        setShowTimeoutDialog(true)
        return
      } else {
        // Other errors - show normally
        alert(`Error: ${error.response?.data?.detail || error.message || 'Unknown error'}\n\nStatus: ${error.response?.status || 'N/A'}`)
      }
    } finally {
      setLocalLoading(false)
      setLoading(false)
    }
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files || files.length === 0) return

    // Convert to array immediately
    const filesArray = Array.from(files)
    console.log('Files uploaded, count:', filesArray.length)
    console.log('File names:', filesArray.map(f => f.name))
    
    // Read file contents immediately for display
    const contents: Record<string, string> = {}
    const fileList: string[] = []
    
    for (const file of filesArray) {
      fileList.push(file.name)
      try {
        const text = await file.text()
        contents[file.name] = text
      } catch (e) {
        console.error(`Error reading file ${file.name}:`, e)
      }
    }
    
    console.log('File list for display:', fileList)
    console.log('File contents loaded:', Object.keys(contents))
    
    // Set file contents immediately so files can be viewed
    setFileContents(contents)
    
    // Notify parent about files for display - this should show files in FileTree
    if (onDirectorySelected) {
      onDirectorySelected(filesArray)
      console.log('Notified parent about files')
    }

    // Now scan the files
    setLocalLoading(true)
    setLoading(true)
    const formData = new FormData()
    filesArray.forEach(file => {
      formData.append('files', file)
    })

    try {
      const headers: any = {
        'Content-Type': 'multipart/form-data'
      }
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }
      const response = await axios.post(`${API_URL}/upload-files`, formData, {
        headers
      })

      console.log('Upload response:', response.data)
      
      // Update file contents (they're already set above)
      // Just update analysis results
      onAnalyzeFiles(response.data)
    } catch (error: any) {
      console.error('Error uploading files:', error)
      
      // Handle scan limit reached (403 error)
      if (error.response?.status === 403) {
        const scanData = error.response.data?.detail || error.response.data
        if (scanData?.error === 'scan_limit_reached') {
          const scansUsed = scanData.scans_used || scanData.scan_count || 0
          const scanLimit = scanData.scan_limit || 5
          setLocalLoading(false)
          setLoading(false)
          if (onScanLimitReached) {
            onScanLimitReached(scansUsed, scanLimit)
          }
          return
        }
      }
      
      if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
        alert(
          '❌ Network Error: Backend server is not running!\n\n' +
          'Please start the backend server first.'
        )
      } else {
        alert(`Error: ${error.response?.data?.detail || error.message}`)
      }
    } finally {
      setLocalLoading(false)
      setLoading(false)
    }
  }

  const handleGitRepoAnalyze = async () => {
    // Use selectedRepo if GitHub user, otherwise use repoUrl
    const repoToAnalyze = user?.provider === 'github' && selectedRepo 
      ? repositories.find(r => r.full_name === selectedRepo)?.clone_url || ''
      : repoUrl.trim()
    
    if (!repoToAnalyze) {
      alert('Please select or enter a Git repository URL')
      return
    }

    setLocalLoading(true)
    setLoading(true)
    try {
      const requestData: any = {
        repo_url: repoToAnalyze,
        languages: ['python', 'cpp', 'automotive', 'frontend']  // Include frontend for JS/TS files, exclude .json
      }
      
      if (repoBranch.trim()) {
        requestData.branch = repoBranch.trim()
      }

      const response = await axios.post(`${API_URL}/analyze-git-repo`, requestData, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      })
      
      // Convert response to FileAnalysis format
      const results: Record<string, FileAnalysis> = {}
      
      // Process files from the repository
      for (const [filePath, fileData] of Object.entries(response.data.files)) {
        if (fileData && typeof fileData === 'object') {
          try {
            const data = fileData as any
            // Store full_path for later file content fetching
            results[filePath] = {
              language: data.language || 'unknown',
              vulnerabilities: data.vulnerabilities || [],
              total_vulnerabilities: data.total_vulnerabilities || 0,
              error: data.error,
              full_path: data.full_path  // Store full path for fetching file content
            } as any
          } catch (e) {
            console.error(`Error processing file ${filePath}:`, e)
          }
        }
      }
      
      // Files will be loaded on demand when selected
      onAnalyzeGitRepo(results, response.data.repo_name || 'Repository')
      
      // Filter to count only code files (exclude .git, hidden files, etc.)
      const codeExtensions = ['.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html', '.css', '.scss', '.sass', '.less', '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc']
      const codeFiles = Object.keys(results).filter(filePath => {
        if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') return false
        const parts = filePath.split('/')
        const skipDirs = ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist', '.git', '.vscode', '.idea']
        if (parts.some(part => skipDirs.includes(part))) return false
        const fileName = parts[parts.length - 1]
        const ext = fileName.substring(fileName.lastIndexOf('.'))
        return codeExtensions.includes(ext.toLowerCase())
      })
      
      // Show success message with filtered file count
      const message = `Repository analyzed successfully!\n\nFound ${response.data.total_vulnerabilities} vulnerabilities in ${codeFiles.length} code files.`
      alert(message)
    } catch (error: any) {
      console.error('Error analyzing Git repository:', error)
      
      // Handle scan limit reached (403 error)
      if (error.response?.status === 403) {
        const scanData = error.response.data?.detail || error.response.data
        if (scanData?.error === 'scan_limit_reached') {
          const scansUsed = scanData.scans_used || scanData.scan_count || 0
          const scanLimit = scanData.scan_limit || 5
          setLocalLoading(false)
          setLoading(false)
          if (onScanLimitReached) {
            onScanLimitReached(scansUsed, scanLimit)
          }
          return
        }
      }
      
      // Check if it's a network error (backend not running)
      if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
        alert(
          '❌ Network Error: Backend server is not running!\n\n' +
          'Please start the backend server:\n' +
          '1. Open a terminal\n' +
          '2. cd backend\n' +
          '3. source venv/bin/activate (or venv\\Scripts\\activate on Windows)\n' +
          '4. python main.py\n\n' +
          'Or run: ./start.sh from the project root'
        )
      } else {
        alert(`Error: ${error.response?.data?.detail || error.message}`)
      }
    } finally {
      setLocalLoading(false)
      setLoading(false)
    }
  }

  const handleDownloadPDF = async () => {
    if (!analysisResults || Object.keys(analysisResults).length === 0) {
      alert('No scan results available to download. Please run a scan first.')
      return
    }

    setDownloadingPDF(true)
    try {
      const response = await axios.post(
        `${API_URL}/generate-pdf-report`,
        {
          results: analysisResults,
          scan_type: scanType || 'Code Scan',
          scan_target: scanTarget || 'Unknown'
        },
        {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          responseType: 'blob'
        }
      )

      // Create a blob URL and trigger download
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5)
      link.download = `vulnerability_report_${timestamp}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (error: any) {
      console.error('Error generating PDF:', error)
      alert(`Error generating PDF: ${error.response?.data?.detail || error.message}`)
    } finally {
      setDownloadingPDF(false)
    }
  }

  const handleDownloadComplianceReport = async () => {
    if (!analysisResults || Object.keys(analysisResults).length === 0) {
      alert('No scan results available to generate compliance report. Please run a scan first.')
      return
    }

    setDownloadingCompliance(true)
    try {
      const response = await axios.post(
        `${API_URL}/generate-compliance-pdf`,
        {
          results: analysisResults,
          scan_type: scanType || 'Automotive Compliance Scan',
          scan_target: scanTarget || 'Unknown'
        },
        {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          responseType: 'blob'
        }
      )

      // Create a blob URL and trigger download
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5)
      link.download = `compliance_report_${timestamp}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (error: any) {
      console.error('Error generating compliance report:', error)
      alert(`Error generating compliance report: ${error.response?.data?.detail || error.message}`)
    } finally {
      setDownloadingCompliance(false)
    }
  }

  // Fetch GitHub repositories when user is logged in with GitHub
  useEffect(() => {
    const fetchRepositories = async () => {
      if (user && user.provider === 'github' && token) {
        setLoadingRepos(true)
        try {
          const response = await axios.get(`${API_URL}/auth/github/repositories`, {
            headers: { Authorization: `Bearer ${token}` }
          })
          setRepositories(response.data.repositories || [])
        } catch (error: any) {
          console.error('Error fetching repositories:', error)
          // Don't show alert - just log the error
        } finally {
          setLoadingRepos(false)
        }
      }
    }
    fetchRepositories()
  }, [user, token])

  // Fetch branches when a repository is selected
  useEffect(() => {
    let isMounted = true // Flag to prevent state updates if component unmounts
    let abortController: AbortController | null = null
    
    const fetchBranches = async () => {
      if (user && user.provider === 'github' && token && selectedRepo) {
        // Clear directory selection when GitHub repo is selected
        if (selectedDirectory) {
          setSelectedDirectory('')
          setLocalSelectedFiles(null)
          setFileContents({})
          if (onDirectorySelected) {
            onDirectorySelected([]) // Clear directory files in parent
          }
        }
        
        // Clear previous analysis results when repository changes
        // This ensures old files don't stay in the file viewer
        if (onAnalyzeGitRepo) {
          onAnalyzeGitRepo({}, '') // Clear results
        }
        setFileContents({}) // Clear file contents
        
        // Parse owner and repo from selectedRepo (format: owner/repo)
        const [owner, repo] = selectedRepo.split('/')
        if (owner && repo) {
          // Cancel any previous request
          if (abortController) {
            abortController.abort()
          }
          abortController = new AbortController()
          
          setLoadingBranches(true)
          setBranches([]) // Clear previous branches
          setRepoBranch('') // Clear selected branch
          
          try {
            const response = await axios.get(`${API_URL}/auth/github/repositories/${owner}/${repo}/branches`, {
              headers: { Authorization: `Bearer ${token}` },
              signal: abortController.signal
            })
            
            if (!isMounted) return // Don't update state if component unmounted
            
            const fetchedBranches = response.data.branches || []
            console.log('Fetched branches response:', response.data)
            console.log('Fetched branches array:', fetchedBranches)
            console.log('Branches count:', fetchedBranches.length)
            
            // Verify branch structure
            if (fetchedBranches.length > 0) {
              console.log('First branch structure:', fetchedBranches[0])
            }
            
            setBranches(fetchedBranches)
            console.log('Branches state set, will re-render with', fetchedBranches.length, 'branches')
            
            // Set default branch if available
            const selectedRepoData = repositories.find(r => r.full_name === selectedRepo)
            if (selectedRepoData && selectedRepoData.default_branch) {
              console.log('Setting default branch:', selectedRepoData.default_branch)
              setRepoBranch(selectedRepoData.default_branch)
            } else if (fetchedBranches.length > 0) {
              // If no default branch but branches exist, select the first one
              const firstBranchName = fetchedBranches[0]?.name || fetchedBranches[0]
              console.log('Setting first branch as default:', firstBranchName)
              setRepoBranch(firstBranchName)
            }
          } catch (error: any) {
            if (error.name === 'AbortError' || error.code === 'ERR_CANCELED') {
              console.log('Branch fetch cancelled')
              return
            }
            console.error('Error fetching branches:', error)
            console.error('Error details:', {
              message: error.message,
              response: error.response?.data,
              status: error.response?.status,
              url: error.config?.url
            })
            // Show user-friendly error message
            if (error.response?.status === 401 || error.response?.status === 403) {
              alert('GitHub authentication failed. Please log in again with GitHub.')
            } else if (error.response?.status === 404) {
              alert('Repository not found or you don\'t have access to it.')
            } else {
              console.warn('Failed to fetch branches. You can still enter a branch name manually.')
            }
          } finally {
            if (isMounted) {
              setLoadingBranches(false)
            }
          }
        }
      }
    }
    
    fetchBranches()
    
    // Cleanup function
    return () => {
      isMounted = false
      if (abortController) {
        abortController.abort()
      }
    }
  }, [selectedRepo, user?.provider, token]) // Removed repositories and onDirectorySelected from dependencies to prevent re-triggers

  // Debug: Log branches state changes
  useEffect(() => {
    console.log('Branches state changed:', branches)
    console.log('Branches count:', branches.length)
    console.log('Selected repo:', selectedRepo)
    console.log('Loading branches:', loadingBranches)
  }, [branches, selectedRepo, loadingBranches])

  // Removed auto-analyze - scanning will only happen when "Analyze Git Repo" button is clicked

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement
      if (menuOpen && !target.closest('.header-menu-container')) {
        setMenuOpen(false)
      }
    }
    if (menuOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [menuOpen])

  return (
    <header className="header">
      <div className="header-content">
        <div className="header-left" style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexShrink: 0 }}>
          <div className="header-title">
            <img 
              src="/assets/daifend-logo.png" 
              alt="Stratum by Daifend" 
              className="logo"
              onClick={() => {
                window.location.href = '/';
              }}
              onError={(e) => {
                // Fallback if image doesn't exist - hide the image element
                const target = e.target as HTMLImageElement;
                target.style.display = 'none';
              }}
              style={{ display: 'block', cursor: 'pointer' }}
            />
          </div>
          
          {onViewChange && (
            <div className="header-menu-container">
              <button
                className="header-menu-button"
                onClick={() => setMenuOpen(!menuOpen)}
              >
                <Menu size={18} />
                <span>{currentView === 'dashboard' ? 'Dashboard' : currentView === 'languages' ? 'Languages' : currentView === 'pricing' ? 'Pricing' : 'Support'}</span>
                <ChevronDown size={16} className={menuOpen ? 'menu-chevron-open' : ''} />
              </button>
              {menuOpen && (
                <div className="header-menu-dropdown">
                  <button
                    className={`menu-item ${currentView === 'dashboard' ? 'active' : ''}`}
                    onClick={() => {
                      onViewChange('dashboard')
                      setMenuOpen(false)
                    }}
                  >
                    <FileCode size={16} />
                    <span>Dashboard</span>
                  </button>
                  <button
                    className={`menu-item ${currentView === 'languages' ? 'active' : ''}`}
                    onClick={() => {
                      onViewChange('languages')
                      setMenuOpen(false)
                    }}
                  >
                    <Code2 size={16} />
                    <span>Languages</span>
                  </button>
                  <button
                    className={`menu-item ${currentView === 'pricing' ? 'active' : ''}`}
                    onClick={() => {
                      onViewChange('pricing')
                      setMenuOpen(false)
                    }}
                  >
                    <DollarSign size={16} />
                    <span>Pricing</span>
                  </button>
                  <button
                    className={`menu-item ${currentView === 'support' ? 'active' : ''}`}
                    onClick={() => {
                      onViewChange('support')
                      setMenuOpen(false)
                    }}
                  >
                    <HelpCircle size={16} />
                    <span>Support</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
        
        <div className="header-actions" style={{ margin: '0 auto' }}>
          <div className="git-repo-input">
            {user?.provider === 'github' ? (
              <>
                <select
                  value={selectedRepo}
                  onChange={(e) => {
                    const newRepo = e.target.value
                    // Clear previous results when repository changes
                    if (newRepo !== selectedRepo) {
                      if (onAnalyzeGitRepo) {
                        onAnalyzeGitRepo({}, '') // Clear previous analysis results
                      }
                      setFileContents({}) // Clear file contents
                      setBranches([]) // Clear branches
                      setRepoBranch('') // Clear selected branch
                    }
                    setSelectedRepo(newRepo)
                    setRepoUrl('') // Clear manual URL when using dropdown
                  }}
                  className="repo-url-input"
                  style={{ 
                    width: '100%',
                    padding: '0.5rem',
                    borderRadius: '4px',
                    border: '1px solid #475569',
                    background: '#1e293b',
                    color: '#e2e8f0',
                    fontSize: '0.9rem'
                  }}
                  disabled={loadingRepos}
                >
                  <option value="">Select Repository</option>
                  {repositories.map((repo) => (
                    <option key={repo.id} value={repo.full_name}>
                      {repo.full_name}
                    </option>
                  ))}
                </select>
                <select
                  value={repoBranch}
                  onChange={(e) => {
                    console.log('Branch selected:', e.target.value)
                    setRepoBranch(e.target.value)
                  }}
                  className="repo-branch-input"
                  style={{ 
                    width: '100%',
                    padding: '0.5rem',
                    borderRadius: '4px',
                    border: '1px solid #475569',
                    background: '#1e293b',
                    color: '#e2e8f0',
                    fontSize: '0.9rem'
                  }}
                  disabled={!selectedRepo || loadingBranches}
                >
                  <option value="">{loadingBranches ? 'Loading branches...' : 'Select Branch'}</option>
                  {branches.length > 0 ? (
                    branches.map((branch, index) => {
                      const branchName = branch?.name || branch
                      console.log(`Rendering branch ${index}:`, branchName, branch)
                      return (
                        <option key={branchName || index} value={branchName}>
                          {branchName}
                        </option>
                      )
                    })
                  ) : (
                    !loadingBranches && <option value="" disabled>No branches found</option>
                  )}
                </select>
              </>
            ) : (
              <>
                <input
                  type="text"
                  placeholder="Git repository URL (e.g., https://github.com/user/repo)"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="repo-url-input"
                />
                <input
                  type="text"
                  placeholder="Branch (optional)"
                  value={repoBranch}
                  onChange={(e) => setRepoBranch(e.target.value)}
                  className="repo-branch-input"
                />
              </>
            )}
            <button onClick={handleGitRepoAnalyze} className="btn-primary btn-git">
              <GitBranch size={18} />
              Analyze Git Repo
            </button>
          </div>
          <label 
            className="btn-secondary" 
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', width: '160px', justifyContent: 'flex-start', overflow: 'hidden' }}
            onClick={async (e) => {
              // Try File System Access API first (no white browser dialog)
              // @ts-ignore
              if ('showDirectoryPicker' in window) {
                e.preventDefault()
                await handleDirectorySelectViaAPI()
                return false
              }
              // Otherwise, let the default file input behavior happen (will show browser dialog)
            }}
          >
            <FolderOpen size={18} style={{ flexShrink: 0 }} />
            <span style={{ 
              overflow: 'hidden', 
              textOverflow: 'ellipsis', 
              whiteSpace: 'nowrap',
              flex: 1,
              minWidth: 0
            }}>
              {selectedDirectory ? selectedDirectory : 'Directory'}
            </span>
            <input
              type="file"
              id="directory-input"
              {...({ webkitdirectory: '', directory: '' } as any)}
              multiple
              onChange={handleDirectorySelect}
              style={{ display: 'none' }}
              accept=".py,.cpp,.cxx,.cc,.c++,.c,.hpp,.h,.arxml"
            />
          </label>
          {selectedDirectory && (
            <button 
              className="btn-primary"
              onClick={handleScanDirectory}
              disabled={localLoading || ((!selectedFiles || selectedFiles.length === 0) && (!localSelectedFiles || localSelectedFiles.length === 0))}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: '160px', justifyContent: 'center' }}
              title={(!selectedFiles || selectedFiles.length === 0) && (!localSelectedFiles || localSelectedFiles.length === 0) ? 'No files selected' : 'Start scanning'}
            >
              <FileCode size={18} />
              {localLoading ? 'Scanning...' : 'Scan Directory'}
            </button>
          )}
          {analysisResults && Object.keys(analysisResults).length > 0 && (
            <>
              <button 
                onClick={handleDownloadPDF} 
                className="btn-secondary"
                disabled={downloadingPDF}
                title="Download Vulnerability PDF Report"
              >
                <Download size={18} />
                {downloadingPDF ? 'Generating...' : 'Download PDF'}
              </button>
              <button 
                onClick={handleDownloadComplianceReport} 
                className="btn-secondary"
                disabled={downloadingCompliance}
                title="Download Compliance Report (ISO 21434 & UN R155)"
              >
                <Download size={18} />
                {downloadingCompliance ? 'Generating...' : 'Compliance Report'}
              </button>
            </>
          )}
        </div>
        
        {/* Avatar with dropdown menu - positioned at absolute rightmost corner, always visible */}
        <div 
          className="user-avatar-container" 
          style={{ 
            position: 'absolute',
            top: '50%',
            right: '1rem',
            transform: 'translateY(-50%)',
            display: 'flex',
            alignItems: 'center',
            zIndex: 1000,
            flexShrink: 0
          }}
        >
          {/* Avatar with first letter */}
          <div 
            className="user-avatar-initial"
            onClick={() => setAvatarMenuOpen(!avatarMenuOpen)}
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '50%',
              background: '#3b82f6',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'white',
              fontSize: '18px',
              fontWeight: 'bold',
              cursor: 'pointer',
              border: '2px solid rgba(255, 255, 255, 0.2)',
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
              transition: 'transform 0.2s, box-shadow 0.2s, background 0.2s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'scale(1.05)'
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)'
              e.currentTarget.style.background = '#2563eb'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'scale(1)'
              e.currentTarget.style.boxShadow = '0 2px 8px rgba(0, 0, 0, 0.2)'
              e.currentTarget.style.background = '#3b82f6'
            }}
            title={user ? user.email : 'User'}
          >
            {user 
              ? (user.name ? user.name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase())
              : <User size={20} strokeWidth={2.5} />
            }
          </div>
          
          {/* Dropdown Menu */}
          {avatarMenuOpen && (
            <>
              {/* Backdrop to close menu */}
              <div
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  zIndex: 998
                }}
                onClick={() => setAvatarMenuOpen(false)}
              />
              {/* Menu */}
              <div 
                className="avatar-menu-dropdown"
                style={{
                  position: 'absolute',
                  top: 'calc(100% + 8px)',
                  right: 0,
                  background: 'white',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
                  minWidth: '200px',
                  zIndex: 999,
                  overflow: 'hidden'
                }}
              >
                {user ? (
                  <>
                    <div style={{
                      padding: '12px 16px',
                      borderBottom: '1px solid #e5e7eb',
                      background: '#f9fafb'
                    }}>
                      <div style={{
                        fontSize: '0.875rem',
                        fontWeight: '500',
                        color: '#1f2937',
                        marginBottom: '4px'
                      }}>
                        {user.name || 'User'}
                      </div>
                      <div style={{
                        fontSize: '0.75rem',
                        color: '#6b7280'
                      }}>
                        {user.email}
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        logout()
                        setAvatarMenuOpen(false)
                      }}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.75rem',
                        padding: '12px 16px',
                        background: 'white',
                        border: 'none',
                        textAlign: 'left',
                        color: '#dc2626',
                        fontSize: '0.875rem',
                        fontWeight: '500',
                        cursor: 'pointer',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = '#fef2f2'
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'white'
                      }}
                    >
                      <LogOut size={16} />
                      <span>Logout</span>
                    </button>
                  </>
                ) : (
                  <div style={{
                    padding: '12px 16px',
                    fontSize: '0.875rem',
                    color: '#6b7280',
                    textAlign: 'center'
                  }}>
                    Not logged in
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
      
      <ConfirmDialog
        isOpen={showConfirmDialog}
        title="Confirm Directory Upload"
        message={`Upload ${pendingCodeFilesCount} code file${pendingCodeFilesCount !== 1 ? 's' : ''} from "${pendingDirectoryName}"?\n\nThis will upload all code files from the selected directory. Hidden files and non-code files will be excluded.\n\nTotal files in directory: ${pendingTotalFilesCount}\nCode files to upload: ${pendingCodeFilesCount}`}
        onConfirm={() => {
          if (pendingFiles) {
            setSelectedDirectory(pendingDirectoryName)
            setLocalSelectedFiles(pendingFiles)
            setShowConfirmDialog(false)
            setPendingFiles(null)
            setPendingDirectoryName('')
            setPendingCodeFilesCount(0)
            setPendingTotalFilesCount(0)
          }
        }}
        onCancel={() => {
          setShowConfirmDialog(false)
          setPendingFiles(null)
          setPendingDirectoryName('')
          setPendingCodeFilesCount(0)
          setPendingTotalFilesCount(0)
        }}
        confirmText="Upload"
        cancelText="Cancel"
      />
      
      <ConfirmDialog
        isOpen={showTimeoutDialog}
        title="Scan Status"
        message={timeoutDialogMessage}
        onConfirm={() => {
          if (timeoutDialogOnConfirm) {
            timeoutDialogOnConfirm()
          }
          setShowTimeoutDialog(false)
          setTimeoutDialogOnConfirm(null)
        }}
        onCancel={() => {
          setShowTimeoutDialog(false)
          setTimeoutDialogOnConfirm(null)
          setLocalLoading(false)
          setLoading(false)
        }}
        confirmText="Wait"
        cancelText="Cancel"
      />
    </header>
  )
}

export default Header

