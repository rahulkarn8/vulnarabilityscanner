import { useState } from 'react'
import { AlertCircle, CheckCircle, ChevronRight, ChevronDown, Folder, FolderOpen } from 'lucide-react'
import { FileAnalysis } from '../App'
import './FileTree.css'

interface FileTreeProps {
  files: string[]
  selectedFile: string | null
  onFileSelect: (file: string) => void
  analysisResults: Record<string, FileAnalysis>
}

interface FileNode {
  name: string
  path: string
  type: 'file' | 'folder'
  children?: FileNode[]
  fullPath?: string
}

function FileTree({ files, selectedFile, onFileSelect, analysisResults }: FileTreeProps) {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set())

  // Filter out .git and non-code files
  const filterCodeFiles = (filePaths: string[]): string[] => {
    const codeExtensions = [
      '.py', '.cpp', '.cxx', '.cc', '.c++', '.c', '.hpp', '.h', '.hxx', '.h++',
      '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
      '.html', '.css', '.scss', '.sass', '.less',
      '.arxml', '.dbc', '.ldf', '.sym', '.a2l', '.odx', '.pdx', '.cdd', '.ecuc', '.epc'
    ]
    
    return filePaths.filter(filePath => {
      // Skip .git directories and files
      if (filePath.includes('/.git/') || filePath.startsWith('.git/') || filePath === '.git') {
        return false
      }
      
      // Skip hidden files and directories (except if they're code files)
      const parts = filePath.split('/')
      if (parts.some(part => part.startsWith('.') && part !== '.' && part !== '..')) {
        // Allow hidden files if they have code extensions
        const fileName = parts[parts.length - 1]
        const ext = fileName.substring(fileName.lastIndexOf('.'))
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
      const fileName = parts[parts.length - 1]
      const ext = fileName.substring(fileName.lastIndexOf('.'))
      return codeExtensions.includes(ext.toLowerCase())
    })
  }

  // Build hierarchical tree structure from file paths
  const buildTree = (filePaths: string[]): FileNode[] => {
    const tree: FileNode[] = []
    const pathMap = new Map<string, FileNode>()

    filePaths.forEach(filePath => {
      const parts = filePath.split('/')
      let currentPath = ''
      
      parts.forEach((part, index) => {
        const isFile = index === parts.length - 1
        const parentPath = currentPath
        currentPath = currentPath ? `${currentPath}/${part}` : part
        
        if (!pathMap.has(currentPath)) {
          const node: FileNode = {
            name: part,
            path: currentPath,
            type: isFile ? 'file' : 'folder',
            children: isFile ? undefined : []
          }
          
          if (isFile) {
            node.fullPath = filePath
          }
          
          pathMap.set(currentPath, node)
          
          if (parentPath) {
            const parent = pathMap.get(parentPath)
            if (parent && parent.children) {
              parent.children.push(node)
            }
          } else {
            tree.push(node)
          }
        }
      })
    })

    return tree
  }

  const toggleFolder = (path: string) => {
    setExpandedFolders(prev => {
      const newSet = new Set(prev)
      if (newSet.has(path)) {
        newSet.delete(path)
      } else {
        newSet.add(path)
      }
      return newSet
    })
  }

  const getFileIcon = (file: string) => {
    if (file.endsWith('.py')) return '🐍'
    if (file.match(/\.(cpp|cxx|cc|c\+\+|hpp|h)$/)) return '⚙️'
    return '📄'
  }

  const getVulnerabilityCount = (file: string) => {
    const result = analysisResults[file]
    if (!result || result.error) return null
    return result.total_vulnerabilities
  }

  const getSeverityColor = (file: string) => {
    const result = analysisResults[file]
    if (!result || result.error) return null
    
    const vulns = result.vulnerabilities
    if (vulns.some(v => v.severity === 'critical')) return 'critical'
    if (vulns.some(v => v.severity === 'high')) return 'high'
    if (vulns.some(v => v.severity === 'medium')) return 'medium'
    if (vulns.some(v => v.severity === 'low')) return 'low'
    return 'safe'
  }

  const renderNode = (node: FileNode, level: number = 0): JSX.Element => {
    const isExpanded = expandedFolders.has(node.path)
    const filePath = node.fullPath || node.path
    const isSelected = selectedFile === filePath
    const hasError = filePath && analysisResults[filePath]?.error
    const count = filePath ? getVulnerabilityCount(filePath) : null
    const severity = filePath ? getSeverityColor(filePath) : null

    if (node.type === 'folder') {
      return (
        <div key={node.path}>
          <div
            className="file-tree-folder"
            style={{ paddingLeft: `${level * 1.25}rem` }}
            onClick={() => toggleFolder(node.path)}
          >
            <span className="folder-icon">
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              {isExpanded ? <FolderOpen size={16} /> : <Folder size={16} />}
            </span>
            <span className="folder-name">{node.name}</span>
          </div>
          {isExpanded && node.children && (
            <div className="file-tree-children">
              {node.children.map(child => renderNode(child, level + 1))}
            </div>
          )}
        </div>
      )
    }

    return (
      <div
        key={node.path}
        className={`file-tree-item ${isSelected ? 'selected' : ''}`}
        style={{ paddingLeft: `${level * 1.25}rem` }}
        onClick={() => filePath && onFileSelect(filePath)}
      >
        <div className="file-tree-item-content">
          <span className="file-icon">{getFileIcon(node.name)}</span>
          <span className="file-name" title={filePath}>
            {node.name}
          </span>
        </div>
        <div className="file-tree-item-badge">
          {hasError ? (
            <AlertCircle size={16} className="error-icon" />
          ) : count !== null && count > 0 ? (
            <span className={`vuln-count ${severity}`}>{count}</span>
          ) : count === 0 ? (
            <CheckCircle size={16} className="safe-icon" />
          ) : null}
        </div>
      </div>
    )
  }

  // Debug: Log files and analysis results
  console.log('FileTree rendered - files prop:', files)
  console.log('FileTree - files.length:', files.length)
  console.log('FileTree - files array:', JSON.stringify(files))
  console.log('FileTree - analysisResults keys:', Object.keys(analysisResults))
  console.log('FileTree - analysisResults count:', Object.keys(analysisResults).length)

  // Filter files to show only code files
  const filteredFiles = filterCodeFiles(files)
  
  if (filteredFiles.length === 0) {
    console.warn('FileTree: files array is empty after filtering!')
    return (
      <div className="file-tree">
        <div className="file-tree-header">
          <h2>Explorer</h2>
        </div>
        <div className="file-tree-empty">
          <p>No code files found</p>
          <p className="hint">Select a directory or upload files to view them</p>
        </div>
      </div>
    )
  }

  const tree = buildTree(filteredFiles)
  console.log('FileTree - built tree with', tree.length, 'root nodes')

  return (
    <div className="file-tree">
      <div className="file-tree-header">
        <h2>Explorer</h2>
        <span className="file-count">{filteredFiles.length} {filteredFiles.length === 1 ? 'file' : 'files'}</span>
      </div>
      <div className="file-tree-list">
        {tree.map(node => renderNode(node))}
      </div>
    </div>
  )
}

export default FileTree
