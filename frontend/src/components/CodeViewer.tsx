import { useEffect, useRef } from 'react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { Vulnerability } from '../App'
import './CodeViewer.css'

interface CodeViewerProps {
  filePath: string | null
  content: string
  vulnerabilities: Vulnerability[]
  selectedVulnerability: Vulnerability | null
  onVulnerabilitySelect: (vuln: Vulnerability) => void
}

function CodeViewer({
  filePath,
  content,
  vulnerabilities,
  selectedVulnerability,
  onVulnerabilitySelect
}: CodeViewerProps) {
  // All hooks must be called at the top, before any conditional returns
  const codeRef = useRef<HTMLDivElement>(null)
  const lineNumbersRef = useRef<HTMLDivElement>(null)
  const codeContentRef = useRef<HTMLDivElement>(null)

  // Synchronize scrolling between line numbers and code content
  useEffect(() => {
    const lineNumbersEl = lineNumbersRef.current
    const codeContentEl = codeContentRef.current

    if (!lineNumbersEl || !codeContentEl || !filePath) return

    const handleLineNumbersScroll = () => {
      if (codeContentEl) {
        codeContentEl.scrollTop = lineNumbersEl.scrollTop
      }
    }

    const handleCodeContentScroll = () => {
      if (lineNumbersEl) {
        lineNumbersEl.scrollTop = codeContentEl.scrollTop
      }
    }

    lineNumbersEl.addEventListener('scroll', handleLineNumbersScroll)
    codeContentEl.addEventListener('scroll', handleCodeContentScroll)

    return () => {
      lineNumbersEl.removeEventListener('scroll', handleLineNumbersScroll)
      codeContentEl.removeEventListener('scroll', handleCodeContentScroll)
    }
  }, [content, filePath])

  // Scroll to selected vulnerability
  useEffect(() => {
    if (selectedVulnerability && lineNumbersRef.current) {
      const lineElement = lineNumbersRef.current.querySelector(
        `[data-line-number="${selectedVulnerability.line_number}"]`
      )
      if (lineElement) {
        lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    }
  }, [selectedVulnerability])

  const getLanguage = () => {
    if (!filePath) return 'text'
    if (filePath.endsWith('.py')) return 'python'
    if (filePath.match(/\.(cpp|cxx|cc|c\+\+|hpp|h)$/)) return 'cpp'
    return 'text'
  }

  const getLineClass = (lineNumber: number) => {
    const vuln = vulnerabilities.find(v => v.line_number === lineNumber)
    if (!vuln) return ''
    
    const isSelected = selectedVulnerability?.line_number === lineNumber
    return `vulnerable-line ${vuln.severity} ${isSelected ? 'selected' : ''}`
  }

  if (!filePath) {
    return (
      <div className="code-viewer">
        <div className="code-viewer-header">
          <h3>Code Viewer</h3>
        </div>
        <div className="code-viewer-empty">
          <p>Select a file to view its code</p>
        </div>
      </div>
    )
  }

  const lines = content.split('\n')
  const language = getLanguage()

  return (
    <div className="code-viewer">
      <div className="code-viewer-header">
        <h3>{filePath.split('/').pop() || filePath}</h3>
        <span className="vulnerability-count">
          {vulnerabilities.length} {vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'}
        </span>
      </div>
      <div className="code-viewer-content" ref={codeRef}>
        <div className="line-numbers" ref={lineNumbersRef}>
          {lines.map((_, index) => {
            const lineNumber = index + 1
            const vuln = vulnerabilities.find(v => v.line_number === lineNumber)
            return (
              <div
                key={lineNumber}
                className={`line-number ${getLineClass(lineNumber)}`}
                data-line-number={lineNumber}
                onClick={() => vuln && onVulnerabilitySelect(vuln)}
                style={{
                  height: '1.5rem',
                  lineHeight: '1.5rem'
                }}
              >
                {lineNumber}
                {vuln && (
                  <span className={`severity-indicator ${vuln.severity}`} title={vuln.vulnerability_type} />
                )}
              </div>
            )
          })}
        </div>
        <div className="code-content" ref={codeContentRef}>
          <SyntaxHighlighter
            language={language}
            style={vscDarkPlus}
            customStyle={{
              margin: 0,
              padding: '1rem',
              background: '#0f172a',
              height: '100%',
              fontSize: '0.9rem',
              lineHeight: '1.5rem'
            }}
            lineNumberStyle={{
              display: 'none'
            }}
            showLineNumbers={false}
            CodeTag={({ children, ...props }: any) => (
              <code {...props} style={{ lineHeight: '1.5rem' }}>
                {children}
              </code>
            )}
            PreTag={({ children, ...props }: any) => (
              <pre {...props} style={{ margin: 0, padding: 0, lineHeight: '1.5rem' }}>
                {children}
              </pre>
            )}
          >
            {content}
          </SyntaxHighlighter>
        </div>
      </div>
    </div>
  )
}

export default CodeViewer

