import { Code2, Shield, CheckCircle2 } from 'lucide-react'
import './Languages.css'

interface Language {
  name: string
  icon: string
  description: string
  features: string[]
  fileExtensions: string[]
}

const languages: Language[] = [
  {
    name: 'Python',
    icon: '🐍',
    description: 'Comprehensive security scanning for Python applications',
    features: [
      'SQL injection detection',
      'Command injection prevention',
      'Hardcoded credentials detection',
      'Weak cryptography identification',
      'AST-based vulnerability analysis',
      'Bandit integration'
    ],
    fileExtensions: ['.py']
  },
  {
    name: 'C++',
    icon: '⚙️',
    description: 'Advanced security analysis for C++ codebases',
    features: [
      'Buffer overflow detection',
      'Memory leak identification',
      'Use-after-free detection',
      'Format string vulnerabilities',
      'Race condition detection',
      'cppcheck integration'
    ],
    fileExtensions: ['.cpp', '.cxx', '.cc', '.c++', '.hpp', '.h', '.hxx', '.h++']
  },
  {
    name: 'C',
    icon: '🔧',
    description: 'Embedded and system-level C code security scanning',
    features: [
      'MISRA C compliance checks',
      'Unsafe function detection',
      'Pointer arithmetic analysis',
      'Stack overflow protection',
      'Memory safety checks'
    ],
    fileExtensions: ['.c', '.h']
  },
  {
    name: 'ROS 2',
    icon: '🤖',
    description: 'Robot Operating System 2 security and configuration analysis',
    features: [
      'Parameter validation checks',
      'Security strategy validation',
      'Launch file security',
      'DDS security configuration',
      'Node security patterns'
    ],
    fileExtensions: ['.launch.py', '.launch.xml', '.launch.yaml', '.params.yaml']
  },
  {
    name: 'Automotive',
    icon: '🚗',
    description: 'Automotive embedded systems and AUTOSAR security scanning',
    features: [
      'CAN bus security analysis',
      'AUTOSAR architecture checks',
      'MISRA C/C++ compliance',
      'UDS/OBD-II diagnostic security',
      'ISO 26262 functional safety',
      'ECU security patterns',
      'Embedded system vulnerabilities'
    ],
    fileExtensions: ['.c', '.cpp', '.arxml', '.xml', '.yaml']
  }
]

function Languages() {
  return (
    <div className="languages-container">
      <div className="languages-header">
        <div className="languages-title">
          <Code2 size={32} />
          <h1>Supported Languages & Frameworks</h1>
        </div>
        <p className="languages-subtitle">
          Comprehensive security scanning across multiple programming languages and domains
        </p>
      </div>

      <div className="languages-grid">
        {languages.map((lang) => (
          <div key={lang.name} className="language-card">
            <div className="language-header">
              <span className="language-icon">{lang.icon}</span>
              <h2>{lang.name}</h2>
            </div>
            <p className="language-description">{lang.description}</p>
            
            <div className="language-features">
              <h3>Security Features:</h3>
              <ul>
                {lang.features.map((feature, idx) => (
                  <li key={idx}>
                    <CheckCircle2 size={16} />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="language-extensions">
              <h3>Supported Extensions:</h3>
              <div className="extension-tags">
                {lang.fileExtensions.map((ext, idx) => (
                  <span key={idx} className="extension-tag">{ext}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="languages-footer">
        <div className="security-badge">
          <Shield size={24} />
          <div>
            <h3>Enterprise-Grade Security</h3>
            <p>All languages are scanned using industry-standard tools and custom pattern detection</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Languages

