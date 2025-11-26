import './Footer.css'

function Footer() {
  return (
    <footer className="app-footer">
      <div className="footer-content">
        <p className="footer-copyright">
          © {new Date().getFullYear()} DAIFEND. All rights reserved.
        </p>
      </div>
    </footer>
  )
}

export default Footer

