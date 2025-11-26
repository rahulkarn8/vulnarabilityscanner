import { X } from 'lucide-react'
import './ConfirmDialog.css'

interface ConfirmDialogProps {
  isOpen: boolean
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
  confirmText?: string
  cancelText?: string
}

function ConfirmDialog({ 
  isOpen, 
  title, 
  message, 
  onConfirm, 
  onCancel, 
  confirmText = 'Confirm',
  cancelText = 'Cancel'
}: ConfirmDialogProps) {
  if (!isOpen) return null

  return (
    <div className="confirm-dialog-overlay" onClick={onCancel}>
      <div className="confirm-dialog-content" onClick={(e) => e.stopPropagation()}>
        <button className="confirm-dialog-close" onClick={onCancel}>
          <X size={20} />
        </button>
        <div className="confirm-dialog-header">
          <h2>{title}</h2>
        </div>
        <div className="confirm-dialog-body">
          <p>{message}</p>
        </div>
        <div className="confirm-dialog-footer">
          <button className="confirm-dialog-btn confirm-dialog-btn-cancel" onClick={onCancel}>
            {cancelText}
          </button>
          <button className="confirm-dialog-btn confirm-dialog-btn-confirm" onClick={onConfirm}>
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  )
}

export default ConfirmDialog

