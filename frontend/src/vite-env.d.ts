/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string
  readonly DEV: boolean
  // Add more env variables as needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

