#!/bin/bash

echo "🚀 Starting Code Vulnerability Dashboard"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Kill any existing processes on ports 3000 and 8000
echo "🔍 Checking for existing processes..."
if lsof -ti:3000 > /dev/null 2>&1; then
    echo "   Stopping process on port 3000..."
    lsof -ti:3000 | xargs kill -9 2>/dev/null
fi
if lsof -ti:8000 > /dev/null 2>&1; then
    echo "   Stopping process on port 8000..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null
fi
sleep 1

echo "📦 Setting up backend..."
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Start backend in background
echo "Starting backend server on port 8000..."
python main.py &
BACKEND_PID=$!

cd ..

echo ""
echo "📦 Setting up frontend..."
cd frontend

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing Node.js dependencies..."
    npm install
fi

# Start frontend
echo "Starting frontend server on port 3000..."
npm run dev &
FRONTEND_PID=$!

cd ..

echo ""
echo "✅ Dashboard is starting!"
echo "   Backend: http://localhost:8000"
echo "   Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both servers"

# Wait for user interrupt
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait

