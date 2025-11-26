#!/bin/bash

echo "🛑 Stopping Code Vulnerability Dashboard"
echo ""

# Kill processes on ports 3000 and 8000
if lsof -ti:3000 > /dev/null 2>&1; then
    echo "   Stopping frontend on port 3000..."
    lsof -ti:3000 | xargs kill -9 2>/dev/null
    echo "   ✅ Frontend stopped"
else
    echo "   ℹ️  No process running on port 3000"
fi

if lsof -ti:8000 > /dev/null 2>&1; then
    echo "   Stopping backend on port 8000..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null
    echo "   ✅ Backend stopped"
else
    echo "   ℹ️  No process running on port 8000"
fi

# Also kill any vite or python main.py processes
pkill -f "vite" 2>/dev/null
pkill -f "python.*main.py" 2>/dev/null

echo ""
echo "✅ All servers stopped"

