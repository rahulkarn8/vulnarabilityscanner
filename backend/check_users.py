#!/usr/bin/env python3
"""
Simple script to check users who have scanned.
Can be run directly or imported.
"""
import sys
import os
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import get_db, User, UsageLog
from sqlalchemy import func, and_

def list_users_with_scans(days=30):
    """List all users who have performed scans"""
    db = next(get_db())
    
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        print(f"\n{'='*80}")
        print(f"Users who have scanned (last {days} days)")
        print(f"{'='*80}\n")
        
        # Authenticated users
        user_stats = db.query(
            User.id,
            User.email,
            User.name,
            User.subscription_plan,
            func.count(UsageLog.id).label('scans'),
            func.sum(UsageLog.files_count).label('files'),
            func.max(UsageLog.created_at).label('last_scan')
        ).join(
            UsageLog, User.id == UsageLog.user_id
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(
            User.id, User.email, User.name, User.subscription_plan
        ).order_by(
            func.count(UsageLog.id).desc()
        ).all()
        
        if user_stats:
            print("AUTHENTICATED USERS:")
            print("-" * 80)
            print(f"{'Email':<40} {'Name':<20} {'Plan':<15} {'Scans':<8} {'Files':<8} {'Last Scan':<20}")
            print("-" * 80)
            
            for user_id, email, name, plan, scans, files, last_scan in user_stats:
                plan_str = plan or "Free"
                name_str = name or "N/A"
                files_str = str(int(files or 0))
                last_scan_str = last_scan.strftime("%Y-%m-%d %H:%M") if last_scan else "N/A"
                print(f"{email:<40} {name_str:<20} {plan_str:<15} {scans:<8} {files_str:<8} {last_scan_str:<20}")
        else:
            print("No authenticated users found.")
        
        # Anonymous users
        print(f"\n{'='*80}")
        print("ANONYMOUS USERS (by IP):")
        print("-" * 80)
        
        anonymous_stats = db.query(
            UsageLog.ip_address,
            func.count(UsageLog.id).label('scans'),
            func.sum(UsageLog.files_count).label('files'),
            func.max(UsageLog.created_at).label('last_scan')
        ).filter(
            and_(
                UsageLog.created_at >= start_date,
                UsageLog.user_id.is_(None),
                UsageLog.action_type.in_(['file_upload', 'directory_scan', 'git_repo_scan', 'code_analyze'])
            )
        ).group_by(UsageLog.ip_address).all()
        
        if anonymous_stats:
            print(f"{'IP Address':<40} {'Scans':<8} {'Files':<8} {'Last Scan':<20}")
            print("-" * 80)
            for ip, scans, files, last_scan in anonymous_stats:
                files_str = str(int(files or 0))
                last_scan_str = last_scan.strftime("%Y-%m-%d %H:%M") if last_scan else "N/A"
                print(f"{ip:<40} {scans:<8} {files_str:<8} {last_scan_str:<20}")
        else:
            print("No anonymous users found.")
        
        print(f"\n{'='*80}")
        print(f"Total authenticated users: {len(user_stats)}")
        print(f"Total anonymous IPs: {len(anonymous_stats)}")
        print(f"{'='*80}\n")
        
    finally:
        db.close()

if __name__ == "__main__":
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    list_users_with_scans(days)

