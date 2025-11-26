"""
Usage Analytics Module
Tracks and provides analytics for platform usage (free vs paid users)
"""
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, Integer
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from auth import UsageLog, User


def get_usage_statistics(
    db: Session,
    days: int = 30,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Get comprehensive usage statistics.
    
    Args:
        db: Database session
        days: Number of days to look back (if start_date/end_date not provided)
        start_date: Start date for statistics
        end_date: End date for statistics
    
    Returns:
        Dictionary with usage statistics
    """
    if not start_date:
        start_date = datetime.utcnow() - timedelta(days=days)
    if not end_date:
        end_date = datetime.utcnow()
    
    # Total usage counts
    total_logs = db.query(UsageLog).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date
        )
    ).count()
    
    # Free vs Paid breakdown
    free_count = db.query(UsageLog).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_type == "free"
        )
    ).count()
    
    paid_count = db.query(UsageLog).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_type == "paid"
        )
    ).count()
    
    # Unique users
    unique_free_users = db.query(func.count(func.distinct(UsageLog.user_id))).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_type == "free",
            UsageLog.user_id.isnot(None)
        )
    ).scalar() or 0
    
    unique_paid_users = db.query(func.count(func.distinct(UsageLog.user_id))).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_type == "paid",
            UsageLog.user_id.isnot(None)
        )
    ).scalar() or 0
    
    # Anonymous users (by IP)
    unique_anonymous = db.query(func.count(func.distinct(UsageLog.ip_address))).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_id.is_(None),
            UsageLog.ip_address.isnot(None)
        )
    ).scalar() or 0
    
    # Action type breakdown
    action_breakdown = db.query(
        UsageLog.action_type,
        func.count(UsageLog.id).label('count')
    ).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date
        )
    ).group_by(UsageLog.action_type).all()
    
    action_stats = {action: count for action, count in action_breakdown}
    
    # Total files scanned
    total_files = db.query(func.sum(UsageLog.files_count)).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date
        )
    ).scalar() or 0
    
    # Total vulnerabilities found
    total_vulns = db.query(func.sum(UsageLog.vulnerabilities_found)).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date
        )
    ).scalar() or 0
    
    # Average scan duration
    avg_duration = db.query(func.avg(UsageLog.scan_duration_ms)).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.scan_duration_ms.isnot(None)
        )
    ).scalar()
    
    # Daily usage trend
    daily_usage = db.query(
        func.date(UsageLog.created_at).label('date'),
        func.count(UsageLog.id).label('count'),
        func.sum(func.cast(UsageLog.user_type == "paid", Integer)).label('paid_count'),
        func.sum(func.cast(UsageLog.user_type == "free", Integer)).label('free_count')
    ).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date
        )
    ).group_by(func.date(UsageLog.created_at)).order_by(func.date(UsageLog.created_at)).all()
    
    daily_trend = [
        {
            "date": str(date),
            "total": count,
            "paid": paid_count or 0,
            "free": free_count or 0
        }
        for date, count, paid_count, free_count in daily_usage
    ]
    
    # Subscription plan breakdown (for paid users)
    plan_breakdown = db.query(
        UsageLog.subscription_plan,
        func.count(UsageLog.id).label('count')
    ).filter(
        and_(
            UsageLog.created_at >= start_date,
            UsageLog.created_at <= end_date,
            UsageLog.user_type == "paid",
            UsageLog.subscription_plan.isnot(None)
        )
    ).group_by(UsageLog.subscription_plan).all()
    
    plan_stats = {plan or "unknown": count for plan, count in plan_breakdown}
    
    return {
        "period": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "days": (end_date - start_date).days
        },
        "summary": {
            "total_actions": total_logs,
            "free_users_actions": free_count,
            "paid_users_actions": paid_count,
            "unique_free_users": unique_free_users,
            "unique_paid_users": unique_paid_users,
            "unique_anonymous_users": unique_anonymous,
            "total_files_scanned": int(total_files),
            "total_vulnerabilities_found": int(total_vulns),
            "average_scan_duration_ms": float(avg_duration) if avg_duration else None
        },
        "action_breakdown": action_stats,
        "subscription_plan_breakdown": plan_stats,
        "daily_trend": daily_trend
    }


def get_user_usage_stats(
    db: Session,
    user_id: int,
    days: int = 30
) -> Dict[str, Any]:
    """Get usage statistics for a specific user"""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    user_logs = db.query(UsageLog).filter(
        and_(
            UsageLog.user_id == user_id,
            UsageLog.created_at >= start_date
        )
    ).all()
    
    total_actions = len(user_logs)
    total_files = sum(log.files_count for log in user_logs)
    total_vulns = sum(log.vulnerabilities_found for log in user_logs)
    
    action_counts = {}
    for log in user_logs:
        action_counts[log.action_type] = action_counts.get(log.action_type, 0) + 1
    
    return {
        "user_id": user_id,
        "period_days": days,
        "total_actions": total_actions,
        "total_files_scanned": total_files,
        "total_vulnerabilities_found": total_vulns,
        "action_breakdown": action_counts
    }

