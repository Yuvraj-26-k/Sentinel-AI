"""SQLAlchemy persistence for normalized Sentinel alerts."""

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    destination_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    event_type: Mapped[str] = mapped_column(String(128), default="security_alert")
    unique_ports: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str] = mapped_column(String(32), default="medium")
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")


class AlertStore:
    def __init__(self, path="~/.sentinel.db"):
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(self.engine)

    def add(self, event):
        with Session(self.engine) as session:
            alert = Alert(
                source_ip=event.get("source", "unknown"),
                destination_ip=event.get("destination", "unknown"),
                event_type=event.get("event", "security_alert"),
                unique_ports=int(event.get("unique_ports", 0)),
                event_count=int(event.get("events", 0)),
                anomaly_score=event.get("anomaly_score"),
                confidence=event.get("confidence", "medium"),
                explanation=event.get("recommendation"),
            )
            session.add(alert)
            session.commit()
            return alert.id

    def recent(self, limit=10):
        with Session(self.engine) as session:
            rows = session.scalars(select(Alert).order_by(Alert.id.desc()).limit(limit)).all()
            return [
                {"id": row.id, "time": row.timestamp.isoformat(), "source": row.source_ip, "event": row.event_type, "ports": row.unique_ports, "status": row.status}
                for row in rows
            ]
