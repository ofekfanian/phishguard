"""Database layer. SQLite by default; any SQLAlchemy URL (e.g. PostgreSQL) works."""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, create_engine, func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .scorer import ScoreResult


class Base(DeclarativeBase):
    pass


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True)
    registered_domain: Mapped[str] = mapped_column(String(255), index=True)
    brand: Mapped[str] = mapped_column(String(100), index=True)
    score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    reasons: Mapped[list] = mapped_column(JSON)
    source: Mapped[str] = mapped_column(String(20))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    registered_on: Mapped[str | None] = mapped_column(String(10), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "registered_domain": self.registered_domain,
            "brand": self.brand,
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "source": self.source,
            "first_seen": self.first_seen.replace(tzinfo=timezone.utc).isoformat(),
            "registered_on": self.registered_on,
        }


class Store:
    def __init__(self, url: str):
        args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=args)
        Base.metadata.create_all(self.engine)
        # Databases created before this column existed get it added here.
        if "registered_on" not in {c["name"] for c in inspect(self.engine).get_columns("detections")}:
            with self.engine.begin() as connection:
                connection.execute(text("ALTER TABLE detections ADD COLUMN registered_on VARCHAR(10)"))

    def save(self, result: ScoreResult, source: str, registered_on: date | None = None) -> bool:
        """Save a detection. Returns False if this domain was already saved."""
        with Session(self.engine) as session:
            session.add(Detection(
                domain=result.domain[:255],
                registered_domain=result.registered_domain[:255],
                brand=result.brand or "",
                score=result.score,
                severity=result.severity,
                reasons=result.reasons,
                source=source,
                first_seen=datetime.now(timezone.utc),
                registered_on=registered_on.isoformat() if registered_on else None,
            ))
            try:
                session.commit()
            except IntegrityError:
                return False
        return True

    def list(self, min_score: int = 0, brand: str | None = None, limit: int = 100) -> list[dict]:
        query = select(Detection).where(Detection.score >= min_score)
        if brand:
            query = query.where(Detection.brand == brand)
        query = query.order_by(Detection.id.desc()).limit(limit)
        with Session(self.engine) as session:
            return [d.to_dict() for d in session.scalars(query)]

    def counts(self) -> dict:
        with Session(self.engine) as session:
            by_brand = session.execute(
                select(Detection.brand, func.count()).group_by(Detection.brand)).all()
            by_severity = session.execute(
                select(Detection.severity, func.count()).group_by(Detection.severity)).all()
        return {
            "total": sum(n for _, n in by_brand),
            "by_brand": dict(sorted(((b, n) for b, n in by_brand), key=lambda x: -x[1])),
            "by_severity": {s: n for s, n in by_severity},
        }
