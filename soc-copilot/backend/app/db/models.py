import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)

    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_user: Mapped[str | None] = mapped_column(String(255))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    process: Mapped[str | None] = mapped_column(String(500))

    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    # No FK to an incidents table yet — correlation still happens in memory
    # (app/correlation/timeline.py). Grouping alerts on disk is the next
    # piece once this lands.
    indicators: Mapped[list["IndicatorRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class IndicatorRecord(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(500), index=True)
    verdict: Mapped[str] = mapped_column(String(20))
    score: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str | None] = mapped_column(String(50))

    alert: Mapped["AlertRecord"] = relationship(back_populates="indicators")
