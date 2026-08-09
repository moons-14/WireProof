from wireproof_evidence import EvidenceRecord, Result


def lab_doctor() -> EvidenceRecord:
    """M1 foundation intentionally never probes or controls Docker."""
    return EvidenceRecord(
        change_id="lab-doctor",
        result=Result.UNKNOWN,
        semantic_ir_hash="uncompiled",
        reason="LAB_ENVIRONMENT_UNAVAILABLE",
    )
