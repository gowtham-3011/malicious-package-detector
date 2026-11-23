"""Synthetic, INERT package corpus for evaluating the detector.

Every "malicious" sample here reproduces the *shape* of a documented supply-chain attack
technique, but cannot do harm: all hosts use the reserved ``.example`` TLD (RFC 2606, cannot
resolve), webhook IDs are zeros, secrets are only ever referenced by name, and the samples
are built in memory and never executed - the detector only reads them.

Splits:
  dev       families used while building the rules (iterate freely against these)
  heldout   families written separately; reported as a generalisation check
  adaptive  evasions written AFTER reading the v1 rules, each targeting a named assumption
  benign    ordinary packages, plus hard negatives that look suspicious but are not
"""

from .samples import Sample, generate  # noqa: F401
