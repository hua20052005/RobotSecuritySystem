# modules/inference/__init__.py
"""
推理管道包
"""

from .pipeline import PayloadDetectionPipeline
from .scorer import FusionScorer

# 兼容旧名称
InferencePipeline = PayloadDetectionPipeline

__all__ = [
    'PayloadDetectionPipeline',
    'InferencePipeline',
    'FusionScorer',
]
