const clamp01 = (value) => Math.max(0, Math.min(1, Number.isFinite(Number(value)) ? Number(value) : 0))

const round3 = (value) => Math.round(clamp01(value) * 1000) / 1000

const TEXT = {
  pendingRisk: '\u5f85\u786e\u8ba4\u98ce\u9669',
  highRisk: '\u9ad8\u98ce\u9669',
  mediumRisk: '\u4e2d\u98ce\u9669',
  lowRisk: '\u4f4e\u98ce\u9669',
  safe: '\u4f4e\u98ce\u9669/\u6b63\u5e38',
  side: '\u8fde\u63a5\u884c\u4e3a\u611f\u77e5',
  payload: '\u8f7d\u8377\u6a21\u5f0f\u7814\u5224',
  motion: '\u52a8\u4f5c\u6d41\u7a0b\u6821\u9a8c',
  noValid: '\u6682\u65e0\u6709\u6548\u7ef4\u5ea6',
  formulaBrief: '\u6700\u5927\u98ce\u9669\u4fdd\u5e95 + \u52a0\u6743\u5e73\u5747 + \u4e00\u81f4\u6027\u589e\u76ca',
}

const STATUS_FLOORS = {
  NORMAL: 0.05,
  SAFE: 0.05,
  SUCCESS: 0.05,
  TOLERATED: 0.38,
  NORMAL_WITH_TOLERANCE: 0.38,
  LOW_RISK: 0.38,
  UNKNOWN: 0.52,
  UNKNOWN_VALIDITY: 0.55,
  REVIEW: 0.55,
  ANOMALY: 0.86,
  HIGH_RISK: 0.86,
}

const DEFAULT_WEIGHTS = {
  side: 0.28,
  payload: 0.42,
  motion: 0.30,
}

const statusFloor = (status) => STATUS_FLOORS[String(status || 'UNKNOWN').toUpperCase()] ?? 0.52

const riskLevel = (score, missingCount) => {
  if (missingCount > 0 && score < 0.3) return { level: 'UNKNOWN_RISK', label: TEXT.pendingRisk }
  if (score >= 0.80) return { level: 'HIGH_RISK', label: TEXT.highRisk }
  if (score >= 0.55) return { level: 'MEDIUM_RISK', label: TEXT.mediumRisk }
  if (score >= 0.30) return { level: 'LOW_RISK', label: TEXT.lowRisk }
  return { level: 'SAFE', label: TEXT.safe }
}

const baseDimension = (key, label, status, state, result, weight) => ({
  key,
  label,
  status,
  state,
  result,
  weight,
  enabled: true,
  valid: state === 'DONE' && Boolean(result),
  score: 0,
  evidence: [],
})

const scoreSide = (input, weight) => {
  const item = baseDimension('side', TEXT.side, input.status, input.state, input.result, weight)
  if (!item.valid) return item
  const ratio = Number(input.result?.summary?.ratio || 0)
  const abnormal = Number(input.result?.summary?.abnormal || 0)
  const total = Number(input.result?.summary?.total || 0)
  const ratioScore = clamp01(ratio / 0.20)
  item.score = round3(Math.max(statusFloor(input.status), ratioScore))
  item.evidence = [
    `\u5f02\u5e38\u7247\u6bb5\u5360\u6bd4 ${(ratio * 100).toFixed(2)}%`,
    `\u5019\u9009\u5f02\u5e38 ${abnormal}/${total}`,
  ]
  return item
}

const scorePayload = (input, weight) => {
  const item = baseDimension('payload', TEXT.payload, input.status, input.state, input.result, weight)
  if (!item.valid) return item
  const abnormalRatio = Number(input.result?.abnormal_ratio || 0)
  const lowConfidence = Number(input.result?.low_confidence_count || 0)
  const ratioScore = clamp01(abnormalRatio / 35)
  item.score = round3(Math.max(statusFloor(input.status), ratioScore))
  item.evidence = [
    `\u5f02\u5e38\u5360\u6bd4 ${abnormalRatio.toFixed(2)}%`,
    `\u4f4e\u7f6e\u4fe1\u7ed3\u679c ${lowConfidence} \u4e2a`,
  ]
  return item
}

const scoreMotion = (input, weight) => {
  const item = baseDimension('motion', TEXT.motion, input.status, input.state, input.result, weight)
  if (!item.valid) return item
  const actionCount = Number(input.result?.actions?.length || 0)
  const transitionRisk = Number(
    input.result?.flow_validation?.transition_check?.max_risk
      ?? input.result?.recognition?.transition_check?.max_risk
      ?? 0,
  )
  item.score = round3(Math.max(statusFloor(input.status), clamp01(transitionRisk)))
  item.evidence = [
    `\u6d41\u7a0b\u72b6\u6001 ${input.status || 'UNKNOWN'}`,
    `\u52a8\u4f5c\u7247\u6bb5 ${actionCount} \u4e2a`,
    `\u6700\u9ad8\u8f6c\u79fb\u98ce\u9669 ${Number.isFinite(transitionRisk) ? transitionRisk.toFixed(2) : '0.00'}`,
  ]
  return item
}

const consistencyBonus = (validItems) => {
  const high = validItems.filter((item) => item.score >= 0.70).length
  const medium = validItems.filter((item) => item.score >= 0.45).length
  const uncertain = validItems.filter((item) => ['UNKNOWN', 'UNKNOWN_VALIDITY', 'REVIEW'].includes(String(item.status || '').toUpperCase())).length
  if (high >= 2) return 0.10
  if (high >= 1 && medium >= 2) return 0.08
  if (medium >= 2) return 0.05
  if (high >= 1 && uncertain >= 1) return 0.03
  return 0
}

export function calculateUnifiedRisk({ enabled, dimensions, weights = DEFAULT_WEIGHTS }) {
  const rawItems = [
    enabled.side ? scoreSide(dimensions.side, weights.side) : { key: 'side', label: TEXT.side, enabled: false, valid: false, weight: weights.side, score: 0, evidence: [] },
    enabled.payload ? scorePayload(dimensions.payload, weights.payload) : { key: 'payload', label: TEXT.payload, enabled: false, valid: false, weight: weights.payload, score: 0, evidence: [] },
    enabled.motion ? scoreMotion(dimensions.motion, weights.motion) : { key: 'motion', label: TEXT.motion, enabled: false, valid: false, weight: weights.motion, score: 0, evidence: [] },
  ]

  const validItems = rawItems.filter((item) => item.enabled !== false && item.valid)
  const missingDimensions = rawItems
    .filter((item) => item.enabled !== false && !item.valid)
    .map((item) => item.label)

  if (!validItems.length) {
    return {
      score: 0,
      score_percent: 0,
      level: 'UNKNOWN_RISK',
      level_label: TEXT.pendingRisk,
      formula: 'R = min(1, max(max(r_i), weighted_avg + delta))',
      formula_brief: TEXT.noValid,
      weights,
      dimensions: rawItems,
      max_dimension_score: 0,
      weighted_average: 0,
      consistency_bonus: 0,
      missing_dimensions: missingDimensions,
    }
  }

  const weightSum = validItems.reduce((sum, item) => sum + Number(item.weight || 0), 0) || 1
  const weightedAverage = validItems.reduce((sum, item) => sum + item.score * Number(item.weight || 0), 0) / weightSum
  const maxDimensionScore = Math.max(...validItems.map((item) => item.score))
  const bonus = consistencyBonus(validItems)
  const score = round3(Math.max(maxDimensionScore, weightedAverage + bonus))
  const level = riskLevel(score, missingDimensions.length)

  return {
    score,
    score_percent: Math.round(score * 100),
    level: level.level,
    level_label: level.label,
    formula: 'R = min(1, max(max(r_i), weighted_avg + delta))',
    formula_brief: TEXT.formulaBrief,
    weights,
    dimensions: rawItems.map((item) => ({
      key: item.key,
      label: item.label,
      status: item.status || 'PENDING',
      state: item.state || 'PENDING',
      enabled: item.enabled !== false,
      valid: item.valid,
      weight: item.weight,
      score: item.score,
      evidence: item.evidence,
    })),
    max_dimension_score: round3(maxDimensionScore),
    weighted_average: round3(weightedAverage),
    consistency_bonus: bonus,
    missing_dimensions: missingDimensions,
  }
}
