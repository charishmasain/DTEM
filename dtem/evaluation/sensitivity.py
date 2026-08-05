"""
dtem.evaluation.sensitivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Evaluates DTEM classification accuracy over a grid search of different weight configurations,
identifying the optimal weights that maximize the F1-Score against ground truth.
"""

import json
import logging
from pathlib import Path
from typing import Any

from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.evaluation.validation_data import setup_validation_db

logger = logging.getLogger(__name__)

# Output paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
EVAL_OUTPUT_DIR = PROJECT_ROOT / "output" / "evaluation"
REPORT_PATH = EVAL_OUTPUT_DIR / "weight_sensitivity_report.json"

def generate_weight_combinations(step: float = 0.1) -> list[tuple[float, float, float, float]]:
    """
    Generates combinations of four weights that sum to 1.0.
    """
    combinations = []
    # Work with integers to avoid floating point precision issues during loop
    steps = int(1.0 / step)
    for f in range(steps + 1):
        for g in range(steps + 1 - f):
            for d in range(steps + 1 - f - g):
                e = steps - f - g - d
                w_f = round(f * step, 2)
                w_g = round(g * step, 2)
                w_d = round(d * step, 2)
                w_e = round(e * step, 2)
                combinations.append((w_f, w_g, w_d, w_e))
    return combinations

def run_sensitivity_analysis(score_threshold: float = 50.0) -> dict[str, Any]:
    """
    Runs grid search over weight combinations, evaluates each combination,
    and returns a summary report of the optimal parameters.
    """
    logger.info("Initializing database with validation data...")
    ground_truth = setup_validation_db()
    
    # 1. Pre-extract features to optimize grid search speed
    extractor = ThreatInfoExtractor(recent_window_days=14)
    engine = DTEMScoringEngine()
    
    features_cache = {}
    normalized_subscores = {}
    
    for keyword in ground_truth.keys():
        feats = extractor.extract_features(keyword, auto_collect=False)
        features_cache[keyword] = feats
        
        # Calculate sub-scores using production scoring functions
        f_sub = engine._normalize_frequency(feats.get("detection_frequency", 0))
        g_sub = engine._normalize_growth_rate(feats.get("growth_rate", 0.0))
        d_sub = engine._normalize_source_diversity(feats.get("source_diversity", 0))
        
        has_exploit = feats.get("exploit_availability", False)
        exploit_ratio = feats.get("breakdown", {}).get("exploit_ratio", 0.0)
        e_sub = engine._normalize_exploit_availability(has_exploit, exploit_ratio)
        
        normalized_subscores[keyword] = (f_sub, g_sub, d_sub, e_sub)

    # 2. Perform Grid Search
    weight_combinations = generate_weight_combinations(step=0.05)
    logger.info("Generated %d weight combinations for grid search.", len(weight_combinations))
    
    results = []
    best_f1 = -1.0
    optimal_weights = None
    
    for weights in weight_combinations:
        w_f, w_g, w_d, w_e = weights
        
        tp, fp, tn, fn = 0, 0, 0, 0
        
        for keyword, actual in ground_truth.items():
            f_sub, g_sub, d_sub, e_sub = normalized_subscores[keyword]
            
            # Compute emergence score using current candidate weights
            score = (w_f * f_sub) + (w_g * g_sub) + (w_d * d_sub) + (w_e * e_sub)
            
            # Decision boundary: Emergence Score >= score_threshold -> Predicted Escalated (True)
            predicted = score >= score_threshold
            
            if predicted and actual:
                tp += 1
            elif predicted and not actual:
                fp += 1
            elif not predicted and not actual:
                tn += 1
            else:
                fn += 1
                
        # Calculate evaluation metrics
        accuracy = (tp + tn) / len(ground_truth)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Track best performance
        if f1 > best_f1:
            best_f1 = f1
            optimal_weights = weights
            
        results.append({
            "weights": {"frequency": w_f, "growth": w_g, "diversity": w_d, "exploit": w_e},
            "metrics": {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4)
            }
        })

    # 3. Evaluate Configured Baseline (Default weights in scoring.py)
    # Default is: frequency=0.25, growth=0.30, diversity=0.20, exploit=0.25
    default_w = (engine.weights.get("detection_frequency", 0.25),
                 engine.weights.get("growth_rate", 0.30),
                 engine.weights.get("source_diversity", 0.20),
                 engine.weights.get("exploit_availability", 0.25))
    
    default_metrics = next(r["metrics"] for r in results if 
                           abs(r["weights"]["frequency"] - default_w[0]) < 1e-4 and
                           abs(r["weights"]["growth"] - default_w[1]) < 1e-4 and
                           abs(r["weights"]["diversity"] - default_w[2]) < 1e-4 and
                           abs(r["weights"]["exploit"] - default_w[3]) < 1e-4)

    # 4. Prepare Report
    report = {
        "summary": {
            "total_combinations_tested": len(weight_combinations),
            "score_threshold": score_threshold,
            "optimal_weights": {
                "frequency": optimal_weights[0],
                "growth": optimal_weights[1],
                "diversity": optimal_weights[2],
                "exploit": optimal_weights[3],
                "f1_score": round(best_f1, 4)
            },
            "default_configured_weights": {
                "frequency": default_w[0],
                "growth": default_w[1],
                "diversity": default_w[2],
                "exploit": default_w[3],
                "f1_score": default_metrics["f1_score"]
            }
        },
        "top_performing_combinations": sorted(results, key=lambda x: x["metrics"]["f1_score"], reverse=True)[:10]
    }
    
    # Save report
    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        
    logger.info("Weight sensitivity report saved to %s", REPORT_PATH)
    return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    rep = run_sensitivity_analysis()
    print("Optimal Weights: ", rep["summary"]["optimal_weights"])
    print("Default Config Weights F1: ", rep["summary"]["default_configured_weights"]["f1_score"])
