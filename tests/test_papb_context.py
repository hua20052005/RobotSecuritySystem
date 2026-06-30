import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PAPB_ROOT = ROOT / "motion" / "motion"
sys.path.insert(0, str(PAPB_ROOT))

from papb_validator import PapbValidator  # noqa: E402


class PapbContextPredictionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = PapbValidator.fit_from_json(
            PAPB_ROOT / "papb_competition_sequences.json",
            max_edit_distance=1,
            max_error_ratio=0.25,
            noncritical_actions=["stand", "move"],
            require_terminal=True,
        )

    def test_model_learns_probability_context_and_embeddings(self):
        model = self.validator.to_model_dict()
        self.assertEqual(len(model["transition_matrix"]), 9)
        self.assertGreaterEqual(len(model["context_transitions"]), 100)
        self.assertEqual(len(model["embedding_centers"]), 9)
        self.assertEqual(model["embedding_kind"], "transition_context")
        self.assertEqual(len(model["forbidden_transitions"]), 6)

    def test_context_predicts_twist_jump(self):
        result = self.validator.predict_next_actions(["stand", "twistBody"])
        self.assertEqual(result["context"], "stand|twistBody")
        self.assertEqual(result["candidates"][0]["action"], "twistJump")
        self.assertGreater(result["candidates"][0]["probability"], 0.5)

    def test_expected_action_is_normal(self):
        result = self.validator.predict_next_actions(
            ["stand", "twistBody"],
            actual_action="twistJump",
        )
        self.assertEqual(result["actual"]["decision"], "NORMAL")

    def test_common_high_branch_transition_is_normal(self):
        result = self.validator.predict_next_actions(
            ["stand"],
            actual_action="move",
        )
        self.assertEqual(result["actual"]["decision"], "NORMAL")

    def test_unseen_context_action_is_anomaly(self):
        result = self.validator.predict_next_actions(
            ["stand", "twistBody"],
            actual_action="backflip",
        )
        self.assertEqual(result["actual"]["decision"], "ANOMALY")

    def test_forbidden_transition_overrides_probability(self):
        result = self.validator.predict_next_actions(
            ["stand", "backflip"],
            actual_action="backflip",
        )
        self.assertEqual(result["actual"]["decision"], "ANOMALY")
        self.assertTrue(result["actual"]["forbidden"])

    def test_controlled_evaluation_set(self):
        dataset = json.loads(
            (PAPB_ROOT / "papb_competition_sequences.json").read_text(encoding="utf-8")
        )
        report = self.validator.evaluate_dataset(dataset["evaluation_sequences"])
        self.assertEqual(report["total"], 16)
        self.assertEqual(report["correct"], 16)


if __name__ == "__main__":
    unittest.main()
