import os
import json
import uuid
import base64
import hashlib
from datetime import datetime
from collections import deque
from detoxify import Detoxify

# =====================================================================
# 1. PROTECTIVE CHILD-SAFETY THRESHOLDS (Custom Per Harm Category)
# =====================================================================
PROTECTIVE_THRESHOLDS = {
    "threat": 0.35,           # Ultra-protective: Flag physical threats/harm at 35%+
    "severe_toxicity": 0.35,  # Ultra-protective: Flag extreme abuse at 35%+
    "identity_attack": 0.45,  # Protective: Flag targeted identity harassment at 45%+
    "insult": 0.45,           # Protective: Flag personal cyberbullying insults at 45%+
    "toxicity": 0.50,         # Balanced protective: Flag general toxic hostility at 50%+
    "obscene": 0.55           # Prevents false alarms on mild non-targeted teen slang
}

# Storage files for State B (Local Evidence Vault) & State C (SafetyEvent Outbox)
STATE_B_VAULT_FILE = "safenet_state_b_vault.json"
STATE_C_OUTBOX_FILE = "safenet_state_c_outbox.json"


class SafeNetUnifiedEngine:
    def __init__(self, model_type="unbiased-small"):
        print("Initializing SafeNet Layer 1 (Context AI) & Three-State Memory...")
        self.model = Detoxify(model_type)
        
        # STATE A: Temporary RAM Ring Buffer (Holds only the last 5 messages in RAM)
        self.state_a_ram_buffer = deque(maxlen=5)
        self.session_id = f"sess_{uuid.uuid4().hex[:8]}"
        print("SafeNet Engine Ready!\n")

    def _encrypt_evidence_payload(self, plaintext_data: dict) -> str:
        """
        Simulates Section 17 / State B local encryption before writing evidence to disk.
        Encodes the JSON context window so raw text is obfuscated in local storage.
        """
        raw_bytes = json.dumps(plaintext_data).encode("utf-8")
        encoded_payload = base64.b64encode(raw_bytes).decode("utf-8")
        integrity_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]
        return f"AES256_ENC::{integrity_hash}::{encoded_payload}"

    def _store_state_b_and_c(self, flagged_msg: str, trigger_cat: str, score: float, severity: str, all_scores: dict):
        """
        Executes Section 49 Three-State Data Model:
        - Saves encrypted context window to State B Local Vault
        - Saves decoupled SafetyEvent metadata to State C Outbox for Layers 2-7
        """
        timestamp = datetime.now().isoformat()
        evidence_id = f"ev_{uuid.uuid4().hex[:10]}"
        event_id = f"evt_{uuid.uuid4().hex[:10]}"

        # 1. Select Relevant Context Window from State A RAM
        context_window = list(self.state_a_ram_buffer)

        # 2. Construct & Encrypt State B Evidence Record
        raw_evidence = {
            "session_id": self.session_id,
            "flagged_message": flagged_msg,
            "surrounding_context_window": context_window
        }
        state_b_record = {
            "evidence_id": evidence_id,
            "timestamp": timestamp,
            "retention_policy": "LOCAL_ENCRYPTED_RETENTION_ONLY",
            "encrypted_payload": self._encrypt_evidence_payload(raw_evidence),
            "readable_preview_for_demo": raw_evidence  # Kept so you can inspect it in VS Code
        }

        # Save to State B Vault File
        vault_data = []
        if os.path.exists(STATE_B_VAULT_FILE):
            with open(STATE_B_VAULT_FILE, "r", encoding="utf-8") as f:
                vault_data = json.load(f)
        vault_data.append(state_b_record)
        with open(STATE_B_VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(vault_data, f, indent=4)

        # 3. Construct State C SafetyEvent (Feeds the other 6 ML Models)
        state_c_event = {
            "event_id": event_id,
            "session_id": self.session_id,
            "timestamp": timestamp,
            "status": "RISK_DETECTED",
            "safety_state": severity,          # ELEVATED, HIGH, or CRITICAL (Section 20)
            "primary_category": trigger_cat.upper(),
            "risk_probability": round(score, 4),
            "layer1_feature_vector": all_scores, # Numerical input for Layer 2/4/5 ML Models!
            "evidence_reference_id": evidence_id
        }

        # Save to State C Outbox File
        outbox_data = []
        if os.path.exists(STATE_C_OUTBOX_FILE):
            with open(STATE_C_OUTBOX_FILE, "r", encoding="utf-8") as f:
                outbox_data = json.load(f)
        outbox_data.append(state_c_event)
        with open(STATE_C_OUTBOX_FILE, "w", encoding="utf-8") as f:
            json.dump(outbox_data, f, indent=4)

        return evidence_id, event_id

    def monitor_message(self, message: str) -> dict:
        # Step 1: Push incoming message into State A (Short-lived RAM Buffer)
        self.state_a_ram_buffer.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "text": message
        })

        # Step 2: Run Pre-Trained Detoxify Model
        raw_scores = self.model.predict(message)
        clean_scores = {k: round(float(v), 4) for k, v in raw_scores.items()}

        # Step 3: Check against Protective Child-Safety Thresholds
        triggered_categories = []
        for category, cutoff in PROTECTIVE_THRESHOLDS.items():
            if clean_scores[category] >= cutoff:
                triggered_categories.append((category, clean_scores[category]))

        # Find highest overall score for reporting
        top_category = max(PROTECTIVE_THRESHOLDS.keys(), key=lambda k: clean_scores[k])
        top_score = clean_scores[top_category]

        # Step 4: Binary Decision -> RISK_DETECTED vs NOT_A_RISK
        if triggered_categories:
            # Sort by most severe triggered category
            triggered_categories.sort(key=lambda x: x[1], reverse=True)
            primary_trigger, trigger_score = triggered_categories[0]

            # Map to SafeNet PDF Section 20 Operational States
            if trigger_score >= 0.80 or primary_trigger in ["threat", "severe_toxicity"] and trigger_score >= 0.60:
                severity_state = "CRITICAL"
            elif trigger_score >= 0.60:
                severity_state = "HIGH"
            else:
                severity_state = "ELEVATED"

            # Execute State B (Vault Retention) & State C (SafetyEvent Dispatch)
            ev_id, evt_id = self._store_state_b_and_c(
                message, primary_trigger, trigger_score, severity_state, clean_scores
            )

            return {
                "classification": "RISK_DETECTED",
                "safety_state": severity_state,
                "confidence": f"{round(trigger_score * 100, 2)}%",
                "reason": primary_trigger.upper(),
                "memory_action": f"Saved to State B Vault ({ev_id}) & State C Outbox ({evt_id})"
            }
        else:
            # FR-03 Zero-Trace Disposal: No disk write, message expires from RAM naturally
            return {
                "classification": "NOT_A_RISK",
                "safety_state": "NORMAL",
                "confidence": f"{round((1.0 - top_score) * 100, 2)}%",
                "reason": "SAFE_MESSAGE",
                "memory_action": "FR-03 Zero-Trace Disposal (Not saved to disk)"
            }


if __name__ == "__main__":
    engine = SafeNetUnifiedEngine(model_type="unbiased-small")

    print("=" * 68)
    print("  SAFENET CHILD-SAFETY MONITOR (Three-State Memory Active)")
    print("  Type 'exit' to quit.")
    print("=" * 68)

    while True:
        msg = input("\nEnter Message: ")
        if msg.strip().lower() in ["exit", "quit"]:
            print("Shutting down SafeNet Monitor.")
            break
        if not msg.strip():
            continue

        res = engine.monitor_message(msg)
        print("-" * 60)
        print(f" -> Decision     : {res['classification']} (State: {res['safety_state']})")
        print(f" -> Confidence   : {res['confidence']}")
        print(f" -> Harm Trigger : {res['reason']}")
        print(f" -> Memory Step  : {res['memory_action']}")
        print("-" * 60)