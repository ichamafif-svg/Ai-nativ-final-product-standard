"""T — the Trusted External side of the TCB (ARCHITECTURE.md §10).

Second judge, durable journal and pins, effect guard, trusted time, escalation delivery, the trust boundary and the
narrow admission gateway. Imports only `kernel` (and the checker only kernel.canon and kernel.floor0).
"""
from .boundary import SignedAssessment, TrustUnavailable, required_for
from .checker import Checker, Disagreement
from .clock import ClockError, WitnessClock
from .delivery import DeliveryError, EscalationOutbox
from .gateway import AdmissionGateway, GatewayClient, GatewayError
from .guard import EffectPort, Guard, NotDispatched
from .journal import Halted, Journal, PinStore
from .service import TrustedService
from .signing import Signer, envelope, entry

__all__ = ["SignedAssessment", "TrustUnavailable", "required_for", "Checker", "Disagreement", "ClockError",
           "WitnessClock", "DeliveryError", "EscalationOutbox", "AdmissionGateway", "GatewayClient", "GatewayError",
           "EffectPort", "Guard", "NotDispatched", "Halted", "Journal", "PinStore", "TrustedService", "Signer",
           "envelope", "entry"]
