"""BT — the trust boundary and its physical mechanisms (ARCHITECTURE.md §10).

Second judge, durable journal and pins, effect guard, the trust boundary and the
narrow admission gateway. Transactions, program hosting and physical adapters live in this package;
Standard's privileged assembly lives in runtime and remains part of installation trust.
Imports only `kernel` (and the checker only kernel.canon and kernel.floor0).
"""
from .assessment import SignedAssessment, TrustUnavailable, required_for
from .checker import Checker, Disagreement
from .gateway import AdmissionGateway, GatewayClient, GatewayError
from .guard import EffectPort, Guard, NotDispatched
from .journal import Halted, Journal, PinStore
from .service import TrustedService
from .signing import Signer, envelope, entry

__all__ = ["SignedAssessment", "TrustUnavailable", "required_for", "Checker", "Disagreement",
           "AdmissionGateway", "GatewayClient", "GatewayError",
           "EffectPort", "Guard", "NotDispatched", "Halted", "Journal", "PinStore", "TrustedService", "Signer",
           "envelope", "entry"]
