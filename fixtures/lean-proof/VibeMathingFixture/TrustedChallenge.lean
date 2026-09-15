import Mathlib.Data.Nat.Notation

namespace VibeMathingTrustedChallenge

/-- Trusted-side statement constant. Candidate proof files must not define or rewrite it. -/
def statement : Prop := (2 : ℕ) + 2 = 4

end VibeMathingTrustedChallenge
