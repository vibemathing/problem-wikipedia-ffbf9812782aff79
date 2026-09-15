import VibeMathingFixture
import VibeMathingFixture.TrustedChallenge

/-- The candidate theorem must inhabit the trusted-side proposition exactly. -/
example : VibeMathingTrustedChallenge.statement :=
  VibeMathingFixture.two_add_two
