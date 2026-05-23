"""Token-level heuristics for injection detection."""

def suspicious_token_ratio(text):
    """Flag inputs with high ratio of control/instruction tokens vs content."""
    instruction_words = {'ignore', 'forget', 'override', 'disregard', 'bypass',
                         'system', 'prompt', 'instruction', 'rule', 'restrict'}
    words = text.lower().split()
    if not words:
        return 0.0
    count = sum(1 for w in words if w in instruction_words)
    return count / len(words)
