

def test_rmap_guess():
    validNonce = secrets.randbits(64)

    attempt = 10_000
    success = 0

    for _ in range(attempt):
        guessedNonce = secrets.randbits(64)

        if guessedNonce == validNonce:
            success += 1

    print(f"\nNonce guesses attempted: {attempt}")
    print(f"Successful guesses: {success}")
    print(f"Observed success rate: {success / attempt:.6f}")