
# Behind Door Number $RANDOM

```
“So Hacksaw was right about you all along?
That’s… actually kind of embarrassing.”
```

Not everything is as random as it seems. Every wrong choice brings you closer to the truth… if you’re smart enough to see it.

Room: https://tryhackme.com/jr/behinddoornumberrandom

## Overview

This room is based around weak randomness in Bash. The intro gives several hints:

> A true problem solver would be able to defeat even Bash’s randomness.

> I generated the true path from one seed...

> And the lies from another.

> The right numbers and the wrong numbers were not born the same.

> All you need to solve the maze has already been provided.

The goal is to work out which door numbers belong to the real Bash `$RANDOM` sequence and use that to predict the correct doors.

The game presents four doors each round. One door is correct and three are wrong. 

If it's not clear, the weakness is that Bash $RANDOM is predictable once enough outputs are observed, and using separate seeded streams for right and wrong answers creates patterns that can be isolated and cracked.

Early wrong guesses reset you instead of ending the session, which lets you collect enough numbers to identify the pattern.

## Finding the weakness

The hint points toward Bash randomness. Searching for Bash `$RANDOM` cracking leads to:

```text
https://github.com/JorianWoltjer/BashRandomCracker
```

Build the tool:

```bash
git clone https://github.com/JorianWoltjer/BashRandomCracker
cd BashRandomCracker
cargo build --release
cd target/release
```

The binary is usually:

```bash
./bashrand
```

## Cracking the maze

Because the game allows several early mistakes, collect the correct door values from the early rounds.

For example, after interacting with the first few rooms, you should be able to gather three values from the true path.

Then run:

```bash
./bashrand crack VALUE1 VALUE2 VALUE3
```

Example:

```bash
./bashrand crack 7443 14804 12957
```

If the values are from the same Bash `$RANDOM` sequence, the tool recovers the seed and predicts future outputs.

Use the predicted future values to identify the correct door numbers for the remaining rounds.

Once you choose correctly ten times in a row, you receive the first flag:

```text
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

## Final key challenge

After escaping the maze, there is one final test.

You are shown four key numbers. Three are wrong and generated from Bash `$RANDOM` using a fresh seed. One number was generated using a different method.

The challenge is to identify the number that does **not** belong to the Bash `$RANDOM` sequence.

Because the three Bash-generated wrong answers are shuffled, we need to try every group of three numbers and every possible order.

Save this as `find_bashrand.py` in the same directory as `bashrand`:

```python
import itertools
import subprocess
import sys

nums = [int(x) for x in sys.argv[1:]]

if len(nums) != 4:
    print("usage: python3 find_bashrand.py n1 n2 n3 n4")
    sys.exit(1)

total_attempts = 24
attempt = 0

for combo in itertools.combinations(nums, 3):
    for perm in itertools.permutations(combo):
        attempt += 1
        remaining = total_attempts - attempt

        print(f"[{attempt}/24] Trying {perm} | Remaining: {remaining}")

        cmd = ["./bashrand", "crack", *map(str, perm)]
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = (p.stdout + "\n" + p.stderr).strip()

        if "Seed:" in out:
            print("\n=== MATCH FOUND ===")
            print(f"triple order: {perm}")
            print(out)

            wrong = set(perm)
            correct = [n for n in nums if n not in wrong]

            if correct:
                print(f"\nCorrect outsider number: {correct[0]}")
            else:
                print("\nCould not determine outsider cleanly.")

            sys.exit(0)

print("\nNo Bash RANDOM triple found.")
```

Run it with the four key values:

```bash
python3 find_bashrand.py N1 N2 N3 N4
```

The script tries every possible shuffled triple. When `bashrand` finds a seed, those three numbers are the Bash-generated wrong answers.

The remaining number is the correct key.

Choosing the correct key gives the final flag:

```text
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

## Bonus flag

There is also a bonus flag for completing the whole room without a wrong answer.

To do that, restart the session and apply the same approach as finding the key, use the find_bashrand.py with door numbers and find the 3 incorrect doors leaving you with the correct. It should show enough wrong room doors to keep going until you can crack the correct random seed.

If completed perfectly, the bonus flag is shown:

```text
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

## Key lesson

Bash `$RANDOM` is not cryptographically secure. Given enough output values, its state can be recovered and future values can be predicted.

