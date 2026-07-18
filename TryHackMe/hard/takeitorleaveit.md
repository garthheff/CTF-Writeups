# Take It or Leave It

Room: https://tryhackme.com/room/manage/takeitorleaveit

## Introduction

**Take It or Leave It** is a business-logic challenge inspired by reports that early game-show case layouts could be predicted because the values were not independently shuffled between games.

The server creates one hidden order of 22 cash values. When a new game begins, the same order is reused but shifted to different case numbers.

By recording two games, the shift can be calculated and the location of every value in the next game can be predicted.

The room contains two flags:

* Finish with the **$250,000** case.
* Follow the predicted lowest-to-highest strategy and make the correct final decision.

---

## Starting the Challenge

Start the shared VM, then open:

```text
http://MACHINE_IP/rooms/9f48d6c2/take-it/
```

The shared VM only starts one challenge at a time, so make sure this is the first challenge URL opened after starting the machine.

Use **Play Again** between games. Restarting the VM creates a new hidden order, so any notes from the previous VM session will no longer be valid.

---

## Understanding the Flaw

A correctly designed version of the game would randomly shuffle every value into a new case before each game.

Instead, this challenge uses the same hidden sequence and moves every value by the same number of positions.

For example, suppose the value in Case 4 during Game 1 appears in Case 9 during Game 2:

```text
4 → 9

Shift = +5
```

If another value moves from Case 20 to Case 3, it confirms the same shift:

```text
20 → 21 → 22 → 1 → 2 → 3

Shift = +5
```

Once the shift is known, apply it again to predict Game 3.

---

## Step 1: Record Game 1

Play the first game through to completion.

Record the case containing each value. The optional live game record makes this easier, but the information can also be recorded manually as cases are opened.

### Lookup Table

| Money value | Game 1 case | Game 2 case | Predicted Game 3 case |
| ----------: | :---------: | :---------: | :-------------------: |
|          $1 |             |             |                       |
|          $5 |             |             |                       |
|         $10 |             |             |                       |
|         $50 |             |             |                       |
|        $100 |             |             |                       |
|        $250 |             |             |                       |
|        $500 |             |             |                       |
|        $750 |             |             |                       |
|      $1,000 |             |             |                       |
|      $3,000 |             |             |                       |
|      $5,000 |             |             |                       |
|     $10,000 |             |             |                       |
|     $15,000 |             |             |                       |
|     $20,000 |             |             |                       |
|     $35,000 |             |             |                       |
|     $50,000 |             |             |                       |
|     $75,000 |             |             |                       |
|    $100,000 |             |             |                       |
|    $150,000 |             |             |                       |
|    $200,000 |             |             |                       |
|    $225,000 |             |             |                       |
|    $250,000 |             |             |                       |

At the end of the game, record the value inside your selected case as well.

---

## Step 2: Record Game 2

Select **Play Again** and complete a second game.

Fill in the **Game 2 case** column using the same process.

Compare the same money value between the two games to calculate how far the sequence moved.

---

## Step 3: Calculate the Shift

Suppose the following values were recorded:

| Money value | Game 1 case | Game 2 case |
| ----------: | :---------: | :---------: |
|          $1 |      4      |      9      |
|    $100,000 |      20     |      3      |
|    $250,000 |      11     |      16     |

The first row gives:

```text
Case 4 → Case 9

Shift = +5
```

The $250,000 row confirms it:

```text
Case 11 → Case 16

Shift = +5
```

The $100,000 value wraps around the end of the board:

```text
Case 20 + 5 positions = Case 3
```

All values should move by the same amount.

---

## Step 4: Predict Game 3

Apply the same shift to each Game 2 position.

The formula is:

```text
Predicted case = ((Game 2 case - 1 + shift) mod 22) + 1
```

Using the example shift of `+5`:

| Money value | Game 1 | Game 2 | Predicted Game 3 |
| ----------: | :----: | :----: | :--------------: |
|          $1 |    4   |    9   |        14        |
|    $100,000 |   20   |    3   |         8        |
|    $250,000 |   11   |   16   |        21        |

### Example without wraparound

```text
Game 2 position: Case 9
Shift: +5

9 + 5 = Case 14
```

### Example with wraparound

```text
Game 2 position: Case 20
Shift: +5

20 → 21 → 22 → 1 → 2 → 3
```

The predicted position is therefore Case 3.

Fill in the predicted Game 3 position for all 22 values before beginning the winning game.

---

## Step 5: Select the $250,000 Case

Start Game 3 using **Play Again**.

Use the completed table to locate the predicted $250,000 value and select that case as your case.

Do not open it during the game.

Using the example above:

```text
Predicted $250,000 location: Case 21
```

Case 21 would be selected as the player’s case.

---

## Step 6: Open Two Confirmation Cases

The first two cases opened after selecting your case are exempt from the required lowest-to-highest sequence.

Use them to confirm that the prediction is correct.

A good choice is to open the predicted locations of the two lowest values:

```text
$1
$5
```

If both cases reveal the expected amounts, the shift calculation is correct.

If they do not match, recheck the table and the direction of the shift before continuing.

---

## Step 7: Open the Remaining Values Lowest to Highest

After the second confirmation case, every following case must be selected from the lowest remaining predicted value to the highest.

Assuming `$1` and `$5` were used as the first two confirmation cases, continue with:

```text
$10
$50
$100
$250
$500
$750
$1,000
$3,000
$5,000
$10,000
$15,000
$20,000
$35,000
$50,000
$75,000
$100,000
$150,000
$200,000
$225,000
```

Use the lookup table to translate each value into its predicted case number.

Do not simply open cases in numerical order. The required order is based on the **money values**, not the case numbers.

The selected $250,000 case remains closed.

---

## Step 8: Reject the Intermediate Offers

When the House presents an offer during the game, choose:

```text
Continue Opening
```

Continue following the lowest-to-highest table until the final decision.

Accepting an intermediate offer ends the game before the strategy can be completed.

---

## Step 9: Make the Correct Final Decision

At the end of the game, compare the House offer with the value predicted to be inside your selected case.

Use:

```text
Offer greater than your case → Take It
Your case greater than offer → Keep Your Case
```

Because the selected case should contain $250,000, the intended final choice will normally be:

```text
Keep Your Case
```

The game then reveals the selected case.

---

## Optional Live Record Hint

The live record can be enabled using the hint URL:

```text
http://MACHINE_IP/rooms/9f48d6c2/take-it/hint/f2e411beb99a0f86262af6216d53506ebf08b9d6bbb3bfc899686cb6fe8da160
```

Open the URL in the same browser session, then return to:

```text
http://MACHINE_IP/rooms/9f48d6c2/take-it/
```

The game log will record the opened case numbers and their values, making it easier to complete the lookup table.

---

## Retrieving the Flags

### Highest-Value Flag

To receive the first flag:

1. Predict the location of $250,000.
2. Select that case.
3. Keep it until the end.
4. Finish with the exact $250,000 payout.

### Strategy Flag

To receive the strategy flag:

1. Reach the prediction game.
2. Open any two confirmation cases.
3. After the second opened case, always select the lowest remaining predicted value.
4. Continue from lowest to highest without making a mistake.
5. Reject all intermediate offers.
6. Make the correct final decision.

Both flags can be earned in the same game.

---

## Troubleshooting

### The predicted cases are wrong

Check whether the shift was applied in the correct direction.

If a value moved from Case 4 in Game 1 to Case 9 in Game 2, the shift is:

```text
+5
```

It is not `-5`.

Also remember to wrap after Case 22.

---

### The table stopped matching after restarting

Restarting the VM creates a new hidden sequence.

Complete both observation games again and build a new table.

---

### The strategy flag was not awarded

Common causes include:

* Selecting one case out of value order after the first two cases.
* Accidentally skipping the lowest remaining value.
* Accepting an intermediate offer.
* Making the wrong final decision.
* Opening the predicted $250,000 case instead of keeping it.

The first two opened cases may be selected freely. The strict sequence begins with the **third opened case**.

---

### Only one flag appeared

The two flags have separate conditions.

Holding $250,000 awards the highest-value flag, but the strategy flag also requires the complete lowest-to-highest sequence and the correct final decision.

---

## Summary

```text
Complete Game 1 and record every value
                    ↓
Complete Game 2 and record every value
                    ↓
Calculate the fixed shift
                    ↓
Predict every value in Game 3
                    ↓
Select the predicted $250,000 case
                    ↓
Open two confirmation cases
                    ↓
Open every remaining value lowest to highest
                    ↓
Reject intermediate offers
                    ↓
Keep the $250,000 case
                    ↓
Capture both flags
```

The weakness is not that the case values can be guessed.

It is that the same hidden sequence is reused predictably between games.
