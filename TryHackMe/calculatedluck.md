# Calculated Luck

Room: https://tryhackme.com/room/manage/calculatedluck

## Introduction

**Calculated Luck** is a business-logic challenge inspired by a real lottery loophole.

The objective is to recognise when the lottery becomes profitable, buy tickets at the correct time, and grow the starting balance to **$1,000,000** before the flaw is fixed.

The challenge is not about predicting the winning numbers. It is about predicting when the lottery’s payout rules create a positive expected return.

---

## Starting the Challenge

The VM is shared between several challenges in the **Unhandled CTF Hub**.

Start the VM, then open:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

The first challenge URL accessed tells the server which room to start. Make sure the Calculated Luck URL is opened first after starting the VM.

If another challenge was loaded, restart the VM and open the lottery URL again.

---

## The Real-World Loophole

Calculated Luck is inspired by Jerry and Marge Selbee, who discovered a flaw in the rules of the **Winfall** and **Cash WinFall** lotteries.

When the jackpot reached its limit without a winner, the lottery triggered a **rolldown**. Instead of continuing to increase the jackpot, the money was added to the lower prize tiers.

The winning numbers remained random, but prizes for matching three, four, or five numbers became much larger.

Jerry calculated that during a rolldown, the average return from a ticket could become greater than its purchase price.

His approximate calculation for $1,100 worth of tickets was:

```text
One four-number prize:       $1,000
Three-number prizes:          $900
Estimated return:           $1,900
Estimated profit:             $800
```

A single ticket was still unlikely to win. However, purchasing thousands of tickets allowed the overall result to move closer to the mathematical average.

The flaw was therefore not weak randomness. It was a mistake in the lottery’s payout rules.

---

## Expected Value

Expected value measures the average return of an action over many attempts.

For each prize tier:

```text
Probability of winning × Prize value
```

Add the value of every prize tier, then subtract the ticket cost:

```text
Net expected value = Expected payout - Ticket price
```

The decision is simple:

```text
Negative expected value → Do not buy
Positive expected value → Buy
```

Normal lottery weeks have a negative expected value.

During a rolldown, the increased lower-tier prizes can produce a positive expected value.

---

## Challenge Objective

The jackpot rolls down when it reaches approximately:

```text
$2,000,000
```

To complete the challenge:

1. Monitor the jackpot.
2. Skip normal weeks.
3. Identify when the next drawing will cross $2 million.
4. Buy the maximum number of tickets.
5. Reinvest the profits during later rolldowns.
6. Reach a balance of $1,000,000.
7. Submit the displayed flag.

Buying tickets every week will quickly reduce the available balance.

---

## Intended Solution

Advance through the weeks while watching the jackpot.

When the jackpot is far below $2 million, do not buy tickets:

```text
Jackpot far below $2 million → Skip
```

Estimate whether the next increase will cross the threshold:

```text
Predicted jackpot =
Current jackpot + Expected increase
```

For example:

```text
Current jackpot:        $1,820,000
Expected increase:        $230,000
Predicted jackpot:      $2,050,000
```

Because the predicted jackpot exceeds $2 million, the next drawing should trigger a rolldown.

Before playing that drawing:

1. Select **Buy Maximum Tickets**.
2. Confirm the purchase.
3. Play the next week.
4. Collect the rolldown return.

Continue skipping ordinary weeks and repeating the maximum purchase before later rolldowns.

---

## Creator’s Tactic

The easiest strategy is to wait until the current jackpot is **just below $2 million**.

Use the following rule:

```text
Far below $2 million  → Skip
Just below $2 million → Buy maximum
After the rolldown    → Wait for the next one
```

Buying the maximum number of tickets during a correctly identified rolldown will generally produce enough profit to continue progressing.

There is simulated variance, so the exact return may differ between attempts. Larger purchases reduce the effect of that variance.

---

## Enabling the Jackpot Prediction

Players who are unsure when the next rolldown will occur can unlock the challenge hint.

The hint provides this URL:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/hint/4eecaa732a0adf67a9e14c6d334b5f0a4473aabb3db838fc0f927c434a63afcb
```

Open it in the same browser session, then return to:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

The game will now display a predicted jackpot amount.

Use it to make the decision:

```text
Predicted jackpot below $2 million → Skip
Predicted jackpot above $2 million → Buy maximum
```

For the easiest completion:

1. Enable the prediction.
2. Advance until the jackpot is just below $2 million.
3. Confirm that the prediction crosses $2 million.
4. Buy the maximum number of tickets.
5. Repeat until the balance reaches $1 million.

---

## Retrieving the Flag

Once the balance reaches the retirement target, the application displays the flag.

Copy the flag and submit it to the TryHackMe question.

If the first rolldown does not produce enough money, continue waiting for later rolldowns and repeat the same strategy.

---

## Troubleshooting

### The challenge does not load

Restart the VM and make sure this is the first challenge URL opened:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

### The balance keeps decreasing

Tickets are being purchased during normal weeks. Only buy when the next drawing is expected to trigger a rolldown.

### The jackpot crossed $2 million without a purchase

The opportunity was missed. Wait for the jackpot to build again or restart the game.

Tickets must be purchased before the drawing that triggers the rolldown.

### The purchase did not make enough profit

Use **Buy Maximum Tickets** rather than purchasing a small amount.

### The flaw was fixed before reaching $1 million

Restart and skip every ordinary week. Only buy maximum tickets before predicted rolldowns.

---

## Conclusion

Calculated Luck demonstrates how a system can use secure randomness and still contain an exploitable business-logic flaw.

The winning numbers cannot be predicted. The profitable conditions can.

```text
Wait for the jackpot to approach $2 million
                    ↓
Predict the next rolldown
                    ↓
Buy maximum tickets
                    ↓
Reinvest the profit
                    ↓
Reach $1 million
                    ↓
Capture the flag
```

The vulnerability is not in the lottery draw.

It is in the rules surrounding it.
