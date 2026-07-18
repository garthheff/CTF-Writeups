# Calculated Luck

Room: https://tryhackme.com/room/manage/calculatedluck

## Introduction

**Calculated Luck** is a business-logic challenge inspired by a real lottery flaw.

The challenge is not about predicting random numbers or manipulating a lottery draw. Instead, the goal is to recognise when the lottery’s payout rules temporarily make buying tickets profitable.

Players must analyse the jackpot, identify an upcoming **rolldown**, invest at the correct time, and grow their balance to **$1,000,000** before the flaw is fixed.

---

## Learning Objectives

By completing this challenge, players will learn how to:

* Identify a business-logic vulnerability.
* Calculate the expected value of an action.
* Distinguish randomness from predictable system behaviour.
* Recognise how scale can reduce the effect of short-term variance.
* Exploit a valid system feature in an unintended way.

---

## Starting the Challenge

The VM used by this challenge is shared with other rooms in the **Unhandled CTF Hub**.

Start the VM from the shared hosting room, then access:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

The VM starts with no individual challenge running. The first challenge URL accessed tells the server which room to load, and only that challenge will be started.

Make sure the **Calculated Luck** URL is the first challenge URL opened after starting the VM.

If another challenge was opened first, restart the VM and then access the Calculated Luck URL.

---

# The Real-World Exploit

## Winfall and Cash WinFall

Calculated Luck is inspired by Jerry and Marge Selbee, who discovered that a lottery’s payout rules could temporarily produce a positive expected return.

The original Michigan game, **Winfall**, used $1 tickets where players selected six numbers from 1 to 49. The important weakness was not in the random-number generation—it was in what happened when the jackpot reached its limit without a jackpot winner.

During a normal week, the jackpot continued growing and the lower prize tiers remained relatively small. During a **rolldown**, however, jackpot money was redistributed among players who matched fewer numbers.

This increased the value of the lower prize tiers. For example:

| Match         | Normal prize | Approximate rolldown prize |
| ------------- | -----------: | -------------------------: |
| Four numbers  |         $100 |                     $1,000 |
| Three numbers |           $5 |                        $50 |

The winning numbers were still random, but the payout structure had changed. During the right drawing, the average value of a ticket could become greater than its purchase price.

Jerry later applied the same strategy to Massachusetts **Cash WinFall**, where rolldowns occurred when the jackpot reached approximately $2 million without being won. Large groups could purchase enough tickets during these periods to make a profit increasingly likely.

---

## Jerry Selbee’s Calculation

Jerry estimated that buying approximately **$1,100 worth of tickets** during a rolldown would produce:

* Approximately one four-number match worth $1,000.
* Approximately eighteen or nineteen three-number matches worth about $900 in total.

His estimated return was therefore:

```text
$1,000 + $900 = $1,900
```

After subtracting the original investment:

```text
$1,900 - $1,100 = $800 estimated profit
```

This did not mean that every $1,100 purchase was guaranteed to return exactly $1,900. It meant that, across enough tickets and repeated rolldowns, the average result was expected to be profitable.

The Selbees began with smaller tests and eventually scaled their purchases dramatically. Across the lottery games they played, they grossed approximately $26 million. Their method was based on reading the rules, calculating the probabilities, and purchasing tickets only when the payout conditions were favourable.

---

# Understanding Expected Value

The mathematical concept behind the strategy is **expected value**, commonly shortened to **EV**.

For each possible prize, multiply the probability of receiving that prize by its value:

```text
Prize contribution = Probability of winning × Prize value
```

Add the contribution from every prize tier:

```text
Expected payout =
    (Probability of prize 1 × Prize 1)
  + (Probability of prize 2 × Prize 2)
  + (Probability of prize 3 × Prize 3)
  + ...
```

Then subtract the ticket cost:

```text
Net expected value = Expected payout - Ticket price
```

The decision can be simplified to:

```text
Net EV below $0  = Do not buy
Net EV above $0  = Buy
```

Most lottery drawings have a negative expected value. Players will occasionally win, but the average return is less than the money spent.

A rolldown changes the payout values without changing the ticket price. If enough jackpot money is moved into the lower prize tiers, the expected payout can rise above the cost of the ticket.

That is the vulnerability.

---

## Why Buying More Tickets Helps

A positive expected value does not guarantee that one ticket will win.

Buying only a few tickets leaves the result heavily dependent on luck. A player might receive no useful prizes even during a profitable rolldown.

Buying many tickets produces more opportunities for the simulated results to approach their mathematical average.

For example, consider a hypothetical profitable ticket with an expected return of $1.20:

```text
Cost per ticket:       $1.00
Expected return:       $1.20
Expected profit:       $0.20
```

Buying ten tickets would produce an expected profit of:

```text
10 × $0.20 = $2.00
```

Buying 100,000 tickets would produce an expected profit of:

```text
100,000 × $0.20 = $20,000
```

The actual result will vary, but larger purchases reduce the effect that a small number of unusually good or bad outcomes has on the overall result.

This is why the intended solution involves buying the maximum number of tickets during a correctly identified rolldown.

---

# Challenge Objective

The player begins with a limited balance and has fewer than 50 weeks before the lottery operators fix the flaw.

The objective is to:

1. Advance through the lottery weeks.
2. Monitor the current jackpot.
3. Identify when the jackpot will cross the $2 million rolldown threshold.
4. Purchase a large number of tickets for that drawing.
5. Reinvest the profits during later rolldowns.
6. Accumulate at least $1,000,000 before the vulnerability is fixed.
7. Retrieve the flag.

Buying tickets during normal weeks will gradually reduce the available balance. The challenge is therefore about **when** to invest, not simply buying tickets every week.

---

# Intended Solution

## Step 1: Open the Lottery

After starting the shared VM, open:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

The application displays information such as:

* Current week.
* Available balance.
* Current jackpot.
* Rolldown threshold.
* Number of tickets to purchase.
* Remaining time before the flaw is fixed.

The important value is the jackpot’s relationship to the **$2 million rolldown threshold**.

---

## Step 2: Observe the Jackpot

Do not immediately spend the starting balance.

Advance through the early weeks and monitor how the jackpot changes after each drawing.

A normal drawing should be skipped when the jackpot is far below the threshold. Tickets purchased during those weeks have a negative expected value and will usually reduce the bankroll.

The intended decision is:

```text
Jackpot far below $2 million  → Skip
Jackpot approaching $2 million → Prepare to buy
```

---

## Step 3: Estimate the Next Jackpot

Record the jackpot movement across several weeks.

A simple prediction can be made using the recent increase:

```text
Predicted jackpot =
    Current jackpot
  + Expected weekly increase
```

For example:

```text
Current jackpot:          $1,820,000
Expected increase:          $230,000
Predicted next jackpot:   $2,050,000
```

Because the predicted amount crosses $2 million, the next drawing is likely to trigger a rolldown if the jackpot is not won.

That is the drawing in which tickets become valuable.

The prediction does not need to be perfectly precise. The safest opportunity occurs when the current jackpot is already close to, but still below, $2 million.

---

## Step 4: Buy the Maximum Number of Tickets

Once a rolldown is expected:

1. Select the ticket purchase control.
2. Choose **Buy Maximum Tickets**.
3. Confirm the purchase.
4. Advance to the next drawing.

Buying the maximum number of tickets gives the simulation enough volume for the result to generally approach the positive expected return.

A correctly timed maximum purchase should increase the balance significantly.

Do not purchase the tickets after the rolldown has already occurred. The tickets must be purchased for the drawing that crosses the threshold.

---

## Step 5: Repeat the Process

After a successful rolldown:

1. Keep the resulting profit.
2. Resume skipping ordinary weeks.
3. Wait for the jackpot to approach $2 million again.
4. Buy the maximum number of tickets before the next rolldown.
5. Repeat until the balance reaches $1 million.

The growing balance allows increasingly large ticket purchases, producing larger profits from later rolldowns.

This creates a compounding cycle:

```text
Larger balance
    ↓
More tickets during a rolldown
    ↓
Larger expected profit
    ↓
Even larger balance
```

---

# Creator’s Tactic

The simplest and most reliable approach is to advance until the jackpot is **just below $2 million**.

Once it is close to the threshold:

1. Stop advancing.
2. Select **Buy Maximum Tickets**.
3. Play the next drawing.
4. Collect the rolldown return.
5. Repeat during later rolldowns.

In most runs, buying the maximum number of tickets when the jackpot is immediately below the threshold will produce enough profit to progress toward the objective.

The game includes simulated variance, so the result of one purchase may differ between runs. However, a maximum purchase during a correctly identified rolldown will generally be profitable.

The creator’s strategy can be summarised as:

```text
Far below $2 million     → Skip
Just below $2 million    → Buy maximum
Rolldown completed       → Keep profit and wait
```

---

# Enabling the Predicted Jackpot

Players who are uncertain about calculating the next jackpot can unlock the challenge hint.

The hint reveals a hidden URL that enables the game’s **predicted jackpot amount**:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/hint/4eecaa732a0adf67a9e14c6d334b5f0a4473aabb3db838fc0f927c434a63afcb
```

Open this URL in the same browser session used for the challenge.

After enabling it, return to the main lottery page:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

The interface will now automatically display an estimated jackpot for the next drawing.

The decision then becomes straightforward:

```text
Predicted amount below $2 million  → Skip
Predicted amount above $2 million  → Buy maximum
```

For an easy completion:

1. Enable the prediction.
2. Advance until the current jackpot is just below $2 million.
3. Confirm that the predicted amount crosses $2 million.
4. Buy the maximum number of tickets.
5. Repeat until the balance exceeds $1 million.

---

# Retrieving the Flag

Once the account balance reaches the required retirement target of **$1,000,000**, the application displays the completion flag.

Copy the displayed flag and submit it to the corresponding TryHackMe question.

The exact financial result may vary between runs because the game simulates lottery variance. If the balance does not reach the target after the first rolldown, continue waiting for and investing in later rolldowns.

---

# Troubleshooting

## The Lottery Page Does Not Load

The wrong challenge may have been activated on the shared VM.

Restart the VM, then make sure the first challenge URL opened is:

```text
http://MACHINE_IP/rooms/a312e8b7/lottery/
```

---

## The Balance Keeps Decreasing

Tickets are probably being purchased during normal weeks.

Skip drawings while the jackpot is far below $2 million. Only invest when the next drawing is expected to trigger a rolldown.

---

## The Jackpot Crossed $2 Million Without a Purchase

The opportunity was missed.

Continue advancing until the jackpot builds toward the threshold again, or restart the game if too many weeks have been used.

Tickets must be purchased **before** the drawing that triggers the rolldown.

---

## The Purchase Was Profitable but Too Small

Buying a small number of tickets leaves the result more exposed to variance and produces limited profit.

During a predicted rolldown, use:

```text
Buy Maximum Tickets
```

The challenge is designed around scaling the purchase during profitable weeks.

---

## The Rolldown Purchase Lost Money

The predicted drawing may have been incorrect, or the purchase may have been too small.

Use the hidden prediction URL and wait until:

```text
Current jackpot < $2 million
Predicted jackpot ≥ $2 million
```

Then buy the maximum number of tickets.

A small amount of simulated variance is still possible, but correctly timed large purchases are generally profitable.

---

## The Flaw Was Fixed Before Reaching $1 Million

Too many ordinary weeks may have been played, or money may have been spent during negative-value drawings.

Restart and use the more aggressive strategy:

1. Skip all ordinary weeks.
2. Enable the predicted jackpot.
3. Buy maximum tickets only before predicted rolldowns.
4. Reinvest during every later rolldown.

---

# Why This Is a Business-Logic Vulnerability

Nothing in the challenge requires:

* Predicting the winning numbers.
* Breaking the random-number generator.
* Modifying requests.
* Accessing another player’s account.
* Injecting code into the application.
* Bypassing authentication.

The lottery performs exactly as its rules specify.

The vulnerability exists because the interaction between several legitimate rules creates an unintended financial outcome:

```text
Jackpot cap
    +
Unclaimed jackpot
    +
Redistribution to lower prizes
    +
Unchanged ticket price
    =
Positive expected value
```

The individual components work correctly, but their combination allows informed players to extract predictable value from the system.

This is a common characteristic of business-logic vulnerabilities: the attacker does not break the software’s technical controls. They understand the system’s rules better than its designers anticipated.

---

# Conclusion

Calculated Luck demonstrates that secure randomness does not automatically create a secure system.

The winning numbers remain random throughout the challenge. What becomes predictable is the **value of participating**.

By monitoring the jackpot, estimating when the rolldown will occur, and purchasing enough tickets during the favourable drawing, the player can turn a game of chance into a positive-expected-value investment.

The intended solution is:

```text
Wait for the jackpot to approach $2 million
                    ↓
Predict whether the next drawing will cross the threshold
                    ↓
Buy the maximum number of tickets
                    ↓
Profit from the rolldown
                    ↓
Repeat until the balance reaches $1 million
                    ↓
Capture the flag
```

The weakness was never the random draw.

It was the rules surrounding it.
