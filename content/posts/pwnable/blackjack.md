---
title: "pwnable blackjack"
date: 2023-07-10T12:13:32+05:30
description: "Wonder if something like this happens in a real casino?"
tags: [pwnable, math, scanf]
---

## Source

The source provided in the game can be found here: [Link](https://cboard.cprogramming.com/c-programming/114023-simple-blackjack-program.html)

## Analysis

I noticed the main gameplay block was quite interesting in the way it handled the users bet:

```c
if(p<=21) //If player total is less than 21, ask to hit or stay
{         
    printf("\n\nWould You Like to Hit or Stay?");
    
    scanf("%c", &choice3);
    //...


    if((choice3=='H') || (choice3=='h')) // If Hit, continues
    { 
        //...
        if(dealer_total==21) //Is dealer total is 21, loss
        {
            printf("\nDealer Has the Better Hand. You Lose.\n");
            loss = loss+1;
            cash = cash - bet; // [1]
            printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
            dealer_total=0;
            askover();
        } 
        //...
    }
    if((choice3=='S') || (choice3=='s')) // If Stay, does not continue
    {
        printf("\nYou Have Chosen to Stay at %d. Wise Decision!\n", player_total);
        stay();
    }
}

void stay() {
    //...
      if(player_total<dealer_total) //If player's total is less than dealer's total, loss
      {
         printf("\nDealer Has the Better Hand. You Lose.\n");
         loss = loss+1;
         cash = cash - bet; // [2]
         printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
         dealer_total=0;
         askover();
      }
    //...
}
```

At both `[1]` and `[2]`, the math done looks a little fishy as our input isn't sanitized to remove any negative values if we lose. Looking at the bet function, we can see the unsanitized values passed can be passed into the `scanf()` call:

```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```

The only check here is that we enter a number, but if we do an some incorrect math; hence, we can put in a negative number to get a positive number.

## Win

```txt
Cash: $900
-------
|S    |
|  Q  |
|    S|
-------

Your Total is 10

The Dealer Has a Total of 7

Enter Bet: $-100000000000000000
\

Would You Like to Hit or Stay?
Please Enter H to Hit or S to Stay.
S

Please Enter H to Hit or S to Stay.

You Have Chosen to Stay at 10. Wise Decision!

The Dealer Has a Total of 16
The Dealer Has a Total of 25
Dealer Has the Better Hand. You Lose.

You have 2 Wins and 3 Losses. Awesome!

...

YaY_I_AM_A_MILLIONARE_LOL
```

We can see here that by intentionally losing after betting a huge negative value, we end with a very large positive number as `X - (-Y) == X + Y` causing the flag to print.
