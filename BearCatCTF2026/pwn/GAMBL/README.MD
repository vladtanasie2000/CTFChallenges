# Desc:
Ian

Gambling is all the rage these days. You can bet on anything! Well, I haven't seen anybody betting on which digital piracy groups will release the next cracked software. So I made it myself! I'm calling it GAMBL, without the E because all new and cool tech startups can't comprehend spelling. Could you find out if there's an infinite money glitch or something? I mean, there isn't, but there's a flag for you if one exists.

# Executable descripion:
The executable is an gambeling simulator, in which the user has 20 days. The goal of the simulator is to acumulate at least 5000000 to open the flag.txt. The user has the following options
* gambeling into one of the 5 piracy groups
* investing into crypto

# Solution
Looking at the logic, we can see that bets only pay on 2,5,8,10 and 13th days. Looking at the gamble method we can see that it first reads the moneyBet 
```
printf("\nHow much would you like to bet?\n > ");
scanf("%f", &moneyBet);
````
then performs a couple of checks. The check we are interested is `if (moneyBet > money)` which as we can see prints a message.
However it doesn't reset the moneyBet variable and also doesn't reduce our money either, meaning that we can bet any amount we want without. 
And so, at the end of the day 2,5,8,10 and 13th days the moneyBet value is multiplied by 2 and added into our accounts even if we don't have enough money to cover the bet. 
Using this method, we can create a bet of 2000000000 on day 2, cash out and have enough money to get the flag
