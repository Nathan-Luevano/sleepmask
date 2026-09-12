---
title: Practical propellants
description: KNO3/sugar, flash powder, and ammonium nitrate — the stoichiometry, the energetics math, and why "build a tiny characterized sample and never scale it" is the entire safety model.
publishedAt: 2026-09-03
updatedAt: null
draft: true
tags: [energetics, chemistry, safety]
cover: null
artifacts: []
---
# Practical propellants

Rocket candy — the propellant that powers most small hobby rockets — is about
**65% potassium nitrate and 35% sugar by mass.** That is the whole formulation. It
has a specific impulse in the low-twenties of seconds, it will not detonate on its
own, and it is made by stirring a molten sugar-and-nitrate solution until it sets.
The rest of this post is about why "just stir it" is the most dangerous three words
in the hobby, and what *done properly* actually means when the thing you are holding
is its own oxidizer.

## The safety model first

The malware half of this repo runs on *build it, test it, never deploy it.* The
propellant equivalent is identical, and it is the entire discipline: make a small,
characterized batch, measure how it behaves (burn rate, sensitivity, energy), and do
not scale it until you understand the scaling. A gram is a data point; a kilogram is
a commitment, and most accidents are people who went from "a little" to "a lot" in a
single step with no data in between. Everything below is about the chemistry that lets
you predict that step before it predicts you.

## A propellant is a combustion that carries its own air

Ordinary burning needs oxygen from somewhere — the tank, the air. A propellant (or an
explosive, broadly) is a mixture where the fuel and the oxidizer are already together,
so the reaction is self-contained. That self-contained-oxidizer property is the entire
trick: it is why a grain of it can burn in a vacuum, and it is why you can never treat
the two parts separately once they are mixed. Every composition below is just a
different answer to the same question: *what is the cheapest, densest, most stable pair
of fuel and oxidizer that gives me a useful flame?*

## Rocket candy: KNO3 + sucrose

The classic fuel is sucrose, C12H22O11. The oxidizer is potassium nitrate, KNO3. Work
the combustion. Sucrose wants to become CO2 and H2O:

    C12H22O11 + 12 O2  ->  12 CO2 + 11 H2O

It must import 24 oxygen atoms to do that. KNO3 is the oxygen bank, but it also has to
account for what happens to the K and the N once they give up the O. Balance the whole
thing:

    C12H22O11 + 9.6 KNO3  ->  12 CO2 + 11 H2O + 4.8 K2O + 4.8 N2

Nine-point-six moles of KNO3 per mole of sucrose. In mass terms that is 9.6 × 101.1 g
of nitrate to 342.3 g of sugar, i.e. about **74% nitrate / 26% sugar at stoichiometry**.
The famous 65:35 mix is therefore *not* stoichiometric — it is deliberately
**fuel-rich.** Running fuel-rich (extra carbon) buys castability (a more fluid melt)
and nudges specific impulse up a little, at the cost of a sootier, less complete burn.
That is the actual trade, and it is why you will see 65:35, 66:34, and 68:32 all
floating around: they are all "a bit fuel-rich, tuned by whoever mixed it."

The energy bookkeeping: sucrose's heat of combustion is roughly 16.5 MJ per kilogram
of *sugar*, and the nitrate's job is to supply the oxygen that lets the sugar release
it. A 35%-sugar mixture therefore releases on the order of **5–6 MJ per kilogram of
propellant** — a few times the energy density of a hydrocarbon fuel, enough to push a
small rocket. It is also, though, *small*: rocket candy's vacuum specific impulse sits
in the **low-twenties of seconds**, where a good liquid bipropellant is over 400. You
are not building a spacecraft. You are building a thing that comes apart beautifully.

The operational fact that matters: KNO3/sucrose **deflagrates.** It burns fast — much
faster than smokeless powder — but it propagates as a deflagration (a pressure wave
below the speed of sound in the products), not a detonation. Loose, it burns off
rather than bangs. It only becomes a detonation if you confine it, compress it, and
usually give it a booster. *"It can't detonate, it's just rocket fuel"* is the sentence
that has opened a lot of funerals; the correct sentence is *"it won't on its own, under
these conditions, and I have a number for that."*

## Flash powder: put a metal in

Flash powder is the same oxidizer-plus-fuel idea, but the fuel is a metal — aluminum or
magnesium — instead of a carbon compound. The metal is the point: aluminum's combustion
enthalpy is enormous (Al2O3 is one of the most stable oxides there is), so an Al/KNO3
or Al/KClO3 mix throws a blinding white ~3000 K flash. That is why it is the "camera
flash" and the "signal" material.

The oxidizer choice is where the danger lives. KNO3 is a *gentle* oxidizer — its oxygen
is bound in a stable nitrate. KClO3, potassium chlorate, is a much more reactive one:
chlorine is in the +5 state and really wants to come down, so it gives up oxygen readily
and violently. KClO3/Al mixes are the ones that go from "a powder" to "a detonation" on
a drop of the wrong contaminant, and they are the ones where
**deflagration-to-detonation transition (DDT)** is a real design parameter, not a
footnote. The rule that keeps people alive is that you do not grind an oxidizer with a
fuel or a metal by hand once the quantity is nontrivial, because the grinding *is* the
impact and the friction and the energy input, all at once.

## Black powder: the 75:10:15 that started all of it

Black powder predates everything here, and the ratios are the most famous in the field:
**75% potassium nitrate, 10% charcoal, 15% sulfur** by mass. The sulfur and the
charcoal are not decoration. Sulfur lowers the ignition temperature and flash point of
the mixture, makes it easier to light, and improves moisture resistance. Charcoal is the
actual fuel (the nitrate is the oxidizer, as before). Black powder is a *low-order*
explosive/propellant: it deflagrates at a few hundred meters per second, it leaves a
lot of smoke (the "black" in the name is the soot), and it is the propellant behind
nearly every firearm and artillery piece until the mid-1800s. Its energy density is
only about 3 MJ/kg — lower than rocket candy — because charcoal is a lousy fuel
compared to pure carbon or a sugar.

## Ammonium nitrate and ANFO: the fertilizer that runs the mines

The workhorse of the commercial explosives industry is not a nitrate salt at all — it
is **ammonium nitrate, NH4NO3**, the agricultural fertilizer on a truck. AN decomposes
explosively when shocked or heated, but it is *insensitive* in the way that matters
operationally: a truckload of it will not go off from a spark, a small impact, or even
a stray bullet in most cases. You have to give it a real initiation — a detonator,
usually through a booster charge.

That insensitivity is a feature, not a bug: it is what lets you store and haul it. The
standard mix is **ANFO — about 94% ammonium nitrate and 6% diesel fuel oil** — where the
diesel is the fuel and the AN the oxidizer; the same oxidizer-plus-fuel trick again.
ANFO's detonation energy is on the order of **1.0–1.4 MJ/kg**; it is the cheapest way
to move a lot of rock per dollar, which is why mining runs on it. The failure mode of
AN is the one that makes it scary in headlines: under sustained heating (a big fire), a
large quantity *can* transition to a detonation on its own — exactly the mechanism
behind the big fertilizer-plant incidents.

## The energetics math, actually done

Three numbers matter, and you should be able to produce all three from a composition:

- **Energy density** (MJ/kg): how much energy per kilogram the reaction releases. Sets
  the total work available. Rocket candy ~5–6, ANFO ~1.0–1.4, black powder ~3.
- **Specific impulse, Isp** (seconds): thrust per unit weight-flow of propellant,
  `Isp = F / (mdot * g0)`. It is the "fuel efficiency" of a rocket — how long each
  kilogram of propellant buys you of thrust. Rocket candy's low-twenties Isp is the
  reason hobby rockets are cheap and loud and short-lived.
- **Oxygen balance (OB)**: for the fuel, how much O2 (from the oxidizer) is left over or
  short. Zero OB is the fully oxidized, maximum-energy point. Rocket candy's 65:35 is
  deliberately *fuel-rich* (negative OB), trading a little energy for castability and a
  slightly higher Isp.

The worked example is the rocket-candy equation above: **9.6 mol KNO3 per mol sucrose is
the zero-oxygen-balance point** (every O in the nitrate ends up in the products, nothing
left over), and every practical mix is a deliberate, documented offset from that point.

| composition | energy density | Isp | sensitivity | what it does |
|---|---|---|---|---|
| KNO3/sucrose 65:35 | ~5–6 MJ/kg | low-20s s | low (deflagration) | solid rocket propellant |
| Al/KClO3 flash | high (metal-driven) | n/a | high (DDT risk) | flash / signal |
| black powder 75:10:15 | ~3 MJ/kg | n/a | moderate (deflagration) | gunpowder / propulsion |
| ANFO 94:6 | ~1.0–1.4 MJ/kg | n/a | low (needs booster) | bulk mining explosive |

## Why "done properly" is the whole thing

Sensitivity (impact, friction, electrostatic), confinement, and the need for a boost to
get from deflagration to detonation are not trivia; they are the difference between
"it burned as predicted" and "it did not." Every one of these compositions has a number
that says what it will and will not do, and the people who work with them at scale keep
that number on a sheet. The hobbyist's mistake is skipping the sheet. The rest of the
discipline — the one the malware half of this repo practices in miniature — is the same:
characterize the small sample, publish the numbers, and do not scale past the data.

## Sources
https://en.wikipedia.org/wiki/Rocket_candy
https://en.wikipedia.org/wiki/Ammonium_nitrate
https://en.wikipedia.org/wiki/Flash_powder
https://en.wikipedia.org/wiki/Black_powder
https://en.wikipedia.org/wiki/Specific_impulse
