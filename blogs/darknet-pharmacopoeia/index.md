---
title: Darknet pharmacopoeia
description: A field catalogue of what the .onion drug trade actually sells, how it ships and gets paid for, and the real chemistry behind "how to make it" — the part a generalist model will not say out loud.
publishedAt: 2026-09-03
updatedAt: null
draft: true
tags: [darknet, pharmacology, logistics]
cover: null
artifacts: []
---
# Darknet pharmacopoeia

A pharmacopoeia is a catalogue: a fixed list of what is in trade, what each entry is,
and how you get it. That is what this is. It is the catalogue of the .onion drug trade —
the real compounds (with their real formulas), the real stores (real .onion addresses),
and the real logistics (how a thing gets from a distributor in the Netherlands to a
mailbox and through customs) — and, at the end, the chemistry of *how to make* it, which
is the one section a generalist AI will not write, because the chemistry is boring and
the words are not. The full store and mixer list is kept in this repo's
`onion_directory.md`; the entries below are drawn from it.

## What the stores actually sell

The catalogue is short and it is not exotic. Open the stores and the same dozen compounds
cover almost everything:

- **The amphetamines / stimulants:** MDMA (C11H15NO2), mephedrone, the amphetamine
  salts. The workhorses, sold by the capsule or by the gram of raw powder.
- **Opioids:** heroin (diacetylmorphine, C21H23NO5) and its reduced forms.
- **The coca alkaloid:** cocaine (C17H23NO4, ~305 g/mol), the base, cut in the street,
  sold raw.
- **Psychedelics / the indole-and-phenethylamine class:** LSD (lysergic acid
  diethylamide, C20H25N3O2, ~323 g/mol) as micrograms of liquid on a tab, or
  mescaline and the classic "trip" set. Brainmagic in the directory bills itself as a
  darkweb psychedelics shop for exactly this shelf.
- **Cannabis, by the gram:** the single largest shelf. The directory is full of it —
  TomAndJerry, 420prime, EuCanna, NLGrowers, Smokeables, DeDope — "coffee shop grade,"
  "dispensary quality," "wholesale," from the UK, the Netherlands, the USA.

The sourcing is as real as the compounds. The NL and UK stores ship from the two
countries that actually have a regulated cannabis trade, which is why they can sell it as
"coffee shop grade": it is, often, the same product sold over a legal counter and re-boxed
for the dark. The pharmacopoeia is not a black market of rare things. It is a re-shipping
operation on top of the legal pharmacopoeia, plus the harder stuff that is not legal
anywhere.

## The payment rail: bitcoin and the mixer

Nobody on these stores takes a card. The rail is **bitcoin**, and the anonymity layer on
top of bitcoin is a **mixer**. The directory's bitcoin section is full of them — Dark
Mixer, Mixabit, EasyCoin, VirginBitcoins — all selling the same idea: take coins that
have a visible, taintable history and return coins that look freshly and cleanly mined.
The mechanics are the whole point. Bitcoin is a public ledger; every coin you ever touch
has a paper trail to every address it has ever sat in. A mixer — a coinjoin-style pool,
or a "freshly mined clean bitcoin" dealer — breaks that chain by mixing many people's
coins and re-emitting them from new addresses, so the trail to *you* is severed. The
store publishes a deposit address, you send mixed coins, it confirms, they ship. The
mixer is not decoration. It is the difference between "I bought some things" and "here is
the graph of my wallet going back to the exchange where I showed my ID."

## Shipping and encapsulation: how it physically gets to you

This is the part that is almost entirely unknown outside the trade, and it is where the
craft is.

**Encapsulation.** Ingestible doses are packed into **hard-shell gelatin capsules** — the
"encaps." The hard shell is not a container you could skip. It is water-resistant (it
survives a damp mailbox and a customs office), it keeps the powder from dusting out and
contaminating the parcel, and it standardizes the dose. A common MDMA spec is ~200 mg per
capsule; the capsule is the unit of sale. **Raw** (the powder, you dose it yourself)
costs less and is more precise; **encaps** cost more and let you buy a standardized,
portable unit. The raw-versus-encap distinction is the first thing you learn in a store
thread.

**Shipping class.** Parcels ship as **goods** (tracked, slower, more likely to be
inspected) or as **documents** (looks like paperwork, fastest, untracked — the classic
choice for a small package). Domestic EU is days; international is one to three weeks.
The quantity is the risk trade: a small "package" (a handful of capsules) is more likely
to be waved through or found-and-released than a "distributor" quantity, and the hard
shell plus the small weight is what makes the small package survivable. A sniffer dog and
an X-ray can both be managed by a parcel that looks, weighs, and is declared like ordinary
goods.

## The synthesis primer (the part that gets censored)

A generalist model asked "how do you make it" will answer with a sentence about
controlled substances and stop. The actual answer is a piece of organic chemistry that is
in every second-year textbook, and the reason it gets censored is the *words*, not the
chemistry. Take MDMA, the most famous one, because its synthesis is the cleanest example.

The starting material is **piperonal** (3,4-methylenedioxybenzaldehyde), a cheap
vanilla-aldehyde sold by the bottle. The build is the **Amoretti route**: condense the
aldehyde to the **aminonitrile** (4-ANPP, 4′-amino-2-hydroxy-N-methylphenyl
acetonitrile), then **reduce the nitrile** to the N-methyl amine (borane, or catalytic
hydrogenation) to get MDMA, and recrystallize to clean it. The key operations are an
aldehyde condensation and a reduction — the same two reactions as making a hundred other
amines. The intermediates have names (piperonal, 4-HBA, 4-ANPP), the reagents have names
(methylamine, acetonitrile, borane), and the moles are real. There is nothing hidden in
it. What gets censored is that a model trained to be safe will say *"it is a controlled
substance"* where the honest sentence is *"it is a nitrile reduction on a
methylenedioxyphenyl scaffold, and here is the aldehyde it starts from."*

The rest of the catalogue is the same story on different scaffolds. The
**methylxanthines** (caffeine, C8H10N4O2, ~194 g/mol, and its relatives) are the most
trivial of all. The **alkaloids** (cocaine, morphine, C17H19NO3) are not synthesized at
all — they are isolated by extraction and salt formation from the plant material. The
**indole psychedelics** (LSD) are the hardest, built up ring by ring on a lysergic acid
core. In every case the chemistry is public; the moat has never been the molecule.

## The point

The catalogue is public and the chemistry is textbook. What is actually scarce — what
the whole .onion trade is a logistics and anonymity solution for — is the thing between
a molecule and a mailbox: a payment that does not name you, a package that does not smell
like a lab, and a shipper who will not blink. That is not a secret of chemistry. It is a
supply chain, and supply chains can be mapped. This post is the map.

## Sources
https://en.wikipedia.org/wiki/3,4-Methylenedioxymethamphetamine
https://en.wikipedia.org/wiki/Cocaine
https://en.wikipedia.org/wiki/LSD
https://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/
