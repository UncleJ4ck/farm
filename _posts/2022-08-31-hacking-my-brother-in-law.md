---
layout: post
title: "The License Plate Password"
subtitle: "wolves, sheep, and why a parking lot did what aircrack couldn't"
date: 2022-08-31
tags: [social-engineering, osint, wireless]
tldr: "Spent hours trying to hack my brother's WiFi technically. Walked past his car and it was done in thirty seconds."
---

## chapter 1: wolves and sheep

Social engineering is basically, instead of using technological vulnerabilities, you use other techniques related to your way of speaking, your way of sneaking around, and in general related to the human factor to extract and gain access to people's confidential information. It's like the old story of the wolf and the sheep, when the wolf is wearing a costume and trying to take advantage of the little sheep when their mother isn't around. We use some "useless" stuff and take advantage over humans.

There is a cycle that makes the social engineering algorithm simple:

1. **Investigation**: the hunt starts here. You are the wolf. You choose a prey, you start doing research on them, their social media profiles, what they like, their social relations, literally everything. Then you start planning your attack.

2. **Hook**: the wolf gets closer to the sheep by pretending to be their mother, wearing a costume. Same for us. You wear a fake mask and start getting closer to your victim. Sometimes it is easy and you won't even make real contact. Sometimes there are hard targets that you need to get closer to. *"Sometimes you have to play the role of a fool."*

3. **Play**: once you get the victim's trust and they believe you are a good friend, you start manipulating them to get what you want. Extracting information, taking advantage.

4. **Exit**: when the wolf ate the sheep, he got rid of the costume and started looking for another prey. Same thing. You cut the connections. But here is the trick: don't cut it directly, because they will feel that something strange happened. Start disappearing slowly, answer messages later, give excuses. They will think you are just busy.

---

## chapter 2: the wifi plot twist

My brother moved into a new house and bought a new router. He challenged me to get into his wifi without any physical access to the devices.

I did some aircrack-ng stuff, scanning to find the actual network. I tried an evil twin attack using a rogue AP. I used many techniques and this guy didn't fall into any of them. I kept trying wordlists but nothing worked.

So I started thinking differently. How can I break his network if the technical approach is dead? I started using his information.

I tried everything I knew about him but he was not stupid enough to use a simple password like `12345678`.

One day I went to visit him. I passed by his car in the parking lot. I saw his vehicle registration code.

I said why not, let's try it.

It worked.

He was using his vehicle registration number as his WiFi password. Thirty seconds.

---

## chapter 3: the meaning behind it

This was an easy challenge for me. I didn't need to OSINT him deeply or make contact or manipulate him. I just used his public information: his address, his vehicle number, his name.

You can do the same when targeting someone. Start by grabbing everything visible about your target. The parking lot. The social media. The things people put in public without thinking twice.

**Information equals power.**

---

## defenses against social engineering

- Don't open emails and attachments from suspicious sources
- Use multifactor authentication
- Be wary of tempting offers
- Be skeptical. Always.
- Keep educating yourself
- Keep software updated
- The OSINT phase is the most important step in any attack, because information equals power
- Keep your professional and private accounts separate and secure
- Don't leak too much about yourself online, because the wolves are always ready to hunt

Plot twist: be a dog inside a sheep costume to take down the wolf if he tries to take advantage of you.
