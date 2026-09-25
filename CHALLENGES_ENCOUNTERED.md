# VALENS.AI — The Challenges We Ran Into

> **Project**: VALENS.AI — Security Operations. Deception. Intelligence  
> **Team**: Harkirat Singh, Shaikh Arman  
> **What this document is**: A simple, honest, and non-technical look at the real hurdles we hit while building this project and how we solved them.

---

## The Real Story: 3 Big Hurdles We Faced

Building a cybersecurity project during a high-speed hackathon sounds great on paper, but things get tricky the moment you start building for the real world. 

Here are the three biggest challenges we tackled, explained in simple, everyday language:

---

### Challenge 1: The Judge’s Challenge — Building an AI Security Chatbot on the Spot

* **What happened**:  
  During our initial demo and mentoring discussion, one of the hackathon judges gave us a direct challenge:  
  > *"This dashboard has great data, but what if the person using it isn't a hardcore cyber expert? Can they just talk to it in plain English or Hindi to find out what's going on?"*

* **Why it was hard**:  
  Building an AI chatbot from scratch under tight hackathon time is already stressful. But in cybersecurity, chatbots love to "hallucinate" (make up fake facts). If someone types random keys on the keyboard (like `asdfghjkl` or `kjbfekdeve`), typical AI bots will get confused and pretend an imaginary hacker is attacking. We needed an assistant that speaks like a smart human, understands cybersecurity context, and doesn't get tricked by random garbage text.

* **How we solved it**:  
  * We connected Google’s Gemini AI directly to the live memory of our decoy traps.
  * We built a simple "noise filter" so if someone mashes their keyboard or asks something nonsensical, the bot doesn't make up a wild cyber story—it politely asks them to clarify, just like ChatGPT would.
  * We trained it to respond naturally in both **English and Hindi / Hinglish**, so anyone on the team can ask: *"System ka status kaisa hai?"* or *"Explain this attack in simple words"*, and get clear, instant guidance.

---

### Challenge 2: The Geo & IP Tracking Myth 

* **The common misconception**:  
  In movies, when a hacker attacks, the screen shows a blinking red dot zooming straight into the hacker’s living room window. **In real life, that is physically impossible.** An IP address does not point to a person’s house; it points to their Internet Service Provider (ISP) gateway or cell tower miles away. 

* **Why it was a challenge**:  
  We did not want to show fake, made-up pinpoint locations on our map just to look cool for a demo. We wanted our threat intelligence to be 100% honest and practically useful. 

* **How we solved it**:  
  * Instead of pretending we know the exact street address, our map draws a realistic **20 kilometer circle** around the Internet Service Provider's hub. This tells the defender the truth: *"The attacker is routed through this specific ISP in this city/region."*
  * For cases where the attacker visits our fake web portal, we added a clever "Honey-Lure", a deceptive prompt asking for browser location permission (disguised as an internal login verification). Only if the attacker grants it do we obtain accurate GPS coordinates. Otherwise, we stick to the honest 20 km ISP estimate.

---

### Challenge 3: Fixing the Security Leak Safely via GitHub Pull Requests

* **The dilemma**:  
  Once our decoys caught a hacker trying to exploit a security hole (like injecting malicious database commands or stealing credentials), we wanted the system to help fix that bug in the code.  
  
  The obvious idea was: *"Why not let the AI automatically rewrite the code on our servers?"*  
  **The answer is: That is extremely dangerous!** You should NEVER give an AI robot full permission to directly overwrite your company's live production code. If the AI hallucinates, misinterprets something, or makes a typo, it could accidentally crash your entire website or delete critical databases.

* **How we solved it (The Smart GitHub PR Idea)**:  
  * Instead of letting the AI touch live code, we had Gemini write the fix as a clean suggestion such as a security patch that blocks SQL injection.

  * Then, our system automatically packages that fix into a **1-Click GitHub Pull Request (PR)**.

  * A real human developer gets notified, opens GitHub, reviews the suggested fix, and decides: **"Does this make sense and solve the leak?"** 

  * If it looks good, the developer clicks **"Merge"**, and the code is safely updated.  
  
  This gives organizations the best of both worlds: **the speed of AI to write the patch, with a real human staying in complete control.**

---

## In Short

| Challenge | What Was Hard | How We Solved It (In Plain English) |
| :--- | :--- | :--- |
| **1. The Judge's Chatbot** | Making an AI assistant on short notice that speaks English/Hindi without making up fake security alarms. | Hooked up Gemini with live decoy context and added a smart filter to ignore keyboard mashing. |
| **2. Geolocation Reality** | You cannot legally or technically track an IP down to a person's house. | Showed an honest 12km ISP routing circle on the map instead of pretending to have fake movie GPS. |
| **3. Safe Code Fixing** | Letting AI directly change production code could break the entire system. | Built a 1-click GitHub Pull Request so AI proposes the fix, but a human developer approves it. |
