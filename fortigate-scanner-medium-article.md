# Your FortiGate Passed the Audit. Could It Survive the Attack?

*Most firewall reviews check whether the config is tidy. Almost none check whether the box can actually withstand the techniques attackers use. So I built a scanner that does both — and open-sourced it.*

---

The breach almost never starts where the headlines say it does.

It doesn't start with a zero-day dropped by a nation-state. It starts with a firewall that's been running fine for three years. Nobody has logged into it since the last firmware push. The rules still work, traffic still flows, and buried somewhere in a multi-thousand-line configuration there's an admin interface answering on the WAN, a password policy that never expired, and external logging that quietly stopped after a reboot.

That firewall is doing its job. It's just not doing it *securely* — and there's a meaningful difference between the two.

I've spent the better part of two decades on the defensive side of security, the last several of them running information security for a power distribution utility — the kind of organization where the network isn't carrying email, it's carrying the systems that keep a city's lights on. Critical infrastructure. Regulated. The sort of place where "the firewall is probably fine" is not an acceptable risk posture.

So I stopped guessing and built a tool. This is the story of why, and what it actually does.

## The edge is the front line now

If you've watched threat intelligence over the last two years, you've seen the center of gravity shift. The compromises that matter most aren't coming through phishing-to-workstation chains anymore. They're coming through the **edge** — the internet-facing appliances that sit between your network and everything else.

The reasons are uncomfortable to say out loud:

- These devices are **always on and always exposed**. That's their entire purpose.
- Their firmware frequently **lags on patching**, because patching the firewall means a maintenance window nobody wants to own.
- They're usually **invisible to your EDR**. You can't put an agent on the appliance, so it's a blind spot by design.
- And a firewall can be **fully patched and still wide open**, purely because of how it's configured.

FortiGate is the world's most widely deployed network firewall, which makes it a standing target. The FortiOS SSL-VPN bugs of recent years — the out-of-bounds write in CVE-2024-21762, the long tail running back through CVE-2022-42475 and CVE-2022-40684 — weren't obscure. They were mass-exploited, at the edge, against organizations that in many cases didn't know which firmware train they were even on.

That last point is the one that kept me up at night. We've trained a generation of engineers to treat firewall security as a patching problem: close the CVE, close the ticket. But the configuration itself is an attack surface — and so is the gap between "this config looks clean" and "this device would actually stop an attacker."

## The two questions almost no audit asks

Here's the thing most firewall reviews quietly skip.

The first question — *is this config hygienic?* — is the one everyone asks. Is admin access restricted? Is MFA on? Is there an explicit deny at the bottom of the policy table? Important, and entirely answerable by reading the config.

The second question is the one that actually matters to an attacker: **if a real adversary ran their standard playbook against this box, how much of it would the firewall stop?** Does IPS coverage actually blunt exploitation attempts? Is deep SSL inspection on, or is encrypted C2 sailing straight through? Are DNS filtering and DLP positioned to catch exfiltration? Is east-west traffic inspected, or is lateral movement a free ride once someone's inside?

That second question maps almost perfectly onto the MITRE ATT&CK framework — and it's the one a tidy-config check will never answer. A firewall can pass every hygiene check and still be functionally blind to the techniques that show up in real intrusions.

I wanted a tool that answered both questions in one pass. So that's what I built.

## What I built

**The Fortinet FortiGate Security Scanner** is a Python-based posture assessment tool that evaluates a FortiGate against best practices, five compliance frameworks, MITRE ATT&CK techniques, and known FortiOS CVEs — and tells you not just what's wrong, but exactly how to fix it.

It runs in two modes that share the same **260+ checks across 18 check methods**:

- **Live mode** connects over the FortiOS REST API with a **read-only token**. Zero agent on the device, nothing installed on the target.
- **Offline mode** parses an exported `.conf` backup with **zero network access and zero third-party dependencies** — Python standard library only.

That second mode isn't a convenience feature. It's the reason the project exists in the shape it does, and I'll come back to it.

## The part I'm proudest of: resilience, not just hygiene

The headline capability is **MITRE ATT&CK resilience testing**. The scanner runs **31 ATT&CK techniques across 11 tactics** — reconnaissance, initial access, execution, persistence, defense evasion, credential access, discovery, lateral movement, command-and-control, exfiltration, and impact — and checks whether the FortiGate features that *should* mitigate each technique are actually configured to do so.

The output is a single **0–100% resilience score**. Not a vibe. A number you can put on a slide and watch move quarter over quarter.

This reframes the whole conversation. Instead of handing leadership "we have 14 medium-severity findings" — which means nothing to anyone who isn't a firewall engineer — you can say: *"Against the techniques real attackers use to reach exfiltration, this firewall is configured to stop 71% of them. Here are the three changes that get us to 90%."* That sentence travels. It survives contact with a board.

## Built for the places other tools can't reach

Now, that offline mode.

Most scanners assume they can reach the thing they're scanning. In enterprise IT, fair enough. In **OT, ICS, and air-gapped environments** — the world I actually live in — that assumption falls apart. The firewall protecting a process network is often somewhere a scanning host simply cannot route to, by deliberate design. And the operator workstation that *can* reach it usually has no internet, no `pip`, and a change-control process that treats installing a Python package as a federal case.

So the offline scanner runs on a config backup file, on the standard library alone. Copy two `.py` files to a locked-down operator workstation, point it at a `.conf` export, and you get the **same 18 check categories, the same 31 MITRE tests, the same 66 CVE checks, the same compliance mappings** — with nothing installed and nothing touching the network. The same machinery that would've needed a live connection now runs against a static file you can carry across an air gap.

For anyone defending critical infrastructure, that's the difference between a tool you can use and a tool you can only admire.

## Audit-grade by default

A finding without context is just anxiety, so the scanner is built to produce evidence, not noise.

Every finding is **mapped to compliance controls** across five frameworks — CIS FortiGate, PCI-DSS 4.0, NIST 800-53 Rev 5, SOC 2 Type II, and HIPAA. When the auditor asks how you *know* the firewall is hardened, you export a compliance CSV with per-framework control columns instead of saying "trust me, a smart person looked at it."

Every finding also ships with **remediation** — actual FortiOS CLI config blocks you can review and apply, so the output is a work order, not a worry list.

And because firmware is half the battle, the scanner carries **66 known FortiOS CVEs from 2019 to 2026**, sourced from FortiGuard PSIRT and matched against the device's firmware *train* — so it knows the difference between a 7.4 build that's exposed and one that's patched, rather than waving its hands at a version string.

Reports come out in six formats: colour-coded console, JSON, a dark-themed interactive HTML report with filtering and search, the compliance CSV, the remediation script, and the ATT&CK resilience score.

## A finding in the wild

To make it concrete, here's the shape of what the scanner surfaces — trivially easy to miss in a manual scroll, genuinely dangerous in production:

> **[CRITICAL] Administrative access exposed on WAN interface**
> The WAN interface permits HTTPS/SSH administrative access. Internet-reachable management planes are a primary target for credential attacks and management-plane exploitation.
> **Compliance:** CIS FortiGate · PCI-DSS 4.0 · NIST 800-53 AC-17
> **MITRE:** T1595 (Active Scanning), T1190 (Exploit Public-Facing Application)
> **Remediation:** Remove `https`/`ssh` from the WAN interface's `allowaccess`; restrict admin access to a dedicated management network and enforce trusted-host ACLs on all admin accounts.

One line in a config file. The difference between a firewall protecting you and a firewall advertising its own login page to the internet. *This* is work that should never have depended on someone having the patience to find it by eye.

## Drop it into the pipeline

Because the scanner returns **exit code 1 on any CRITICAL or HIGH finding**, it slots straight into CI/CD as a gate. Push a config change, the pipeline scans it, and a critical misconfiguration fails the build before it reaches a production firewall. Shift-left, for the one device almost nobody shift-lefts. There's a multi-device inventory mode too, so you can assess a whole fleet in one run and get a unified report instead of chasing firewalls one at a time.

## Why I open-sourced it

I could have kept this internal. It would have been a perfectly reasonable decision. I didn't, for two reasons.

The first is that **defense is a commons.** The actors hammering edge devices don't care whether the FortiGate belongs to a utility in India or a hospital in Germany. The misconfigurations are the same everywhere, and the people defending against them are almost always under-resourced and over-stretched. A tool that turns a two-hour expert review into a two-second automated one is exactly the kind of leverage the defensive community needs more of — and hoarding it helps no one but the attacker.

The second is that **a security tool you can't read is a security tool you can't trust.** I'd never run a closed-box scanner against my own infrastructure and take its verdicts on faith. It's a single, readable Python file under an MIT license. Every check is auditable. Disagree with how I've interpreted a control? You can see the logic, challenge it, and improve it. In security, that isn't a nice-to-have — it's the whole point.

## Try it, break it, make it better

If you run FortiGate firewalls — and odds are decent that you, or someone whose network you depend on, does — point this at a config and tell me what you find.

Export a backup from a non-production device, run the offline scanner, and read the resilience score. If it catches something you'd missed, that's a good afternoon. If it misses something it should have caught, open an issue — that's a better one, because it sharpens the tool for the next defender.

**The repo:** [github.com/Krishcalin/Fortinet-Network-Security](https://github.com/Krishcalin/Fortinet-Network-Security)

```bash
git clone https://github.com/Krishcalin/Fortinet-Network-Security.git
cd Fortinet-Network-Security
python fortinet_offline_scanner.py fw1.conf --html report.html
```

Stars help other defenders find it. Issues and pull requests make it better. And if you're building in this space too, I'd love to compare notes — the edge isn't getting any quieter.

The firewall is the front door. It's worth knowing whether yours is actually locked — *and* whether it would hold if someone leaned on it.

---

*Written by Krishnendu De — security engineer, two decades on the defensive side, currently leading information security for a critical-infrastructure utility. I write about practical defense, detection engineering, and the unglamorous work that actually keeps networks standing.*
