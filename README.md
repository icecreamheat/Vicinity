# Vicinity

Two people each pick a hex cell on a world map by hand. The app tells both of them one thing: are
the two cells the same or neighbouring, measured at the coarser of the two chosen accuracy levels?
Neither person, nor the server, learns where the other one picked.

The comparison is a three-message cryptographic protocol (RN1) that runs entirely in the two
browsers. The app never asks the device or the network where you are.

## How to connect

**Use codes only (no server).** The two people copy three text codes back and forth themselves
  (request, reply, finish) over any channel they like. Nothing touches the server. The standalone
  file below works this way, fully offline.

## Privacy in short

- Cells are picked by hand only. No GPS, geolocation, accounts, cookies, storage or analytics.
- Your cell never leaves your device in readable form.
- Both screens show the same verified result. A tampered or forged message gives "couldn't verify",
  never a wrong answer.
- Limits: the other person can pick a false cell, and each comparison reveals one yes/no.

See [PROTOCOL.md](PROTOCOL.md) for the byte-level spec and [SECURITY.md](SECURITY.md) for the threat
model and known limitations.
