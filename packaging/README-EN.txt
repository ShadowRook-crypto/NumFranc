NumFranc (NFR) — user guide (English)
=====================================
(The full guide, in French, is LISEZMOI.txt. White paper in English: WHITEPAPER.pdf.)

1. INSTALL AND START
   Download the installer for your system from the releases page
   (https://github.com/ShadowRook-crypto/NumFranc/releases/latest), then open your "Downloads" folder:
   - Mac:     double-click NumFranc-macos.dmg, drag NumFranc onto Applications, open it from Launchpad.
              The very first time, macOS shows "Not Opened" (independent project, no Apple developer account).
              Click "Done", then System Settings > Privacy & Security, at the very bottom:
              "Open Anyway" (Mac password), then "Open". Only once.
              (macOS 14 and older: right-click NumFranc > Open > Open is enough.)
   - Windows: double-click NumFranc-windows-installation.exe, then "Next". If Windows shows "Windows protected
              your PC": More info > Run anyway. NumFranc is then in the Start menu.
   - Linux:   double-click NumFranc-linux-amd64.deb (or -arm64.deb), then "Install"
              (or: sudo apt install ./NumFranc-linux-amd64.deb). NumFranc is in the applications menu.
   On first launch NumFranc adds itself to the applications menu and enables nfr: payment links.
   Without the installer (this folder, NumFranc.zip): Mac "Lancer NumFranc.command" (the first time macOS blocks it: System Settings >
   Privacy & Security > "Open Anyway"; macOS 14 and older: right-click > Open), Windows "Lancer NumFranc.bat", Linux ./lancer-numfranc.sh in a terminal.

2. FIRST LAUNCH
   You choose TWO different secrets: the OPENING PASSWORD (12+ characters, asked at every start: see balance,
   mine, receive) and the SPENDING CODE (16+ characters, asked at every payment: it protects the secret key).
   The wallet is encrypted twice (AES-256-GCM then XChaCha20-Poly1305) with Argon2id-derived keys.
   Then the RECOVERY CODE is shown in 3 PIECES: copy each onto a different paper, kept in a different place.
   Any 2 pieces recover everything (even if you forget your passwords); one piece alone is useless.
   Never photograph them, never send them, never paste them into any chat.
   Mining starts by itself on half of your cores (4 MiB of memory per core, Argon2d). It heats the computer:
   uncheck "Mine with this computer" or lower the number of cores to slow it down.

3. JOINING THE NETWORK
   Nothing to set up. NumFranc finds other computers by itself (local network, then the world directory) and asks
   your router to open port 6910 (UPnP, NAT-PMP, PCP) so that others can connect to you too. The status is shown
   on the home screen and in Settings > Connection, with the reason and what to do if it fails (UPnP turned off
   on the router, Internet address shared by your provider, ...). NumFranc works even without the open port:
   it connects to others. To add a node by hand: put its address in noeuds.txt (e.g. mynode.example:6910).

4. THE WINDOW
   Essentials: Home (balance, mining, network, earnings chart), Send, Receive (address, fingerprint, QR code),
   History (CSV export), Contacts, Settings; under "More...": Security (recovery code, password change)
   and Explanations. EXPERT MODE (Settings) adds Explorer, Issuance, Advanced and Network.
   Each address has a 4-word fingerprint + a colour (e.g. "jasmin gorille horloge jonque - red"):
   check it with the other person (by phone, for instance) before saving their address.
   A payment link nfr:... opens NumFranc on "Send", already filled in. Nothing is sent without your spending code.
   Languages (v1.1.1): French, English, Spanish, German, Italian, Portuguese - Settings > Language. The system language is
   used on first launch when supported. Translations are machine-made: corrections are welcome.
   If your router cannot open the port by itself, Settings > Connection shows a step-by-step guide (works with any router).

5. GOOD TO KNOW
   - A mining reward becomes spendable after 100 blocks; a payment is safe after 6 blocks.
   - Data folders: Mac ~/Library/Application Support/NumFranc, Linux ~/.numfranc, Windows %APPDATA%\NumFranc
     (uninstalling never touches them).
   - Check a downloaded installer: python3 sha3sum.py --fichier SHA3SUMS.txt FILE-NAME (tool included in NumFranc.zip).
     SHA3SUMS.txt is signed (SHA3SUMS.txt.sig, SLH-DSA) with the public key in cle-publique.txt.
   - No real money is involved: no NFR is for sale and no value is promised.

NumFranc has no connection with FrancNum. Software provided without warranty (MIT licence).
