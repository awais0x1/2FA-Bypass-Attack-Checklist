####  Multi-Factor Authentication MFA Bypass (2fa)


## Common 2FA bypasses to test on every website

### Session cookie reuse / porting
**Steps to Test:**
1. Enable 2FA, complete login and 2FA on Device A.  
2. Export authenticated session cookies from Device A.  
3. Import those cookies into Device B and attempt to access the account.

**Impact:**
- Full account access without re-doing 2FA if session cookies are valid/portable.  
- Enables takeover via stolen cookies (XSS, compromised device).

---

### Password reset / email-login flow bypass
**Steps to Test:**
1. Trigger password reset or "login link" for a test account.  
2. Follow the email link and complete the reset flow.  
3. Verify whether the session after reset skips the 2FA challenge.

**Impact:**
- Password reset / login-link flows may grant access without 2FA → account takeover.  
- Attackers with email access can bypass second factor.

---

### OAuth / Social login bypass
**Steps to Test:**
1. Sign in via third-party OAuth (Google, Apple, Facebook) using an account tied to the same email.  
2. Observe whether the target site logs you in without prompting site-enforced 2FA.

**Impact:**
- OAuth login can bypass site-enforced 2FA → attacker with control of the third-party account can access the victim’s account.

---

### OTP brute-force due to missing/weak rate-limiting
**Steps to Test:**
1. Intercept OTP verification and automate submissions across the full OTP space (e.g., 0000–9999).  
2. Observe whether attempts are limited/blocked or a valid code can be discovered.

**Impact:**
- Automated brute-force yields account takeover when no proper rate-limiting/lockout is enforced.

---

### Backup-code weaknesses (replay/accept arbitrary codes)
**Steps to Test:**
1. Issue backup codes, then attempt login using "use backup code" option.  
2. Submit random or previously-used codes and observe acceptance behavior.

**Impact:**
- If backup codes are not validated or are reusable/predictable, attackers can bypass 2FA.

---

### Race conditions in 2FA setup/change flows
**Steps to Test:**
1. Open two concurrent sessions and initiate 2FA enrollment/change in both.  
2. Race the two requests (replace payloads, replay) and see if secret/backup codes can be replaced without current OTP.

**Impact:**
- Race conditions let an attacker replace or disable 2FA without knowing the victim's OTP → account takeover.

---

### Previously-issued sessions remain valid after enabling/disabling 2FA
**Steps to Test:**
1. Sign in on Device A and Device B.  
2. Enable or disable 2FA from Device A.  
3. Check whether Device B remains logged in and can access protected pages.

**Impact:**
- Existing sessions bypass newly enabled 2FA or remain active after disable → persistent unauthorized access.

---

### Rate-limit / IP-based protections bypass via HTTP headers
**Steps to Test:**
1. Trigger 2FA/OTP attempts until rate-limiting occurs.  
2. Retry while changing headers like `X-Forwarded-For` / `X-Real-IP` to see if limits are evaded.

**Impact:**
- Attackers can brute-force OTPs by spoofing client-controllable headers if server trusts them.

---

---

####  Multi-Factor Authentication MFA Bypass (2fa)

### 2FA bypass by sending blank code
**Steps to Test:**
1. Enable 2FA on a test account.
2. Log out and start a new login to trigger the OTP prompt.
3. Intercept the OTP POST request with a proxy (e.g., Burp).
4. Blank or remove the code parameter in the intercepted request and forward it.
5. Verify whether the login completes.

**Impact:**
- Complete bypass of 2FA → account takeover.
- Attackers able to manipulate requests (MITM/proxy) can authenticate without OTP.


### 2FA bypass → impersonation via "Trust this device" + email change
**Steps to Test:**
1. Create an account with your attacker email and complete OTP verification; select **"Trust this device for 1 month"**.  
2. Go to account settings and change the account email to the victim's email.  
3. Verify the session remains trusted; log out and log back in using the victim email — observe no OTP prompt.  
4. (To persist) Change email back to attacker, re-verify and trust the device, then change to victim again; repeat and confirm access stays without OTP.  
5. From the victim POV, attempt to register with their email and observe the "email already used" behavior.

**Impact:**
- Impersonation / account takeover without valid 2FA.  
- Persistent bypass by cycling emails and re-trusting device.  
- Victim unable to register (denial of account ownership) and potential long-term unauthorized access.  
- High severity (full account compromise, privacy & trust issues).

### Previously created sessions remain valid after MFA activation
**Steps to Test:**
1. Sign in to the same account on two devices (A and B).  
2. On device A, enable/complete MFA enrollment via account security settings.  
3. On device B, reload or navigate the account — do not re-authenticate.  
4. Check whether device B remains logged in and can access protected pages without completing MFA.

**Impact:**
- Existing sessions bypass newly enabled MFA → attacker retains access.
- Enables persistent account takeover if an attacker already has a session token.
- Reduces effectiveness of MFA as a mitigation after compromise.

### Enable 2FA without verifying the email
**Steps to Test:**
1. Register an account using the victim's email (do not complete email verification).  
2. If allowed, log in to the new account without verifying the email.  
3. Go to account security and add/enable 2FA for the account.  
4. Confirm 2FA is active (generate backup codes or complete OTP enrollment) while the email remains unverified.  
5. From the victim POV, attempt to register with their email or reset password and observe inability to access due to 2FA.

**Impact:**
- Attacker can claim an email, enable 2FA, and block the legitimate owner from registering or accessing the account.  
- Victim may be unable to recover account (password reset ineffective without 2FA).  
- Account ownership confusion and potential long-term takeover.

### Account takeover via 2FA linking by supplying another user's ID (/api/2fa/verify)
**Steps to Test:**
1. Register **User A** and skip/enroll no 2FA; record User A's account ID.  
2. Register **User B** and initiate 2FA enrollment for User B.  
3. In the 2FA enrollment request, replace User B's ID with User A's ID (submit the request for User A).  
4. Call `/api/2fa/verify` (or the platform's 2FA verify endpoint) with a valid OTP for the current flow and the User A ID.  
5. Confirm User A now has 2FA enabled/linked to the attacker's flow and that the attacker can authenticate as User A (or the original owner faces login issues).

**Impact:**
- Full account takeover of User A without their interaction.  
- Severe — attacker only needs a known/discoverable account ID to enable/verify 2FA on someone else's account.  
- IDs exposed via user directories or enumeration make the issue easily exploitable.

### Two-factor authentication enforcement bypass 
**Steps to Test:**
1. Log in as an administrator and create a new group (e.g., **Enforcement**).  
2. Add a new user to that group (e.g., username: `Bypass`).  
3. In admin settings → Security → 2FA Enforcement, enforce 2FA for the **Enforcement** group and save.  
4. Log out, then log in as the `Bypass` user — notice the message requiring 2FA setup.  
5. In another session, log in again as `Bypass` and replace the `oc_sessionPassphrase` token with the token from the first session.  
6. Confirm that the user bypasses 2FA enforcement and gains access.

**Impact:**
- Complete bypass of enforced 2FA policy for restricted groups.  
- Allows unverified or unprotected logins even when enforcement is enabled.  
- High severity — administrative policy enforcement broken → increased risk of unauthorized access and privilege misuse.

### Changing 2FA secret key and backup codes without knowing the 2FA OTP
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Capture or craft the API request used to update/rotate 2FA credentials (e.g., the GraphQL `UpdateTwoFactorAuthenticationCredentials` or equivalent endpoint).  
3. Replace the payload fields with a new `totp_secret`, new `backup_codes`, and valid current password but **do not** provide the victim's current OTP (or provide OTP from an attacker-controlled authenticator).  
4. Send/replay the request and observe whether the server accepts the change.  
5. Log out and attempt login using the new OTP to confirm the secret/backup codes were replaced.

**Impact:**
- Attacker can replace victim's 2FA secret and backup codes → account takeover.  
- Victim's previous OTPs/backup codes are invalidated, locking out the legitimate user.  
- High severity: complete compromise of second-factor protection.

### 2FA bypass via brute-force on SMS endpoint
**Steps to Test:**
1. Log in to the app (or emulator) with a test account that uses SMS verification for profile changes.  
2. Initiate a profile action that triggers an SMS verification code (e.g., edit profile → Save).  
3. Capture required request headers (e.g., session header like `x-mts-ssid`) from an app request via a proxy.  
4. Send repeated verification requests to the profile verification endpoint with sequential 4-digit codes (1000–9999) until a `204`/success response is returned.  
5. Observe whether there is no rate-limiting, no code expiration after failed attempts, and whether a correct code can be discovered by brute force.

**Impact:**
- Complete bypass of SMS-based verification → account takeover (change email/phone, lock out owner).  
- Severe: lack of rate-limiting and no expiration allows automated brute-forcing of 4-digit codes.


### Misconfiguration in Two-Factor Authentication
**Steps to Test:**
1. Enable Two-Factor Authentication (2FA) using Google Authenticator on your Shopify admin account.  
2. Go to **Settings → Account → Login Services** and enable **Google Apps** for login.  
3. Logout and then try to log in using the **Sign in with Google** option:  
   `https://shop-1.myshopify.com/admin/auth/login?google_apps=1`  
4. Observe that no 2FA prompt appears — you are logged in directly to the admin panel.  
5. Check **Account Settings** again — the 2FA option is now missing, and it cannot be re-enabled.  
6. Attempt a normal login (email + password) — 2FA is still not required.  

**Impact:**
- 2FA can be silently disabled via “Sign in with Google.”  
- No notification or alert when 2FA is turned off.  
- Complete bypass of 2FA → attacker with credentials can acces


### Signup with any email and enable 2FA without verifying email
**Steps to Test:**
1. Register a new account using a victim's email (do not complete email verification).  
2. Log in to the account if allowed without verifying the email.  
3. Go to Two-Factor Authentication settings and enable 2FA.  
4. Confirm 2FA is active (generate backup codes or confirm OTP enrollment).  
5. From the victim's POV, try to register or reset password with their email and observe inability to access due to 2FA.

**Impact:**
- Attacker can claim someone else's email and enable 2FA, preventing the legitimate owner from registering.  
- Victim may be unable to regain access even after password reset because 2FA blocks lo

### Sign in with Apple Works on Existing Accounts — Bypasses 2FA
**Steps to Test:**
1. Create an Apple ID using the same email as an existing Cloudflare account.  
2. Go to Cloudflare login and choose **Sign in with Apple**.  
3. Authenticate via Apple ID login flow.  
4. Observe that you are logged into the Cloudflare account without being prompted for 2FA.  

**Impact:**
- Allows attackers to bypass Cloudflare 2FA protection.  
- Leads to full account compromise if attacker controls or registers an Apple ID with the same email.  
- Breaks the security assumption that 2FA is enforced on all login methods.

### 2FA bypass via leaked/ported session cookies
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Log out and log back in; complete the 2FA challenge.  
3. Export the authenticated session cookies (use a cookie editor or browser devtools).  
4. Paste/import those cookies into a different browser/profile.  
5. Access the site and verify whether the account is usable without re-doing the 2FA challenge.

**Impact:**
- Session cookie theft allows full account access without the second factor.  
- Attackers who can steal or copy cookies (XSS, compromised device, sh

### Reset 2FA completes without user confirmation → account takeover
**Steps to Test:**
1. Enable 2FA on a test account and sign out.  
2. Sign in and at the TOTP prompt choose **Reset two-factor authentication** (confirm the reset).  
3. Do NOT interact with any email notifications or verification links sent.  
4. Wait the platform's reset period (e.g., ~24 hours).  
5. Attempt to sign in again and confirm you can access the account without providing the original 2FA.

**Impact:**
- Attacker can remove 2FA protection without the account owner's confirmation.  
- Enables account takeover and denial of recovery for the legitimate user.  
- High severity: breaks the purpose of MFA and recovery workflows.

### Bypassing password authentication for 2FA-enabled users via OTP/session swap
**Steps to Test:**
1. Create two accounts (Attacker and Victim), enable 2FA on both.  
2. As Attacker, start login (enter Attacker's credentials) and reach the OTP prompt.  
3. Intercept the OTP submission request (proxy).  
4. Add/replace the `login` (or username) parameter with Victim's username and replace the OTP with a valid OTP from Victim's authenticator.  
5. Forward the modified request and verify you are logged in as Victim.

**Impact:**
- Sign-in as another user without knowing their password → full account takeover.  
- Undermines authentication by validating OTP against a different account than the password.  
- High severity: allows attacker with access to a victim OTP (or who can guess/obtain it) to impersonate users.

### Improper Authentication — reusable/long-lived 2FA OTP
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Start a login and note the current OTP from the authenticator.  
3. Wait multiple OTP intervals (e.g., 2–3 cycles / ~60–90 seconds).  
4. Attempt to submit the old OTP observed in step 2 to complete login.  
5. Repeat with several older OTPs (previous 1–3 codes) and record which ones are accepted.

**Impact:**
- Older/expired OTPs remain valid → weakens TOTP expiry guarantees.  
- Increases chance of account takeover if an attacker reuses or intercepts an OTP.  
- Undermines the security properties of time-based 2FA (confidentiality and integrity at risk).

### Bypassing Two-Factor Authentication via account deactivation + password reset
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Deactivate the account via account settings.  
3. Use the account's email to perform a password reset and set a new password.  
4. Sign in with the email + new password and observe whether the site allows access without prompting for 2FA.

**Impact:**
- Attackers who can access a user's email can deactivate the account, reset the password, and sign in without 2FA.  
- Full account takeover and bypass of second-factor protections.  
- High severity: breaks recovery and deactivation logic, enabling unauthorized access.

### 2FA bypass via password-reset/login email flow (Instagram-style)
**Steps to Test:**
1. Create a test account and enable 2FA.  
2. Have access to the account's email (victim email) in a test mailbox.  
3. Trigger "Forgot password / Send login link" for the target username.  
4. In the email, click the **Reset your password** (or direct login) button that opens the app/web reset flow.  
5. Complete the in-app/web password reset and set a new password.  
6. Log in with the new password and verify whether 2FA is required or can be disabled.

**Impact:**
- Full account takeover if attacker controls the user's email.  
- Ability to reset password and disable 2FA without the original second factor.  
- High severity: defeats MFA protection and enables persistent unauthorized access.

### Bypassing 2FA via email confirmation / login link
**Steps to Test:**
1. Create an account and enable 2FA.  
2. Initiate an account email-change or "confirm email" flow that sends a verification/confirmation link to the account email.  
3. Using the confirmation link (or the app's direct-login link in the email), open it in a browser where you are not authenticated.  
4. Observe whether the link logs you in or grants access to the account without prompting for 2FA.  
5. Repeat with password-reset / login-link emails to check for the same behavior.

**Impact:**
- Email confirmation/login links can bypass 2FA, allowing account takeover if the attacker controls the email.  
- Breaks the second-factor guarantee — attacker who can access the email gains full account access.  
- High severity for systems that auto-login users after email confirmation.

### 2FA disable with wrong password via response tampering
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Go to the disable 2FA flow and open a proxy (e.g., Burp) to intercept the disable request.  
3. In the confirmation dialog submit a valid OTP/backup code but an incorrect password.  
4. Tamper with the intercepted server response (or remove/modify password field) as needed and forward it.  
5. Observe whether 2FA gets disabled despite the wrong password being provided.

**Impact:**
- 2FA can be removed without correct password validation → account takeover.  
- Attackers with OTP/backup codes or ability to tamper responses can remove second-factor protections.  
- High severity: undermines authentication and recovery controls.

### 2FA bypass — non-expiring confirmation/authenticity tokens allow password reset
**Steps to Test:**
1. Trigger an email confirmation or password-reset flow for a test account and capture the `confirmation_token` URL from the email.  
2. Visit the `enter_password?confirmation_token=XXXX` link after the account lockout window (or after token should be expired) and attempt to set a new password.  
3. Alternatively, capture a valid `authenticity_token` from the password form and replay the POST (e.g., `POST /manage/password`) with `update_user_password_form[password]=<new>` using the captured token.  
4. Confirm the password was changed and that you can sign in (and bypass any lockout / 2FA prompt).

**Impact:**
- Tokens that do not expire or can be replayed let attackers reset passwords and bypass account lockouts and 2FA protections.  
- Enables account takeover for attackers who can intercept or access confirmation/authenticity tokens (email access, MITM, leaked logs).  
- High severity: defeats rate-limiting/lockout defenses and undermines MFA.

### Bypass 2FA via password-reset request by removing token parameter
**Steps to Test:**
1. Trigger "Forgot password" for a test account and open the reset URL from the email.  
2. Begin the reset flow in the browser/app until the request that submits the new password and 2FA token is sent.  
3. Intercept that POST request with a proxy (e.g., Burp).  
4. Remove the `token` (or 2FA parameter) from the request body, forward the request.  
5. Confirm the password is changed and you are logged in without providing the 2FA code.

**Impact:**
- Password reset flow bypasses 2FA → full account takeover.  
- Allows attackers with email access (or who can intercept reset requests) to bypass MFA protections.

### Backup-code acceptance not validated (random backup codes accepted)
**Steps to Test:**
1. Enable 2FA and record the issued backup codes.  
2. Log out and start a login to trigger the 2FA prompt.  
3. Choose the "use backup code" option.  
4. Submit a random backup code (same format/length as issued) instead of a real one.  
5. Verify whether the login succeeds.

**Impact:**
- Any attacker can bypass 2FA by submitting arbitrary backup codes → account takeover.  
- Backup-code mechanism is effectively disabled, removing recovery/second-factor protections.

### 2FA brute-force due to missing rate-limiting / no OTP lockout
**Steps to Test:**
1. Enable 2FA (SMS/OTP) on a test account.  
2. Start login to trigger OTP prompt.  
3. Intercept the OTP verification request (e.g., with Burp).  
4. Use an automated tool (Intruder, wfuzz, custom script) to submit OTPs across the full range (e.g., 0000–9999 or 000000–999999 depending on length).  
5. Monitor responses for a success indicator (HTTP status, JSON field, length change, token returned).  
6. If a valid OTP is found, verify you can complete login and access the account.  

**Impact:**
- Full account takeover via automated brute-force of OTPs.  
- Severe when no rate-limiting, no progressive lockout, or no OTP invalidation after repeated failures.

### Bypass 2FA by evading rate-limiting using HTTP headers (e.g., X-Forwarded-For)
**Steps to Test:**
1. Enable 2FA on a test account and start a login to trigger the OTP prompt.  
2. Intercept the OTP verification request with a proxy.  
3. Send repeated OTP attempts and confirm rate-limiting kicks in (blocked responses / 429 / throttled).  
4. Retry the OTP attempts while adding/modifying HTTP headers that can influence perceived client identity (e.g., `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) — vary the header values per request.  
5. Attempt automated brute-force (sequential or wordlist) while rotating the header values and observe whether rate-limiting is bypassed.  
6. Test additional header/value permutations and confirm which headers cause rate-limit evasion.

**Impact:**
- Allows automated brute-force of OTPs despite intended rate-limits → account takeover.  
- Severe when rate-limiting trusts client-controllable headers or poorly handles proxied requests.  
- Enables large-scale attacks (credential stuffing / OTP brute-force) if left unmitigated.

### Mass account takeover via weak account-recovery / password-reset flows (archive-assisted enumeration)
**Steps to Test:**
1. Use archive/web discovery (e.g., Wayback) to enumerate candidate account usernames or archived account URLs.  
2. For a candidate username, visit the provider's account recovery / "forgot password" flow.  
3. Try the recovery options that confirm alternate email addresses (or send confirmation codes) and see if the flow leaks a code or accepts the confirmation without additional proof.  
4. If a confirmation code is returned or delivered to a controlled mailbox, follow the recovery steps and attempt to reset the account password.  
5. Test whether security-question / secondary checks are weak, guessable, or bypassable using public information or minimal answers.  
6. Repeat at scale for multiple enumerated usernames to verify mass exploitability.

**Impact:**
- Large-scale account takeover when recovery flows can be enumerated and confirmed via archives or weak alternate-email confirmation.  
- Confidentiality & integrity loss: attackers can access mail, reset passwords, and hijack accounts.  
- High severity at scale — thousands of accounts may be compromised if recovery checks are weak or confirmation tokens are usable without robust verification.

### 2FA persistence abuse — login succeeds after password change / 2FA disable
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Start a login and wait at the 2FA input page (do not submit code).  
3. In another browser/device, change the account password or disable 2FA.  
4. Return to the waiting 2FA page, submit a valid OTP, and observe whether login completes.  
5. Optionally: use “Try another way” / re-select 2FA to refresh the session and repeat after extended time.

**Impact:**
- Attacker retains access despite victim password reset or 2FA disable.  
- Enables persistent account takeover and undermines password-reset protections.  
- High severity: session/state logic allows re-entry without current credentials or synced 2FA state.

### 1) Bypass 2FA via conventional session management (password reset flow)
**Steps to Test:**
1. Enable 2FA on a test account.  
2. Trigger a password-reset for that account and follow the reset link.  
3. Complete the reset flow and observe whether the session created by the reset grants access without requiring 2FA.  
4. Attempt to access protected areas and verify 2FA is not enforced post-reset.

**Impact:**
- Password reset flow can log in users without 2FA → account takeover if attacker controls email.  
- Defeats MFA as a recovery vector and enables persistent access.

--- 

### 2) Bypass 2FA via OAuth / "Sign in with X" integrations
**Steps to Test:**
1. Ensure target supports an OAuth/Social login (e.g., Google, Apple, Facebook).  
2. Create/obtain a third-party account tied to the victim's email.  
3. Use the provider's OAuth flow to sign in to the target site.  
4. Verify whether the site logs you in without prompting for the target site's 2FA.

**Impact:**
- OAuth login can bypass site-enforced 2FA → attacker with control of the third-party account can access the victim’s account.  
- Breaks assumption that every authentication path enforces MFA.

---

### 3) Bypass 2FA via brute-force (missing/weak rate-limiting)
**Steps to Test:**
1. Trigger the OTP prompt for a test account.  
2. Intercept the OTP verification request and automate submissions across the full OTP space (e.g., 0000–9999).  
3. Observe whether attempts are limited, blocked, or whether a valid code can be discovered.  
4. Verify login completes after a discovered code.

**Impact:**
- Absence of rate-limiting or lockout allows automated OTP brute-force → account takeover.  
- Enables mass exploitation at scale if not mitigated.

---

### 4) Bypass 2FA via race conditions (concurrent enroll/change flows)
**Steps to Test:**
1. Start a 2FA enrollment/change flow on one session (Session A).  
2. In parallel, trigger an enrollment/change from Session B targeting the same account.  
3. Race the two requests (or replay crafted API calls) and observe whether the server accepts a change without requiring the current OTP or confirmation.  
4. Test variations: concurrent secret rotation, backup-code regeneration, or disabling 2FA mid-flow.

**Impact:**
- Race conditions let an attacker replace or disable 2FA without knowing the victim's OTP → account takeover.  
- Transactional/locking failures enable persistent unauthorized access and lockout of the real owner.

### 2FA bypass — tampering `sendCodeTo` (recovery-phone ID swapping)
**Steps to Test:**
1. Create two test accounts (A and B) with different recovery phone numbers.  
2. Trigger the "send recovery code to phone" request for each account and capture the request payload (note the `sendCodeTo` value).  
3. For Account B's flow, intercept the request and replace `sendCodeTo` with Account A's captured phone-ID value.  
4. Forward the modified request and check which phone receives the recovery/SMS code.  
5. Repeat variations (use previously-assigned IDs, change account A's phone then re-test) to confirm predictable/portable IDs.

**Impact:**
- Attacker can direct recovery/SMS codes to another phone → account takeover.  
- Predictable/mappable phone identifiers and lack of server-side binding enable targeted hijacking of recovery flows.  
- High severity: breaks SMS recovery trust and allows unauthorized access.

### The Rise of 2FA Bypass Attacks

**How to Test:**
1. Simulate common 2FA bypass vectors:
   - Perform phishing simulation capturing both credentials and 2FA code.
   - Test MitM interception using an authorized proxy to observe 2FA code handling.
   - Attempt SIM-swap scenarios on test environments using cloned or redirected numbers.
   - Check rate limiting and session handling for OTP re-use or delayed replay.
2. Evaluate password reuse with known credential sets to simulate credential stuffing.
3. Review application flow to verify 2FA challenge enforcement after session or device changes.

**Impact:**
- Attackers can bypass or intercept 2FA through phishing, SIM swapping, or MitM attacks.
- Compromised OTPs lead to full account takeover even with 2FA enabled.
- Weak 2FA implementations (e.g., SMS-based) are highly vulnerable to social engineering and interception.
- Undermines user trust and platform security posture — high risk for identity theft and data breach.






